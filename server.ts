import express, { Request as ExpressRequest, Response, NextFunction } from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { Pool } from 'pg';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

// ============================================================================
// 1. CONFIGURATION
// ============================================================================
dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_key_123';

// Increase payload limit for Base64 image uploads (Receipts/Profile Pics)
app.use(express.json({ limit: '50mb' }));

// --- CORS FIX: Allow Vercel & Localhost ---
app.use(cors({
  origin: '*', // Allows Vercel, Localhost, and Mobile Apps to connect
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// ============================================================================
// 2. DATABASE CONNECTION (Render SSL Fix)
// ============================================================================
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false // Required for Render/Neon self-signed certs
  }
});

// Test the connection immediately when server starts
pool.connect()
  .then(() => console.log('✅ Connected to Database successfully'))
  .catch(err => console.error('❌ Database Connection Error:', err.message));

// ============================================================================
// 3. TYPES & INTERFACES (TypeScript Build Fix)
// ============================================================================
interface AuthRequest extends ExpressRequest {
  user?: {
    id: string;
    role: string;
    isAdmin: boolean;
    adminRole?: string;
  };
  [key: string]: any; // Fixes "Property does not exist" build errors
}

// ============================================================================
// 4. UTILITIES & HELPERS
// ============================================================================
const generateToken = (id: string, role: string, isAdmin: boolean, adminRole?: string) => {
  return jwt.sign({ id, role, isAdmin, adminRole }, JWT_SECRET, { expiresIn: '30d' });
};

const sendEmail = async (to: string, subject: string, text: string) => {
  // Mock Email Sender (Replace with Nodemailer later)
  if (process.env.NODE_ENV !== 'test') {
    console.log(`\n--- [MOCK EMAIL] ---\nTo: ${to}\nSubject: ${subject}\nBody: ${text}\n--------------------\n`);
  }
};

const handleError = (res: Response, error: any, message: string = 'Server Error') => {
  console.error(message, error);
  res.status(500).json({ message: error.message || message });
};

// Notification Helper
const createNotification = async (userId: string, title: string, message: string, type: string) => {
  try {
    await pool.query(
      'INSERT INTO notifications (user_id, title, message, type, created_at) VALUES ($1, $2, $3, $4, NOW())',
      [userId, title, message, type]
    );
  } catch (error) {
    console.error('Failed to create notification:', error);
  }
};

// ============================================================================
// 5. MIDDLEWARE
// ============================================================================
const protect = (req: AuthRequest, res: Response, next: NextFunction) => {
  let token;
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    try {
      token = req.headers.authorization.split(' ')[1];
      const decoded = jwt.verify(token, JWT_SECRET) as any;
      req.user = decoded;
      next();
    } catch (error) {
      res.status(401).json({ message: 'Not authorized, token failed' });
    }
  } else {
    res.status(401).json({ message: 'Not authorized, no token' });
  }
};

const admin = (req: AuthRequest, res: Response, next: NextFunction) => {
  if (req.user && req.user.isAdmin) next();
  else res.status(403).json({ message: 'Admin access required' });
};

// ============================================================================
// 6. ROUTES: AUTH
// ============================================================================
app.post('/api/auth/register', async (req: ExpressRequest, res: Response) => {
  const { email, password, role, fullName, phoneNumber, state, city, address, clientType, cleanerType, companyName, experience, services, bio, chargeHourly, chargeDaily, chargePerContract, bankName, accountNumber, profilePhoto, governmentId, businessRegDoc } = req.body;

  try {
    const userExists = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (userExists.rows.length > 0) return res.status(400).json({ message: 'User already exists' });

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    
    // Handle JSONB for services: pass array directly, or empty array if null
    const servicesData = JSON.stringify(services || []);

    const result = await pool.query(
      `INSERT INTO users (
        email, password_hash, role, full_name, phone_number, state, city, address, 
        client_type, cleaner_type, company_name, experience, services, bio, 
        charge_hourly, charge_daily, charge_per_contract, bank_name, account_number,
        profile_photo, government_id, business_reg_doc, subscription_tier, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, 'Free', NOW()) RETURNING *`,
      [email, hashedPassword, role, fullName, phoneNumber, state, city, address, clientType, cleanerType, companyName, experience, servicesData, bio, chargeHourly, chargeDaily, chargePerContract, bankName, accountNumber, profilePhoto, governmentId, businessRegDoc]
    );

    const user = result.rows[0];
    
    // Send Welcome Notification
    await createNotification(user.id, 'Welcome to CleanConnect!', 'Your account has been successfully created.', 'system');

    res.status(201).json({
      ...user,
      token: generateToken(user.id, user.role, user.is_admin, user.admin_role)
    });
  } catch (error) { handleError(res, error, 'Registration failed'); }
});

app.post('/api/auth/login', async (req: ExpressRequest, res: Response) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];

    if (user && (await bcrypt.compare(password, user.password_hash))) {
      if (user.is_suspended) return res.status(403).json({ message: 'Account is suspended.' });
      
      const userData = {
        id: user.id,
        fullName: user.full_name,
        email: user.email,
        role: user.role,
        isAdmin: user.is_admin,
        adminRole: user.admin_role,
        profilePhoto: user.profile_photo,
        subscriptionTier: user.subscription_tier
      };
      
      res.json({ token: generateToken(user.id, user.role, user.is_admin, user.admin_role), user: userData });
    } else {
      res.status(401).json({ message: 'Invalid email or password' });
    }
  } catch (error) { handleError(res, error, 'Login failed'); }
});

// ============================================================================
// 7. ROUTES: USERS & CLEANERS (WITH SNAKE_CASE TO CAMELCASE FIX)
// ============================================================================
app.get('/api/users/me', protect, async (req: AuthRequest, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        u.*, 
        (SELECT json_agg(b.*) FROM bookings b WHERE b.client_id = u.id OR b.cleaner_id = u.id) as booking_history,
        (SELECT json_agg(r.*) FROM reviews r WHERE r.cleaner_id = u.id) as reviews_data
      FROM users u WHERE u.id = $1
    `, [req.user!.id]);
    
    const user = result.rows[0];
    if (!user) return res.status(404).json({ message: 'User not found' });

    // --- FIX: Translate Bookings from Snake_Case to camelCase ---
    const rawBookings = user.booking_history || [];
    const formattedBookings = rawBookings.map((b: any) => ({
        id: b.id,
        clientId: b.client_id,
        cleanerId: b.cleaner_id,
        clientName: b.client_name,
        cleanerName: b.cleaner_name,
        service: b.service,
        date: b.date,
        amount: b.amount,
        totalAmount: b.total_amount,
        paymentMethod: b.payment_method,
        status: b.status,
        paymentStatus: b.payment_status,
        jobApprovedByClient: b.job_approved_by_client,
        reviewSubmitted: b.review_submitted,
        createdAt: b.created_at
    }));

    // Format snake_case DB fields to camelCase for frontend
    const formattedUser = {
      id: user.id,
      fullName: user.full_name,
      email: user.email,
      role: user.role,
      phoneNumber: user.phone_number,
      address: user.address,
      state: user.state,
      city: user.city,
      profilePhoto: user.profile_photo,
      isAdmin: user.is_admin,
      adminRole: user.admin_role,
      subscriptionTier: user.subscription_tier,
      cleanerType: user.cleaner_type,
      clientType: user.client_type,
      experience: user.experience,
      bio: user.bio,
      services: user.services, // Already JSONB
      chargeHourly: user.charge_hourly,
      chargeDaily: user.charge_daily,
      chargePerContract: user.charge_per_contract,
      bankName: user.bank_name,
      accountNumber: user.account_number,
      bookingHistory: formattedBookings, // <--- Use the translated list
      reviewsData: user.reviews_data || [],
      pendingSubscription: user.pending_subscription
    };

    res.json(formattedUser);
  } catch (error) { handleError(res, error); }
});

app.put('/api/users/me', protect, async (req: AuthRequest, res) => {
  const { fullName, phoneNumber, address, bio, services, experience, chargeHourly, chargeDaily, chargePerContract, profilePhoto } = req.body;
  try {
    const result = await pool.query(
      `UPDATE users SET 
        full_name = COALESCE($1, full_name),
        phone_number = COALESCE($2, phone_number),
        address = COALESCE($3, address),
        bio = COALESCE($4, bio),
        services = COALESCE($5, services),
        experience = COALESCE($6, experience),
        charge_hourly = COALESCE($7, charge_hourly),
        charge_daily = COALESCE($8, charge_daily),
        charge_per_contract = COALESCE($9, charge_per_contract),
        profile_photo = COALESCE($10, profile_photo)
       WHERE id = $11 RETURNING *`,
      [fullName, phoneNumber, address, bio, JSON.stringify(services), experience, chargeHourly, chargeDaily, chargePerContract, profilePhoto, req.user!.id]
    );
    res.json(result.rows[0]);
  } catch (error) { handleError(res, error, 'Update failed'); }
});

app.get('/api/cleaners', async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM users WHERE role = 'cleaner' AND is_suspended = false");
    const cleaners = result.rows.map(c => ({
      id: c.id,
      name: c.full_name,
      photoUrl: c.profile_photo,
      rating: 5.0, // Should be calculated from reviews in production
      serviceTypes: c.services,
      state: c.state,
      city: c.city,
      experience: c.experience,
      bio: c.bio,
      chargeHourly: c.charge_hourly
    }));
    res.json(cleaners);
  } catch (error) { handleError(res, error); }
});

// ============================================================================
// 8. ROUTES: BOOKINGS
// ============================================================================
app.post('/api/bookings', protect, async (req: AuthRequest, res) => {
  const { cleanerId, service, date, amount, totalAmount, paymentMethod } = req.body;
  try {
    const cleanerRes = await pool.query('SELECT full_name FROM users WHERE id = $1', [cleanerId]);
    const cleanerName = cleanerRes.rows[0]?.full_name || 'Cleaner';
    
    const clientRes = await pool.query('SELECT full_name FROM users WHERE id = $1', [req.user!.id]);
    const clientName = clientRes.rows[0]?.full_name || 'Client';

    const result = await pool.query(
      `INSERT INTO bookings (
        client_id, cleaner_id, client_name, cleaner_name, service, date, amount, total_amount, payment_method, status, payment_status, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'Upcoming', $10, NOW()) RETURNING *`,
      [req.user!.id, cleanerId, clientName, cleanerName, service, date, amount, totalAmount, paymentMethod, paymentMethod === 'Direct' ? 'Not Applicable' : 'Pending Payment']
    );

    // Notify the Cleaner
    await createNotification(cleanerId, 'New Booking Request', `You have a new booking request from ${clientName} for ${service}.`, 'booking');

    await sendEmail(req.user!.id, 'Booking Confirmation', `You booked ${cleanerName} for ${service}.`);
    res.status(201).json(result.rows[0]);
  } catch (error) { handleError(res, error, 'Booking failed'); }
});

app.post('/api/bookings/:id/cancel', protect, async (req: AuthRequest, res) => {
  try {
    const result = await pool.query("UPDATE bookings SET status = 'Cancelled' WHERE id = $1 RETURNING *", [req.params.id]);
    const booking = result.rows[0];
    
    // Notify the other party (if client cancelled, notify cleaner)
    if(booking) {
         const targetId = req.user!.id === booking.client_id ? booking.cleaner_id : booking.client_id;
         await createNotification(targetId, 'Booking Cancelled', `The booking for ${booking.service} has been cancelled.`, 'booking');
    }

    res.json(booking);
  } catch (error) { handleError(res, error); }
});

app.post('/api/bookings/:id/complete', protect, async (req: AuthRequest, res) => {
  try {
    const bookingRes = await pool.query('SELECT * FROM bookings WHERE id = $1', [req.params.id]);
    const booking = bookingRes.rows[0];
    
    let newPaymentStatus = booking.payment_status;
    if (booking.payment_method === 'Escrow' && booking.payment_status === 'Confirmed') {
      newPaymentStatus = 'Pending Payout';
    }

    const result = await pool.query(
      "UPDATE bookings SET status = 'Completed', job_approved_by_client = true, payment_status = $1 WHERE id = $2 RETURNING *", 
      [newPaymentStatus, req.params.id]
    );

    // Notify Cleaner Job is done
    await createNotification(booking.cleaner_id, 'Job Marked Complete', 'The client has marked the job as completed.', 'booking');

    res.json(result.rows[0]);
  } catch (error) { handleError(res, error); }
});

app.post('/api/bookings/:id/review', protect, async (req: AuthRequest, res) => {
  const { rating, timeliness, thoroughness, conduct, comment, cleanerId } = req.body;
  try {
    const clientRes = await pool.query('SELECT full_name FROM users WHERE id = $1', [req.user!.id]);
    const reviewerName = clientRes.rows[0]?.full_name || 'Anonymous';

    await pool.query(
      `INSERT INTO reviews (booking_id, cleaner_id, reviewer_name, rating, timeliness, thoroughness, conduct, comment, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())`,
      [req.params.id, cleanerId, reviewerName, rating, timeliness, thoroughness, conduct, comment]
    );
    
    await pool.query("UPDATE bookings SET review_submitted = true WHERE id = $1", [req.params.id]);
    
    // Notify Cleaner of Review
    await createNotification(cleanerId, 'New Review', `You received a ${rating}-star review from ${reviewerName}.`, 'system');

    res.json({ message: 'Review submitted' });
  } catch (error) { handleError(res, error); }
});

app.post('/api/bookings/:id/receipt', protect, async (req: AuthRequest, res) => {
  const { name, dataUrl } = req.body;
  try {
    const receiptJson = JSON.stringify({ name, dataUrl });
    const result = await pool.query(
      "UPDATE bookings SET payment_receipt = $1, payment_status = 'Pending Admin Confirmation' WHERE id = $2 RETURNING *",
      [receiptJson, req.params.id]
    );
    res.json(result.rows[0]);
  } catch (error) { handleError(res, error); }
});

// ============================================================================
// 9. ROUTES: SUBSCRIPTION
// ============================================================================
app.post('/api/users/subscription/upgrade', protect, async (req: AuthRequest, res) => {
  const { plan } = req.body;
  try {
    const result = await pool.query(
      "UPDATE users SET pending_subscription = $1 WHERE id = $2 RETURNING *",
      [plan, req.user!.id]
    );
    res.json(result.rows[0]);
  } catch (error) { handleError(res, error); }
});

app.post('/api/users/subscription/receipt', protect, async (req: AuthRequest, res) => {
  const { name, dataUrl } = req.body;
  try {
    const receiptJson = JSON.stringify({ name, dataUrl });
    const result = await pool.query(
      "UPDATE users SET subscription_receipt = $1 WHERE id = $2 RETURNING *",
      [receiptJson, req.user!.id]
    );
    res.json(result.rows[0]);
  } catch (error) { handleError(res, error); }
});

// ============================================================================
// 10. ROUTES: NOTIFICATIONS
// ============================================================================
app.get('/api/notifications', protect, async (req: AuthRequest, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM notifications WHERE user_id = $1 ORDER BY created_at DESC', 
      [req.user!.id]
    );
    res.json(result.rows);
  } catch (error) { handleError(res, error); }
});

app.patch('/api/notifications/:id/read', protect, async (req: AuthRequest, res) => {
  try {
    await pool.query(
      'UPDATE notifications SET is_read = true WHERE id = $1 AND user_id = $2',
      [req.params.id, req.user!.id]
    );
    res.json({ message: 'Marked as read' });
  } catch (error) { handleError(res, error); }
});

app.patch('/api/notifications/mark-all-read', protect, async (req: AuthRequest, res) => {
  try {
    await pool.query(
      'UPDATE notifications SET is_read = true WHERE user_id = $1',
      [req.user!.id]
    );
    res.json({ message: 'All marked as read' });
  } catch (error) { handleError(res, error); }
});

// ============================================================================
// 11. ROUTES: ADMIN
// ============================================================================
app.get('/api/admin/users', protect, admin, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM users ORDER BY created_at DESC');
    res.json(result.rows.map(u => ({
        id: u.id,
        fullName: u.full_name,
        email: u.email,
        role: u.role,
        isAdmin: u.is_admin,
        isSuspended: u.is_suspended,
        subscriptionTier: u.subscription_tier,
        pendingSubscription: u.pending_subscription,
        subscriptionReceipt: u.subscription_receipt ? JSON.parse(u.subscription_receipt) : null,
        bookingHistory: []
    })));
  } catch (error) { handleError(res, error); }
});

app.patch('/api/admin/users/:id/status', protect, admin, async (req, res) => {
  const { isSuspended } = req.body;
  try {
    await pool.query('UPDATE users SET is_suspended = $1 WHERE id = $2', [isSuspended, req.params.id]);
    res.json({ message: 'User status updated' });
  } catch (error) { handleError(res, error); }
});

app.delete('/api/admin/users/:id', protect, admin, async (req, res) => {
  try {
    await pool.query('DELETE FROM users WHERE id = $1', [req.params.id]);
    res.json({ message: 'User deleted' });
  } catch (error) { handleError(res, error); }
});

app.post('/api/admin/bookings/:id/confirm-payment', protect, admin, async (req, res) => {
  try {
    // 1. Update status
    const result = await pool.query(
      "UPDATE bookings SET payment_status = 'Confirmed' WHERE id = $1 RETURNING client_id", 
      [req.params.id]
    );
    
    // 2. Alert the Client their payment is confirmed
    const booking = result.rows[0];
    if (booking) {
        await createNotification(
            booking.client_id, 
            'Payment Confirmed', 
            'We have received your transfer. Your booking is now fully confirmed!', 
            'payment'
        );
    }
    
    res.json({ message: 'Payment confirmed and user notified' });
  } catch (error) { handleError(res, error); }
});

app.post('/api/admin/bookings/:id/mark-paid', protect, admin, async (req, res) => {
  try {
    await pool.query("UPDATE bookings SET payment_status = 'Paid' WHERE id = $1", [req.params.id]);
    res.json({ message: 'Marked as paid' });
  } catch (error) { handleError(res, error); }
});

app.post('/api/admin/users/:id/approve-subscription', protect, admin, async (req, res) => {
  try {
    const userRes = await pool.query('SELECT pending_subscription FROM users WHERE id = $1', [req.params.id]);
    const plan = userRes.rows[0]?.pending_subscription;
    if (!plan) return res.status(400).json({ message: 'No pending subscription' });

    await pool.query(
      "UPDATE users SET subscription_tier = $1, pending_subscription = NULL, subscription_receipt = NULL WHERE id = $2",
      [plan, req.params.id]
    );

    // Notify User
    await createNotification(req.params.id, 'Subscription Upgraded', `Your account is now upgraded to ${plan}.`, 'system');

    res.json({ message: 'Subscription approved' });
  } catch (error) { handleError(res, error); }
});

// ============================================================================
// 12. ROUTES: CHAT
// ============================================================================
app.post('/api/chats', protect, async (req: AuthRequest, res) => {
    const { participantId } = req.body;
    const userId = req.user!.id;
    try {
        const existingChat = await pool.query(
            `SELECT * FROM chats WHERE (participant_one = $1 AND participant_two = $2) OR (participant_one = $2 AND participant_two = $1)`,
            [userId, participantId]
        );
        if (existingChat.rows.length > 0) {
            return res.json({ id: existingChat.rows[0].id, participants: [existingChat.rows[0].participant_one, existingChat.rows[0].participant_two], participantNames: {} });
        }
        const result = await pool.query(
            'INSERT INTO chats (participant_one, participant_two) VALUES ($1, $2) RETURNING *',
            [userId, participantId]
        );
        res.status(201).json({ id: result.rows[0].id, participants: [userId, participantId], participantNames: {} });
    } catch (error) { handleError(res, error, 'Failed to create chat'); }
});

app.get('/api/chats', protect, async (req: AuthRequest, res) => {
    try {
        const result = await pool.query(
            `SELECT c.*, 
                    m.text as last_message_text, 
                    m.sender_id as last_message_sender, 
                    m.created_at as last_message_time,
                    u1.full_name as name1, u2.full_name as name2
             FROM chats c
             LEFT JOIN messages m ON c.last_message_id = m.id
             JOIN users u1 ON c.participant_one = u1.id
             JOIN users u2 ON c.participant_two = u2.id
             WHERE c.participant_one = $1 OR c.participant_two = $1
             ORDER BY m.created_at DESC NULLS LAST`,
            [req.user!.id]
        );
        const chats = result.rows.map(row => ({
            id: row.id,
            participants: [row.participant_one, row.participant_two],
            participantNames: {
                [row.participant_one]: row.name1,
                [row.participant_two]: row.name2
            },
            lastMessage: row.last_message_text ? {
                text: row.last_message_text,
                senderId: row.last_message_sender,
                timestamp: row.last_message_time
            } : undefined,
            updatedAt: row.last_message_time || row.created_at
        }));
        res.json(chats);
    } catch (error) { handleError(res, error); }
});

app.get('/api/chats/:id/messages', protect, async (req: AuthRequest, res) => {
    try {
        const result = await pool.query(
            'SELECT * FROM messages WHERE chat_id = $1 ORDER BY created_at ASC',
            [req.params.id]
        );
        const messages = result.rows.map(r => ({
            id: r.id,
            chatId: r.chat_id,
            senderId: r.sender_id,
            text: r.text,
            timestamp: r.created_at
        }));
        res.json(messages);
    } catch (error) { handleError(res, error); }
});

app.post('/api/chats/:id/messages', protect, async (req: AuthRequest, res) => {
    const { text } = req.body;
    try {
        const result = await pool.query(
            'INSERT INTO messages (chat_id, sender_id, text) VALUES ($1, $2, $3) RETURNING *',
            [req.params.id, req.user!.id, text]
        );
        const message = result.rows[0];
        
        // Update chat last message
        await pool.query('UPDATE chats SET last_message_id = $1, updated_at = NOW() WHERE id = $2', [message.id, req.params.id]);

        res.status(201).json({
            id: message.id,
            chatId: message.chat_id,
            senderId: message.sender_id,
            text: message.text,
            timestamp: message.created_at
        });
    } catch (error) { handleError(res, error); }
});

// ============================================================================
// 13. ROUTES: STANDARD SEARCH (No AI)
// ============================================================================
app.get('/api/search', async (req: ExpressRequest, res: Response) => {
  const { query, location, service } = req.query;

  try {
    let sql = `SELECT * FROM users WHERE role = 'cleaner' AND is_suspended = false`;
    const params: any[] = [];
    let paramIndex = 1;

    // Filter by Location
    if (location) {
      sql += ` AND (city ILIKE $${paramIndex} OR state ILIKE $${paramIndex} OR address ILIKE $${paramIndex})`;
      params.push(`%${location}%`);
      paramIndex++;
    }

    // Filter by Service (JSONB or Text matching)
    if (service) {
      // Postgres JSONB check: Does the services array contain this text?
      // Since 'services' is JSONB, we cast to text for simple ILIKE matching
      sql += ` AND (services::text ILIKE $${paramIndex} OR bio ILIKE $${paramIndex})`;
      params.push(`%${service}%`);
      paramIndex++;
    }

    // General Query (Name, etc)
    if (query) {
      sql += ` AND (full_name ILIKE $${paramIndex} OR bio ILIKE $${paramIndex} OR city ILIKE $${paramIndex} OR state ILIKE $${paramIndex})`;
      params.push(`%${query}%`);
      paramIndex++;
    }

    const result = await pool.query(sql, params);
    
    const cleaners = result.rows.map(c => ({
      id: c.id,
      name: c.full_name,
      photoUrl: c.profile_photo,
      serviceTypes: c.services,
      state: c.state,
      city: c.city,
      chargeHourly: c.charge_hourly
    }));

    res.json(cleaners);
  } catch (error) { handleError(res, error, "Search failed"); }
});

// ============================================================================
// 14. SERVER START & ROOT ROUTE
// ============================================================================

// Root Route - To verify server is running
app.get('/', (req, res) => {
  res.send('✅ CleanConnect Backend is Running!');
});

// 404 Handler - For unknown routes
app.use((req, res, next) => {
    res.status(404).json({ message: `Not Found - ${req.originalUrl}` });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});