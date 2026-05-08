// ================= LESVOTE BACKEND =================
// Secure Express server with MongoDB and comprehensive security measures

require('dotenv').config();
const express = require('express');
const fs = require('fs');
const path = require('path');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const axios = require('axios');
const crypto = require('crypto');
const mongoose = require('mongoose');

const app = express();
const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'development';
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/lesvote';

// ================= SECURITY HEADERS =================
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  if (NODE_ENV === 'production') {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
  next();
});

app.use(express.json({ limit: '1mb' }));
app.use(express.static('public'));

// ================= MONGODB SETUP =================
mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).catch(err => {
  console.error('MongoDB connection error:', err.message);
  console.error('Make sure MongoDB is running at:', MONGODB_URI);
  process.exit(1);
});

// ================= MONGODB SCHEMAS =================
const superAdminSchema = new mongoose.Schema({
  username: String,
  password: String
}, { collection: 'superAdmin' });

const eventAdminSchema = new mongoose.Schema({
  id: { type: Number, unique: true },
  username: String,
  password: String,
  events: [Number]
}, { collection: 'eventAdmins' });

const categorySchema = new mongoose.Schema({
  id: Number,
  name: String,
  icon: String
});

const nomineeSchema = new mongoose.Schema({
  id: Number,
  name: String,
  catId: Number,
  photo: String,
  votes: { type: Number, default: 0 }
});

const transactionSchema = new mongoose.Schema({
  id: { type: mongoose.Schema.Types.Mixed },
  nomineeId: Number,
  nomName: String,
  catName: String,
  votes: Number,
  amt: Number,
  qty: Number,
  phone: String,
  name: String,
  method: String,
  time: Date,
  status: String
});

const eventSchema = new mongoose.Schema({
  id: { type: Number, unique: true },
  name: String,
  desc: String,
  icon: String,
  photo: String,
  votingOpen: { type: Boolean, default: true },
  votePrice: { type: Number, default: 0.5 },
  showResults: { type: Boolean, default: true },
  categories: [categorySchema],
  nominees: [nomineeSchema],
  transactions: [transactionSchema],
  blocked: [String]
}, { collection: 'events' });

const paystackConfigSchema = new mongoose.Schema({
  publicKey: String,
  email: String
}, { collection: 'paystackConfig' });

// ================= MODELS =================
const SuperAdmin = mongoose.model('SuperAdmin', superAdminSchema);
const EventAdmin = mongoose.model('EventAdmin', eventAdminSchema);
const Event = mongoose.model('Event', eventSchema);
const PaystackConfig = mongoose.model('PaystackConfig', paystackConfigSchema);

// ================= DATABASE INITIALIZATION =================
async function initializeDB() {
  try {
    let superAdmin = await SuperAdmin.findOne();
    if (!superAdmin) {
      const hashedPassword = await bcrypt.hash(process.env.ADMIN_PASSWORD || 'awards2025', 10);
      superAdmin = new SuperAdmin({
        username: process.env.ADMIN_USERNAME || 'admin',
        password: hashedPassword
      });
      await superAdmin.save();
      console.log('✓ Super admin initialized');
    }

    let paystackConfig = await PaystackConfig.findOne();
    if (!paystackConfig) {
      paystackConfig = new PaystackConfig({
        publicKey: process.env.PAYSTACK_PUBLIC_KEY || '',
        email: process.env.ORG_EMAIL || ''
      });
      await paystackConfig.save();
      console.log('✓ Paystack config initialized');
    }
  } catch (err) {
    console.error('Database initialization error:', err.message);
  }
}

// ================= SESSION MANAGEMENT (MongoDB-backed) =================
const sessionSchema = new mongoose.Schema({
  token:     { type: String, unique: true, index: true },
  role:      String,
  adminId:   mongoose.Schema.Types.Mixed,
  username:  String,
  createdAt: { type: Date, default: Date.now },
  expiresAt: { type: Date, index: { expireAfterSeconds: 0 } } // TTL index — Mongo auto-deletes
}, { collection: 'sessions' });

const Session = mongoose.model('Session', sessionSchema);

function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

async function createSession(role, adminId, username) {
  const token = generateToken();
  const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);
  await Session.create({ token, role, adminId, username, expiresAt });
  return token;
}

async function verifySession(token) {
  const session = await Session.findOne({ token, expiresAt: { $gt: new Date() } });
  return session || null;
}

function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'No token provided' });
  verifySession(token).then(session => {
    if (!session) return res.status(401).json({ error: 'Invalid or expired token' });
    req.session = session;
    next();
  }).catch(() => res.status(500).json({ error: 'Server error' }));
}

// ================= INPUT VALIDATION HELPERS =================
function sanitizeString(val, maxLen = 200) {
  if (typeof val !== 'string') return '';
  return val.trim().slice(0, maxLen);
}

function validateVoteQty(qty) {
  const n = parseInt(qty);
  if (isNaN(n) || n < 1 || n > 10000) return null;
  return n;
}

function validatePrice(price) {
  const n = parseFloat(price);
  if (isNaN(n) || n < 0.10 || n > 10000) return null;
  return Math.round(n * 100) / 100;
}

function formatGhanaSmsNumber(phone) {
  const digits = String(phone).replace(/\D/g, '');
  if (/^0[235][0-9]{8}$/.test(digits)) return '+233' + digits.slice(1);
  if (/^[235][0-9]{8}$/.test(digits)) return '+233' + digits;
  if (/^233[235][0-9]{8}$/.test(digits)) return '+' + digits;
  if (/^\+233[235][0-9]{8}$/.test(phone)) return phone;
  return null;
}

// ================= RATE LIMITING =================
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Too many login attempts. Please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const voteLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  message: { error: 'Too many vote requests. Please slow down.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const uploadLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 50,
  message: { error: 'Too many upload requests. Please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// ================= FILE UPLOAD SETUP =================
const uploadsDir = path.join(__dirname, 'public', 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

const storage = multer.diskStorage({
  destination: uploadsDir,
  filename: (req, file, cb) => {
    const uniqueName = `${Date.now()}-${Math.random().toString(36).substr(2, 9)}${path.extname(file.originalname).toLowerCase()}`;
    cb(null, uniqueName);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = /\.(jpg|jpeg|png|gif|webp)$/i;
    if (allowed.test(file.originalname) && file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Only image files are allowed'));
    }
  }
});

// ================= AUTH =================
app.post('/api/login', loginLimiter, async (req, res) => {
  const username = sanitizeString(req.body.username, 100);
  const password = sanitizeString(req.body.password, 200);

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }

  try {
    const superAdmin = await SuperAdmin.findOne();
    if (superAdmin && username === superAdmin.username &&
        await bcrypt.compare(password, superAdmin.password)) {
      const token = await createSession('super', null, username);
      return res.json({ role: 'super', username, token });
    }

    const eventAdmin = await EventAdmin.findOne({ username });
    if (eventAdmin && await bcrypt.compare(password, eventAdmin.password)) {
      const token = await createSession('event', eventAdmin.id, username);
      return res.json({
        role: 'event',
        username,
        adminId: eventAdmin.id,
        managedEvents: eventAdmin.events || [],
        token
      });
    }

    // Constant-time response to prevent user enumeration
    await bcrypt.compare(password, '$2a$10$invalidhashpaddingtoconstanttime00000000000000000000000');
    res.status(401).json({ error: 'Invalid credentials' });
  } catch (error) {
    console.error('Login error:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// Verify token and return session info (used to restore login state after page refresh)
app.get('/api/me', authMiddleware, async (req, res) => {
  try {
    let managedEvents = [];
    if (req.session.role === 'event' && req.session.adminId) {
      const admin = await EventAdmin.findOne({ id: req.session.adminId }, { password: 0 });
      managedEvents = admin ? admin.events : [];
    }
    res.json({
      role: req.session.role,
      username: req.session.username,
      adminId: req.session.adminId,
      managedEvents
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ================= CHANGE PASSWORD =================
app.post('/api/change-password', authMiddleware, async (req, res) => {
  const newPassword = sanitizeString(req.body.password, 200);

  if (!newPassword || newPassword.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters' });
  }

  try {
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    if (req.session.role === 'super') {
      await SuperAdmin.updateOne({}, { password: hashedPassword });
    } else {
      await EventAdmin.updateOne({ id: req.session.adminId }, { password: hashedPassword });
    }

    res.json({ success: true });
  } catch (error) {
    console.error('Change password error:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// ================= PAYSTACK CONFIG =================
app.get('/api/paystack-config', async (req, res) => {
  try {
    const config = await PaystackConfig.findOne();
    res.json({
      publicKey: config?.publicKey || process.env.PAYSTACK_PUBLIC_KEY || '',
      email: config?.email || process.env.ORG_EMAIL || ''
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/paystack-config', authMiddleware, async (req, res) => {
  if (req.session.role !== 'super') {
    return res.status(403).json({ error: 'Only super admins can configure Paystack' });
  }

  const publicKey = sanitizeString(req.body.publicKey, 100);
  const email = sanitizeString(req.body.email, 200);

  if (!publicKey || !email) {
    return res.status(400).json({ error: 'Public key and email are required' });
  }
  if (!email.includes('@')) {
    return res.status(400).json({ error: 'Invalid email address' });
  }

  try {
    let config = await PaystackConfig.findOne();
    if (!config) config = new PaystackConfig();
    config.publicKey = publicKey;
    config.email = email;
    await config.save();
    res.json({ success: true, publicKey: config.publicKey, email: config.email });
  } catch (error) {
    res.status(500).json({ error: 'Server error: ' + error.message });
  }
});

// ================= EVENTS =================
app.get('/api/events', async (req, res) => {
  try {
    const events = await Event.find();
    const eventsWithTotals = events.map(event => ({
      ...event.toObject(),
      totalVotes: event.nominees.reduce((sum, n) => sum + n.votes, 0)
    }));
    res.json(eventsWithTotals);
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/events', authMiddleware, async (req, res) => {
  if (req.session.role !== 'super') {
    return res.status(403).json({ error: 'Only super admins can create events' });
  }

  const name = sanitizeString(req.body.name, 200);
  const desc = sanitizeString(req.body.desc, 500);
  const icon = sanitizeString(req.body.icon, 10) || '🏆';
  const votePrice = validatePrice(req.body.votePrice) || 0.5;

  if (!name) return res.status(400).json({ error: 'Programme name is required' });

  try {
    const eventId = Date.now();
    const newEvent = new Event({
      id: eventId, name, desc, icon,
      votingOpen: true, votePrice,
      categories: [], nominees: [], transactions: [], blocked: [],
      showResults: true
    });
    await newEvent.save();
    res.json(newEvent);
  } catch (error) {
    console.error('Error creating event:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// ================= CATEGORIES =================
app.post('/api/events/:id/categories', authMiddleware, async (req, res) => {
  const name = sanitizeString(req.body.name, 100);
  const icon = sanitizeString(req.body.icon, 10) || '🏅';
  if (!name) return res.status(400).json({ error: 'Category name is required' });

  try {
    const eventId = parseInt(req.params.id);
    const event = await Event.findOne({ id: eventId });
    if (!event) return res.status(404).json({ error: 'Event not found' });

    const catId = Date.now();
    event.categories.push({ id: catId, name, icon });
    await event.save();
    res.json({ success: true, catId });
  } catch (error) {
    console.error('Error adding category:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/events/:id/categories/:catId', authMiddleware, async (req, res) => {
  try {
    const eventId = parseInt(req.params.id);
    const catId = parseInt(req.params.catId);
    const event = await Event.findOne({ id: eventId });
    if (!event) return res.status(404).json({ error: 'Event not found' });

    event.categories = event.categories.filter(c => c.id != catId);
    event.nominees = event.nominees.filter(n => n.catId != catId);
    await event.save();
    res.json({ success: true });
  } catch (error) {
    console.error('Error deleting category:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// ================= NOMINEES =================
app.post('/api/events/:id/nominees', authMiddleware, async (req, res) => {
  const name = sanitizeString(req.body.name, 200);
  const catId = parseInt(req.body.catId);
  if (!name) return res.status(400).json({ error: 'Nominee name is required' });
  if (isNaN(catId)) return res.status(400).json({ error: 'Invalid category' });

  try {
    const eventId = parseInt(req.params.id);
    const event = await Event.findOne({ id: eventId });
    if (!event) return res.status(404).json({ error: 'Event not found' });

    const cat = event.categories.find(c => c.id === catId);
    if (!cat) return res.status(404).json({ error: 'Category not found in this event' });

    const nomineeId = Date.now();
    event.nominees.push({ id: nomineeId, name, catId, photo: '', votes: 0 });
    await event.save();
    res.json({ success: true, nomineeId });
  } catch (error) {
    console.error('Error adding nominee:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/events/:id/nominees/:nomId', authMiddleware, async (req, res) => {
  try {
    const eventId = parseInt(req.params.id);
    const nomId = parseInt(req.params.nomId);
    const event = await Event.findOne({ id: eventId });
    if (!event) return res.status(404).json({ error: 'Event not found' });

    event.nominees = event.nominees.filter(n => n.id != nomId);
    await event.save();
    res.json({ success: true });
  } catch (error) {
    console.error('Error deleting nominee:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// ================= VOTE WITH PAYSTACK VERIFICATION =================
app.post('/api/events/:id/vote', voteLimiter, async (req, res) => {
  try {
    const eventId = parseInt(req.params.id);
    const event = await Event.findOne({ id: eventId });

    if (!event) return res.status(404).json({ error: 'Event not found' });
    if (!event.votingOpen) return res.status(403).json({ error: 'Voting is closed for this event' });

    const { nomineeId, phone, name, method, reference } = req.body;
    const votes = validateVoteQty(req.body.votes);

    if (!votes) return res.status(400).json({ error: 'Invalid vote quantity (must be 1–10,000)' });
    if (!nomineeId) return res.status(400).json({ error: 'Nominee ID is required' });

    const cleanPhone = typeof phone === 'string' ? phone.replace(/\s/g, '') : '';
    if (!cleanPhone) return res.status(400).json({ error: 'Phone number is required' });
    if (event.blocked.includes(cleanPhone)) {
      return res.status(403).json({ error: 'This number is blocked from voting' });
    }

    const nominee = event.nominees.find(n => n.id == nomineeId);
    if (!nominee) return res.status(404).json({ error: 'Nominee not found' });

    // Amount in GHS
    const expectedAmtGHS = Math.round(votes * (event.votePrice || 0.5) * 100) / 100;
    // Amount in kobo (Paystack's unit)
    const expectedAmtKobo = Math.round(expectedAmtGHS * 100);

    const paystackSecretKey = process.env.PAYSTACK_SECRET_KEY;
    const isLiveKey = paystackSecretKey && !paystackSecretKey.includes('your_') && paystackSecretKey.length > 20;

    if (isLiveKey) {
      if (!reference) {
        return res.status(400).json({ error: 'Payment reference is required' });
      }

      // Prevent duplicate reference replay attacks
      const duplicate = event.transactions.find(t => String(t.id) === String(reference));
      if (duplicate) {
        return res.status(409).json({ error: 'This payment reference has already been used' });
      }

      try {
        const verifyUrl = `https://api.paystack.co/transaction/verify/${encodeURIComponent(reference)}`;
        const response = await axios.get(verifyUrl, {
          headers: { 'Authorization': `Bearer ${paystackSecretKey}` },
          timeout: 10000
        });

        const transaction = response.data.data;

        if (transaction.status !== 'success') {
          return res.status(400).json({ error: 'Payment not completed' });
        }

        // Paystack returns amounts in kobo
        if (transaction.amount !== expectedAmtKobo) {
          console.warn(`Amount mismatch: expected ${expectedAmtKobo} kobo, got ${transaction.amount} kobo`);
          return res.status(400).json({ error: 'Payment amount mismatch' });
        }
      } catch (error) {
        if (error.response?.status === 404) {
          return res.status(400).json({ error: 'Payment reference not found' });
        }
        console.error('Paystack verification error:', error.message);
        return res.status(500).json({ error: 'Payment verification error. Please try again.' });
      }
    }

    // Record vote
    nominee.votes += votes;

    const category = event.categories.find(c => c.id === nominee.catId);

    event.transactions.push({
      id: reference || `DEMO-${Date.now()}`,
      nomineeId: nominee.id,
      nomName: nominee.name,
      catName: category ? category.name : 'Unknown',
      votes,
      amt: expectedAmtGHS,
      qty: votes,
      phone: cleanPhone,
      name: sanitizeString(name, 100) || 'Anonymous',
      method: ['mtn', 'telecel'].includes(method) ? method : 'mtn',
      time: new Date(),
      status: 'success'
    });

    await event.save();
    res.json({ success: true });
  } catch (error) {
    console.error('Error recording vote:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/events/:id/sms-receipt', async (req, res) => {
  try {
    const eventId = parseInt(req.params.id);
    const event = await Event.findOne({ id: eventId });
    if (!event) return res.status(404).json({ success: false, error: 'Event not found' });

    const phone = sanitizeString(req.body.phone, 30);
    const name = sanitizeString(req.body.name, 100) || 'Voter';
    const qty = validateVoteQty(req.body.qty) || 0;
    const amt = parseFloat(req.body.amt) || 0;
    const reference = sanitizeString(req.body.reference, 100) || '';
    const nominee = sanitizeString(req.body.nominee, 100) || 'Nominee';
    const programme = sanitizeString(req.body.programme, 100) || event.name;

    const accountSid = process.env.TWILIO_ACCOUNT_SID;
    const authToken = process.env.TWILIO_AUTH_TOKEN;
    const fromNumber = process.env.TWILIO_FROM_NUMBER;

    if (!accountSid || !authToken || !fromNumber) {
      return res.json({ success: false, error: 'SMS not configured' });
    }

    const toNumber = formatGhanaSmsNumber(phone);
    if (!toNumber) {
      return res.status(400).json({ success: false, error: 'Invalid phone number' });
    }

    const body = `Thank you ${name} for voting in ${programme}. ${qty} vote${qty===1?'':'s'} for ${nominee} is confirmed. Reference: ${reference}. Total: GHC ${amt.toFixed(2)}.`;
    const url = `https://api.twilio.com/2010-04-01/Accounts/${accountSid}/Messages.json`;
    const params = new URLSearchParams();
    params.append('From', fromNumber);
    params.append('To', toNumber);
    params.append('Body', body);

    const authHeader = Buffer.from(`${accountSid}:${authToken}`).toString('base64');
    const response = await axios.post(url, params.toString(), {
      headers: {
        'Authorization': `Basic ${authHeader}`,
        'Content-Type': 'application/x-www-form-urlencoded'
      }
    });

    if (response.data && response.data.sid) {
      return res.json({ success: true });
    }

    res.json({ success: false, error: 'Unable to send SMS receipt' });
  } catch (error) {
    console.error('Error sending SMS receipt:', error.response?.data || error.message);
    res.status(500).json({ success: false, error: 'SMS service error' });
  }
});

// ================= TOGGLE VOTING =================
app.post('/api/events/:id/toggle', authMiddleware, async (req, res) => {
  try {
    const eventId = parseInt(req.params.id);
    const event = await Event.findOne({ id: eventId });
    if (!event) return res.status(404).json({ error: 'Event not found' });

    event.votingOpen = !event.votingOpen;
    await event.save();
    res.json({ votingOpen: event.votingOpen });
  } catch (error) {
    console.error('Error toggling voting:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// ================= TOGGLE SHOW RESULTS =================
app.post('/api/events/:id/toggle-results', authMiddleware, async (req, res) => {
  try {
    const eventId = parseInt(req.params.id);
    const event = await Event.findOne({ id: eventId });
    if (!event) return res.status(404).json({ error: 'Event not found' });

    event.showResults = !event.showResults;
    await event.save();
    res.json({ showResults: event.showResults });
  } catch (error) {
    console.error('Error toggling results visibility:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// ================= FRAUD CONTROL =================
app.post('/api/events/:id/block', authMiddleware, async (req, res) => {
  if (req.session.role === 'event') {
    return res.status(403).json({ error: 'Event admins cannot block numbers' });
  }

  const phone = sanitizeString(req.body.phone, 20);
  if (!phone) return res.status(400).json({ error: 'Phone number required' });

  try {
    const eventId = parseInt(req.params.id);
    const event = await Event.findOne({ id: eventId });
    if (!event) return res.status(404).json({ error: 'Event not found' });

    if (!event.blocked.includes(phone)) {
      event.blocked.push(phone);
      await event.save();
    }
    res.json({ success: true, blocked: event.blocked });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/events/:id/unblock', authMiddleware, async (req, res) => {
  if (req.session.role === 'event') {
    return res.status(403).json({ error: 'Event admins cannot unblock numbers' });
  }

  const phone = sanitizeString(req.body.phone, 20);
  if (!phone) return res.status(400).json({ error: 'Phone number required' });

  try {
    const eventId = parseInt(req.params.id);
    const event = await Event.findOne({ id: eventId });
    if (!event) return res.status(404).json({ error: 'Event not found' });

    event.blocked = event.blocked.filter(b => b !== phone);
    await event.save();
    res.json({ success: true, blocked: event.blocked });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ================= VOTE ADJUSTMENT (Super Admin Only) =================
app.post('/api/events/:id/nominees/:nomId/adjust', authMiddleware, async (req, res) => {
  if (req.session.role !== 'super') {
    return res.status(403).json({ error: 'Only super admins can adjust votes' });
  }

  const adjustment = parseInt(req.body.adjustment);
  if (isNaN(adjustment)) return res.status(400).json({ error: 'Invalid adjustment value' });
  if (Math.abs(adjustment) > 100000) return res.status(400).json({ error: 'Adjustment too large' });

  try {
    const eventId = parseInt(req.params.id);
    const nomId = parseInt(req.params.nomId);
    const event = await Event.findOne({ id: eventId });
    if (!event) return res.status(404).json({ error: 'Event not found' });

    const nominee = event.nominees.find(n => n.id == nomId);
    if (!nominee) return res.status(404).json({ error: 'Nominee not found' });

    nominee.votes = Math.max(0, nominee.votes + adjustment);
    await event.save();
    res.json({ success: true, newTotal: nominee.votes });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ================= ADMIN MANAGEMENT =================
app.get('/api/admin/eventadmins', authMiddleware, async (req, res) => {
  if (req.session.role !== 'super') {
    return res.status(403).json({ error: 'Only super admins can view all admins' });
  }

  try {
    const admins = await EventAdmin.find({}, { password: 0 });
    res.json(admins);
  } catch (error) {
    console.error('Error fetching admins:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/admin/eventadmins', authMiddleware, async (req, res) => {
  if (req.session.role !== 'super') {
    return res.status(403).json({ error: 'Only super admins can create admins' });
  }

  const username = sanitizeString(req.body.username, 50);
  const password = sanitizeString(req.body.password, 200);

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }
  if (password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters' });
  }
  if (!/^[a-zA-Z0-9_.-]+$/.test(username)) {
    return res.status(400).json({ error: 'Username can only contain letters, numbers, underscores, hyphens, and dots' });
  }

  try {
    const existingAdmin = await EventAdmin.findOne({ username });
    if (existingAdmin) return res.status(400).json({ error: 'Username already exists' });

    const superAdmin = await SuperAdmin.findOne();
    if (superAdmin && superAdmin.username === username) {
      return res.status(400).json({ error: 'Username already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newAdmin = new EventAdmin({
      id: Date.now(),
      username,
      password: hashedPassword,
      events: []
    });

    await newAdmin.save();
    res.json({ success: true, admin: { id: newAdmin.id, username: newAdmin.username, events: newAdmin.events } });
  } catch (error) {
    console.error('Error creating admin:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/admin/eventadmins/:adminId/assign/:eventId', authMiddleware, async (req, res) => {
  if (req.session.role !== 'super') {
    return res.status(403).json({ error: 'Only super admins can assign admins' });
  }

  try {
    const adminId = parseInt(req.params.adminId);
    const eventId = parseInt(req.params.eventId);

    const eventAdmin = await EventAdmin.findOne({ id: adminId });
    if (!eventAdmin) return res.status(404).json({ error: 'Event admin not found' });

    const event = await Event.findOne({ id: eventId });
    if (!event) return res.status(404).json({ error: 'Event not found' });

    if (!eventAdmin.events.includes(eventId)) {
      eventAdmin.events.push(eventId);
    }
    await eventAdmin.save();
    res.json({ success: true });
  } catch (error) {
    console.error('Error assigning admin:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/admin/eventadmins/:adminId/unassign/:eventId', authMiddleware, async (req, res) => {
  if (req.session.role !== 'super') {
    return res.status(403).json({ error: 'Only super admins can unassign admins' });
  }

  try {
    const adminId = parseInt(req.params.adminId);
    const eventId = parseInt(req.params.eventId);

    const eventAdmin = await EventAdmin.findOne({ id: adminId });
    if (!eventAdmin) return res.status(404).json({ error: 'Event admin not found' });

    eventAdmin.events = eventAdmin.events.filter(id => id != eventId);
    await eventAdmin.save();
    res.json({ success: true });
  } catch (error) {
    console.error('Error unassigning admin:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/admin/eventadmins/:adminId', authMiddleware, async (req, res) => {
  if (req.session.role !== 'super') {
    return res.status(403).json({ error: 'Only super admins can delete admins' });
  }

  try {
    const adminId = parseInt(req.params.adminId);
    const result = await EventAdmin.deleteOne({ id: adminId });
    if (result.deletedCount === 0) return res.status(404).json({ error: 'Event admin not found' });
    res.json({ success: true });
  } catch (error) {
    console.error('Error deleting admin:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// ================= DELETE / UPDATE OPERATIONS =================
app.delete('/api/events/:id', authMiddleware, async (req, res) => {
  if (req.session.role !== 'super') {
    return res.status(403).json({ error: 'Only super admins can delete events' });
  }

  try {
    const eventId = parseInt(req.params.id);
    const result = await Event.deleteOne({ id: eventId });
    if (result.deletedCount === 0) return res.status(404).json({ error: 'Event not found' });
    res.json({ success: true });
  } catch (error) {
    console.error('Error deleting event:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/events/:id', authMiddleware, async (req, res) => {
  try {
    const eventId = parseInt(req.params.id);
    const event = await Event.findOne({ id: eventId });
    if (!event) return res.status(404).json({ error: 'Event not found' });

    if (req.session.role === 'event') {
      // Verify this admin manages this event
      const admin = await EventAdmin.findOne({ id: req.session.adminId });
      if (!admin || !admin.events.includes(eventId)) {
        return res.status(403).json({ error: 'Access denied to this event' });
      }
      // Event admins can only change votingOpen
      if (req.body.votingOpen !== undefined) event.votingOpen = !!req.body.votingOpen;
    } else {
      if (req.body.name) event.name = sanitizeString(req.body.name, 200);
      if (req.body.desc !== undefined) event.desc = sanitizeString(req.body.desc, 500);
      if (req.body.votePrice !== undefined) {
        const price = validatePrice(req.body.votePrice);
        if (price) event.votePrice = price;
      }
      if (req.body.photo !== undefined) event.photo = req.body.photo;
      if (req.body.showResults !== undefined) event.showResults = !!req.body.showResults;
      if (req.body.votingOpen !== undefined) event.votingOpen = !!req.body.votingOpen;
    }

    await event.save();
    res.json({ success: true, event });
  } catch (error) {
    console.error('Error updating event:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// ================= FILE UPLOADS (Auth Required) =================
app.post('/api/upload', authMiddleware, uploadLimiter, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  res.json({ success: true, url: `/uploads/${req.file.filename}` });
});

app.post('/api/events/:id/nominee/:nomId/photo', authMiddleware, uploadLimiter, upload.single('photo'), async (req, res) => {
  try {
    const eventId = parseInt(req.params.id);
    const nomId = parseInt(req.params.nomId);
    const event = await Event.findOne({ id: eventId });

    if (!event) return res.status(404).json({ error: 'Event not found' });
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

    const nominee = event.nominees.find(n => n.id == nomId);
    if (!nominee) return res.status(404).json({ error: 'Nominee not found' });

    nominee.photo = `/uploads/${req.file.filename}`;
    await event.save();
    res.json({ success: true, photo: nominee.photo });
  } catch (error) {
    console.error('Error uploading nominee photo:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/events/:id/photo', authMiddleware, uploadLimiter, upload.single('photo'), async (req, res) => {
  try {
    const eventId = parseInt(req.params.id);
    const event = await Event.findOne({ id: eventId });

    if (!event) return res.status(404).json({ error: 'Event not found' });
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

    event.photo = `/uploads/${req.file.filename}`;
    await event.save();
    res.json({ success: true, photo: event.photo });
  } catch (error) {
    console.error('Error uploading event photo:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// ================= MULTER ERROR HANDLER =================
app.use((err, req, res, next) => {
  if (err.code === 'LIMIT_FILE_SIZE') {
    return res.status(400).json({ error: 'File too large. Maximum size is 5MB.' });
  }
  if (err.message === 'Only image files are allowed') {
    return res.status(400).json({ error: err.message });
  }
  next(err);
});

// ================= START =================
app.listen(PORT, '0.0.0.0', async () => {
  try {
    await initializeDB();

    const os = require('os');
    const interfaces = os.networkInterfaces();
    const ipv4 = Object.values(interfaces)
      .flat()
      .find(addr => addr.family === 'IPv4' && !addr.internal)?.address || 'localhost';

    if (NODE_ENV !== 'production') {
      console.log(`\n✦ LESVOTE is running in ${NODE_ENV} mode`);
      console.log(`  Local:   http://localhost:${PORT}`);
      console.log(`  Network: http://${ipv4}:${PORT}`);
      console.log(`  Database: MongoDB at ${MONGODB_URI}`);
    } else {
      console.log(`✦ LESVOTE is running (${NODE_ENV} mode)`);
      console.log(`  Database: MongoDB connected`);
    }
  } catch (error) {
    console.error('Failed to start server:', error.message);
    process.exit(1);
  }
});
