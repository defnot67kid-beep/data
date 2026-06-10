const express = require('express');
const cors = require('cors');
const jwt = require('jwt-simple');
const bcrypt = require('bcryptjs');
const fetch = require('node-fetch'); // Ensure you run 'npm install node-fetch@2' or configure standard fetch

const app = express();
app.use(cors());
app.use(express.json());

// ============================================
// CONFIGURATIONS & CONSTANTS
// ============================================
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'SUPER_SECRET_TAVIAN_KEY_2026';
const HCAPTCHA_SECRET = process.env.HCAPTCHA_SECRET || '0x0000000000000000000000000000000000000000'; // Replace with real secret

// ============================================
// IN-MEMORY DATA STORE (Production should use Database)
// ============================================
let users = [
    {
        id: 1,
        username: 'realgysj',
        email: 'owner@tavian.com',
        passwordHash: bcrypt.hashSync('tavianowner2026', 10),
        displayName: 'RealGysj',
        role: 'owner',
        tavix: 500000,
        bio: 'Welcome to Tavian. Contact me if something goes wrong.'
    },
    {
        id: 2,
        username: 'plstealme2',
        email: 'admin@tavian.com',
        passwordHash: bcrypt.hashSync('tavianadmin2026', 10),
        displayName: 'Plstealme2',
        role: 'admin',
        tavix: 100000,
        bio: 'Platform System Administrator. Report rules violators directly.'
    }
];

let transactions = [];
let notifications = [];

// Helper to auto-increment user database IDs
let nextUserId = users.length + 1;
let nextNotificationId = 1;

// ============================================
// SECURITY MIDDLEWARE UTILITIES
// ============================================
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ success: false, error: 'Access denied. Authorization token missing.' });
    }

    try {
        const decoded = jwt.decode(token, JWT_SECRET);
        const user = users.find(u => u.id === decoded.id);
        
        if (!user) {
            return res.status(404).json({ success: false, error: 'Session identity user no longer exists.' });
        }

        req.user = user;
        next();
    } catch (err) {
        return res.status(403).json({ success: false, error: 'Invalid or expired secure authentication token.' });
    }
}

function requireRole(role) {
    return (req, res, next) => {
        if (!req.user || req.user.role !== role) {
            return res.status(403).json({ success: false, error: `Unauthorized restriction. Requires role tier level: ${role}` });
        }
        next();
    };
}

// ============================================
// SECURITY & AUTHENTICATION ENDPOINTS
// ============================================

// POST: /api/auth/register
app.post('/api/auth/register', async (req, res) => {
    const { username, email, password, 'h-captcha-response': captchaToken } = req.body;

    if (!username || !email || !password) {
        return res.json({ success: false, error: 'Please fulfill all mandatory user sign up entry items.' });
    }

    // Verify hCaptcha verification payload token
    if (!captchaToken) {
        return res.json({ success: false, error: 'Please fulfill the human validation test puzzle.' });
    }

    try {
        const captchaVerifyUrl = 'https://hcaptcha.com/siteverify';
        const params = new URLSearchParams();
        params.append('secret', HCAPTCHA_SECRET);
        params.append('response', captchaToken);

        const captchaRes = await fetch(captchaVerifyUrl, { method: 'POST', body: params });
        const captchaData = await captchaRes.json();

        if (!captchaData.success) {
            return res.json({ success: false, error: 'Human validation puzzle failed verification. Try again.' });
        }
    } catch (err) {
        return res.json({ success: false, error: 'Authentication challenge provider currently unavailable.' });
    }

    // Clean data input validation strings
    const sanitizedUsername = username.trim().toLowerCase();

    // Check duplicate account registration values
    const existingUser = users.find(u => u.username === sanitizedUsername || u.email.toLowerCase() === email.trim().toLowerCase());
    if (existingUser) {
        return res.json({ success: false, error: 'Username or email address registration entry is already taken.' });
    }

    const newUser = {
        id: nextUserId++,
        username: sanitizedUsername,
        email: email.trim(),
        passwordHash: bcrypt.hashSync(password, 10),
        displayName: username.trim(),
        role: 'user',
        tavix: 0,
        bio: ''
    };

    users.push(newUser);

    // Create session signature token
    const token = jwt.encode({ id: newUser.id }, JWT_SECRET);

    res.json({
        success: true,
        token: token,
        user: { username: newUser.username, displayName: newUser.displayName, email: newUser.email }
    });
});

// POST: /api/auth/login
app.post('/api/auth/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.json({ success: false, error: 'Missing account credentials parameters input fields.' });
    }

    const targetUser = users.find(u => u.username === username.trim().toLowerCase());
    if (!targetUser || !bcrypt.compareSync(password, targetUser.passwordHash)) {
        return res.json({ success: false, error: 'Invalid security account credentials profile matched combinations.' });
    }

    const token = jwt.encode({ id: targetUser.id }, JWT_SECRET);

    res.json({
        success: true,
        token: token,
        user: { username: targetUser.username, displayName: targetUser.displayName, email: targetUser.email, tavix: targetUser.tavix }
    });
});

// GET: /api/auth/me
app.get('/api/auth/me', authenticateToken, (req, res) => {
    res.json({
        success: true,
        user: {
            id: req.user.id,
            username: req.user.username,
            displayName: req.user.displayName,
            email: req.user.email,
            role: req.user.role,
            tavix: req.user.tavix,
            bio: req.user.bio
        }
    });
});

// DELETE: /api/auth/delete
app.delete('/api/auth/delete', authenticateToken, (req, res) => {
    users = users.filter(u => u.id !== req.user.id);
    transactions = transactions.filter(t => t.sender !== req.user.username && t.recipient !== req.user.username);
    notifications = notifications.filter(n => n.username !== req.user.username);
    
    res.json({ success: true });
});

// ============================================
// PLAYERS / GENERAL USERS ENDPOINTS
// ============================================

// GET: /api/users
app.get('/api/users', (req, res) => {
    const publicUsersList = users.map(u => ({
        id: u.id,
        username: u.username,
        displayName: u.displayName,
        role: u.role,
        tavix: u.tavix,
        bio: u.bio
    }));
    res.json({ success: true, users: publicUsersList });
});

// POST: /api/users/profile/bio
app.post('/api/users/profile/bio', authenticateToken, (req, res) => {
    const { bio } = req.body;
    req.user.bio = bio !== undefined ? bio.toString() : '';
    res.json({ success: true });
});

// POST: /api/users/profile/displayname
app.post('/api/users/profile/displayname', authenticateToken, (req, res) => {
    const { displayName } = req.body;
    if (!displayName || displayName.trim().length === 0) {
        return res.json({ success: false, error: 'Display name change cannot contain blank strings parameters.' });
    }
    req.user.displayName = displayName.trim();
    res.json({ success: true });
});

// ============================================
// TAVIX STORE / TRANSACTION WALLET ENDPOINTS
// ============================================

// POST: /api/tavix/buy
app.post('/api/tavix/buy', authenticateToken, (req, res) => {
    const { amount } = req.body;
    const standardAmounts = [100, 500, 1000, 5000];

    if (!amount || !standardAmounts.includes(parseInt(amount))) {
        return res.json({ success: false, error: 'Invalid commercial currency product bundle parameters assignment.' });
    }

    req.user.tavix += parseInt(amount);

    transactions.unshift({
        type: 'buy',
        sender: 'SYSTEM',
        recipient: req.user.username,
        amount: parseInt(amount),
        timestamp: new Date().toISOString()
    });

    res.json({ success: true });
});

// POST: /api/tavix/gift
app.post('/api/tavix/gift', authenticateToken, (req, res) => {
    const { recipient, amount } = req.body;
    const giftAmount = parseInt(amount);

    if (!recipient || !giftAmount || isNaN(giftAmount) || giftAmount <= 0) {
        return res.json({ success: false, error: 'Please fulfill a valid recipient identity token assignment configuration.' });
    }

    if (req.user.username === recipient.trim().toLowerCase()) {
        return res.json({ success: false, error: 'Self-gifting virtual assets is not supported.' });
    }

    if (req.user.tavix < giftAmount) {
        return res.json({ success: false, error: 'Insufficient wallet ledger account balance parameters for gift action.' });
    }

    const targetRecipient = users.find(u => u.username === recipient.trim().toLowerCase());
    if (!targetRecipient) {
        return res.json({ success: false, error: 'Recipient target platform username parameter was not located.' });
    }

    // Process Transaction Exchange
    req.user.tavix -= giftAmount;
    targetRecipient.tavix += giftAmount;

    // Log internally
    transactions.unshift({
        type: 'gift',
        sender: req.user.username,
        recipient: targetRecipient.username,
        amount: giftAmount,
        timestamp: new Date().toISOString()
    });

    // Send Real-Time Recipient System Broadcast Alert Package Notice
    notifications.unshift({
        id: (nextNotificationId++).toString(),
        username: targetRecipient.username,
        type: 'gift',
        title: 'Virtual Asset Gift Package Received!',
        message: `@${req.user.username} sent you a gift bundle total sizing of ${giftAmount} ⌬ TAVIX currency assets!`,
        read: false,
        timestamp: new Date().toISOString()
    });

    res.json({ success: true });
});

// GET: /api/tavix/transactions
app.get('/api/tavix/transactions', authenticateToken, (req, res) => {
    const filteredLedger = transactions.filter(t => t.sender === req.user.username || t.recipient === req.user.username);
    res.json({ success: true, transactions: filteredLedger });
});

// ============================================
// NOTIFICATIONS MANAGEMENT SYSTEM ENDPOINTS
// ============================================

// GET: /api/notifications
app.get('/api/notifications', authenticateToken, (req, res) => {
    const userAlerts = notifications.filter(n => n.username === req.user.username);
    res.json({ success: true, notifications: userAlerts });
});

// POST: /api/notifications/:id/read
app.post('/api/notifications/:id/read', authenticateToken, (req, res) => {
    const notificationId = req.params.id;
    const targetAlert = notifications.find(n => n.id === notificationId && n.username === req.user.username);
    
    if (targetAlert) {
        targetAlert.read = true;
    }
    res.json({ success: true });
});

// ============================================
// ADMINISTRATIVE TIER UTILITIES (OWNER RESTRICTED)
// ============================================

// POST: /api/owner/modify-tavix
app.post('/api/owner/modify-tavix', authenticateToken, requireRole('owner'), (req, res) => {
    const { username, amount } = req.body;

    if (!username || amount === undefined || isNaN(amount)) {
        return res.json({ success: false, error: 'Incomplete utility tool input parameters configuration.' });
    }

    const targetUser = users.find(u => u.username === username.trim().toLowerCase());
    if (!targetUser) {
        return res.json({ success: false, error: 'Target identity username criteria does not exist inside repository registries.' });
    }

    targetUser.tavix = parseInt(amount);

    transactions.unshift({
        type: 'buy',
        sender: 'ADMINISTRATIVE OVERRIDE',
        recipient: targetUser.username,
        amount: parseInt(amount),
        timestamp: new Date().toISOString()
    });

    res.json({ success: true });
});

// POST: /api/owner/modify-role
app.post('/api/owner/modify-role', authenticateToken, requireRole('owner'), (req, res) => {
    const { username, role } = req.body;
    const supportedRoles = ['user', 'admin', 'owner'];

    if (!username || !role || !supportedRoles.includes(role.trim().toLowerCase())) {
        return res.json({ success: false, error: 'Invalid configuration status specifications target value context.' });
    }

    const targetUser = users.find(u => u.username === username.trim().toLowerCase());
    if (!targetUser) {
        return res.json({ success: false, error: 'Target account profile was not located in active collections records.' });
    }

    targetUser.role = role.trim().toLowerCase();
    res.json({ success: true });
});

// ============================================
// SYSTEM RUN INITIALIZER
// ============================================
app.listen(PORT, () => {
    console.log(`=================================================`);
    console.log(` 🔐 TAVIAN GAME PLATFORM ONLINE BACKEND MIDDLEWARE`);
    console.log(` 🚀 Listening deployment services directly on port: ${PORT}`);
    console.log(`=================================================`);
});
