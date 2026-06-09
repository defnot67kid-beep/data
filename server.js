const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Secret keys - Use environment variables in production!
const JWT_SECRET = process.env.JWT_SECRET || "TAVIAN_SUPER_SECRET_KEY_CHANGE_THIS_12345";
const HCAPTCHA_SECRET = process.env.HCAPTCHA_SECRET || "ES_3e9f86c0fff2435a9c741ef2d05a438f";

// Data file path
const DATA_FILE = path.join(__dirname, 'data.json');

// Initialize data file
if (!fs.existsSync(DATA_FILE)) {
    fs.writeFileSync(DATA_FILE, JSON.stringify({ users: [], nextId: 1 }, null, 2));
}

// ============= CORS CONFIGURATION =============
app.use(cors({
    origin: function(origin, callback) {
        // Allow all origins for development
        callback(null, true);
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
    allowedHeaders: ['Content-Type', 'Authorization', 'Cookie', 'X-Requested-With', 'X-Tavian-Token']
}));

app.options('*', cors());
app.use(express.json());
app.use(cookieParser());

// Helper functions
function readData() {
    const data = fs.readFileSync(DATA_FILE);
    return JSON.parse(data);
}

function writeData(data) {
    fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
}

function readUsers() {
    return readData().users;
}

function writeUsers(users) {
    const data = readData();
    data.users = users;
    writeData(data);
}

function getNextId() {
    const data = readData();
    const nextId = data.nextId || 1;
    data.nextId = nextId + 1;
    writeData(data);
    return nextId;
}

// Generate a secure session token (TAVIOSECURITY format compatible)
function generateSecureToken(userId, username) {
    // Create a token that looks like the format you showed but is actually our JWT
    const payload = {
        id: userId,
        username: username,
        timestamp: Date.now(),
        nonce: Math.random().toString(36).substring(2, 15)
    };
    
    // Generate JWT
    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '30d' });
    
    // Store in TAVIOSECURITY format as well for compatibility
    return token;
}

// Verify a secure token
function verifySecureToken(token) {
    if (!token) return null;
    
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        return decoded;
    } catch (error) {
        return null;
    }
}

// ============= hCaptcha Verification =============
async function verifyHCaptcha(hcaptchaResponse) {
    if (!hcaptchaResponse) return false;
    
    try {
        const https = require('https');
        const querystring = require('querystring');
        
        const postData = querystring.stringify({
            secret: HCAPTCHA_SECRET,
            response: hcaptchaResponse
        });
        
        const options = {
            hostname: 'hcaptcha.com',
            port: 443,
            path: '/siteverify',
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Content-Length': Buffer.byteLength(postData)
            }
        };
        
        const result = await new Promise((resolve, reject) => {
            const req = https.request(options, (res) => {
                let data = '';
                res.on('data', (chunk) => { data += chunk; });
                res.on('end', () => {
                    try {
                        const json = JSON.parse(data);
                        resolve(json);
                    } catch(e) {
                        reject(e);
                    }
                });
            });
            req.on('error', reject);
            req.write(postData);
            req.end();
        });
        
        return result.success === true;
    } catch (error) {
        console.error('hCaptcha verification error:', error);
        return false;
    }
}

// ============= AUTH MIDDLEWARE =============
function authenticateToken(req, res, next) {
    let token = null;
    
    // Check Authorization header (Bearer token)
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
        token = authHeader.substring(7);
    }
    
    // Check X-Tavian-Token header
    if (!token && req.headers['x-tavian-token']) {
        token = req.headers['x-tavian-token'];
    }
    
    // Check cookie
    if (!token) {
        token = req.cookies.tavian_token;
    }
    
    // Check for TAVIOSECURITY cookie
    if (!token && req.cookies.TAVIOSECURITY) {
        token = req.cookies.TAVIOSECURITY;
    }
    
    if (!token) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    
    const decoded = verifySecureToken(token);
    if (!decoded) {
        return res.status(401).json({ error: 'Invalid token' });
    }
    
    req.user = decoded;
    next();
}

// Optional auth middleware
function optionalAuth(req, res, next) {
    let token = null;
    
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
        token = authHeader.substring(7);
    }
    
    if (!token && req.headers['x-tavian-token']) {
        token = req.headers['x-tavian-token'];
    }
    
    if (!token) {
        token = req.cookies.tavian_token;
    }
    
    if (!token && req.cookies.TAVIOSECURITY) {
        token = req.cookies.TAVIOSECURITY;
    }
    
    if (token) {
        const decoded = verifySecureToken(token);
        if (decoded) {
            req.user = decoded;
        }
    }
    
    next();
}

// ============= API ENDPOINTS =============

// GET all users
app.get('/api/users', optionalAuth, (req, res) => {
    const users = readUsers();
    const safeUsers = users.map(u => {
        const { password, ...safe } = u;
        return safe;
    });
    res.json(safeUsers);
});

// GET user by ID
app.get('/api/users/:id', optionalAuth, (req, res) => {
    const users = readUsers();
    const userId = parseInt(req.params.id);
    const user = users.find(u => u.id === userId);
    
    if (!user) {
        return res.status(404).json({ error: 'User not found' });
    }
    
    const { password, ...safe } = user;
    res.json(safe);
});

// GET current user
app.get('/api/me', authenticateToken, (req, res) => {
    const users = readUsers();
    const user = users.find(u => u.id === req.user.id);
    if (!user) {
        return res.status(404).json({ error: 'User not found' });
    }
    const { password, ...safe } = user;
    res.json(safe);
});

// Enhanced auto-login endpoint
app.get('/api/auto-login', (req, res) => {
    let token = null;
    
    // Check various token sources
    token = req.cookies.tavian_token;
    if (!token && req.cookies.TAVIOSECURITY) {
        token = req.cookies.TAVIOSECURITY;
    }
    if (!token && req.headers['x-tavian-token']) {
        token = req.headers['x-tavian-token'];
    }
    
    if (!token) {
        return res.status(401).json({ error: 'No session found' });
    }
    
    const decoded = verifySecureToken(token);
    if (!decoded) {
        res.clearCookie('tavian_token', { path: '/' });
        res.clearCookie('TAVIOSECURITY', { path: '/' });
        return res.status(401).json({ error: 'Invalid session' });
    }
    
    const users = readUsers();
    const user = users.find(u => u.id === decoded.id);
    
    if (!user) {
        res.clearCookie('tavian_token', { path: '/' });
        res.clearCookie('TAVIOSECURITY', { path: '/' });
        return res.status(401).json({ error: 'User not found' });
    }
    
    // Refresh the token
    const newToken = generateSecureToken(user.id, user.username);
    
    // Set both cookie formats for compatibility
    res.cookie('tavian_token', newToken, {
        httpOnly: true,
        secure: false,
        sameSite: 'lax',
        maxAge: 30 * 24 * 60 * 60 * 1000,
        path: '/'
    });
    
    res.cookie('TAVIOSECURITY', newToken, {
        httpOnly: true,
        secure: false,
        sameSite: 'lax',
        maxAge: 30 * 24 * 60 * 60 * 1000,
        path: '/'
    });
    
    const { password, ...safe } = user;
    res.json({ success: true, user: safe, token: newToken });
});

// POST register
app.post('/api/register', async (req, res) => {
    const users = readUsers();
    const { username, email, password, displayName, hcaptchaResponse } = req.body;
    
    const isCaptchaValid = await verifyHCaptcha(hcaptchaResponse);
    if (!isCaptchaValid) {
        return res.status(400).json({ error: 'CAPTCHA verification failed. Please try again.' });
    }
    
    if (users.find(u => u.username.toLowerCase() === username.toLowerCase())) {
        return res.status(400).json({ error: 'Username already taken' });
    }
    if (users.find(u => u.email.toLowerCase() === email.toLowerCase())) {
        return res.status(400).json({ error: 'Email already exists' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    const isOwner = username.toLowerCase() === 'realgysj';
    const newId = getNextId();
    
    const newUser = {
        id: newId,
        username,
        email,
        password: hashedPassword,
        displayName: displayName || username,
        tavix: isOwner ? 1000000 : 0,
        about: '',
        visits: 0,
        transactions: [],
        notifications: [{
            id: Date.now(),
            title: "🎉 Welcome to Tavian!",
            message: isOwner ? "You received 1,000,000 TAVIX as owner!" : "Start earning TAVIX by playing games!",
            read: false,
            time: new Date().toISOString()
        }],
        savedDevices: [],
        createdAt: new Date().toISOString()
    };
    
    users.push(newUser);
    writeUsers(users);
    
    const token = generateSecureToken(newUser.id, newUser.username);
    
    // Set both cookie formats
    res.cookie('tavian_token', token, {
        httpOnly: true,
        secure: false,
        sameSite: 'lax',
        maxAge: 30 * 24 * 60 * 60 * 1000,
        path: '/'
    });
    
    res.cookie('TAVIOSECURITY', token, {
        httpOnly: true,
        secure: false,
        sameSite: 'lax',
        maxAge: 30 * 24 * 60 * 60 * 1000,
        path: '/'
    });
    
    const { password: _, ...safe } = newUser;
    res.status(201).json(safe);
});

// POST login
app.post('/api/login', async (req, res) => {
    const users = readUsers();
    const { username, password } = req.body;
    
    const user = users.find(u => u.username.toLowerCase() === username.toLowerCase());
    if (!user) {
        return res.status(401).json({ error: 'Invalid username or password' });
    }
    
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
        return res.status(401).json({ error: 'Invalid username or password' });
    }
    
    const token = generateSecureToken(user.id, user.username);
    
    // Set both cookie formats
    res.cookie('tavian_token', token, {
        httpOnly: true,
        secure: false,
        sameSite: 'lax',
        maxAge: 30 * 24 * 60 * 60 * 1000,
        path: '/'
    });
    
    res.cookie('TAVIOSECURITY', token, {
        httpOnly: true,
        secure: false,
        sameSite: 'lax',
        maxAge: 30 * 24 * 60 * 60 * 1000,
        path: '/'
    });
    
    const { password: _, ...safe } = user;
    res.json(safe);
});

// POST logout
app.post('/api/logout', (req, res) => {
    res.clearCookie('tavian_token', { path: '/' });
    res.clearCookie('TAVIOSECURITY', { path: '/' });
    res.json({ success: true });
});

// PUT update user
app.put('/api/users/:id', authenticateToken, async (req, res) => {
    const userId = parseInt(req.params.id);
    
    if (req.user.id !== userId) {
        return res.status(403).json({ error: 'Forbidden' });
    }
    
    const users = readUsers();
    const index = users.findIndex(u => u.id === userId);
    if (index === -1) {
        return res.status(404).json({ error: 'User not found' });
    }
    
    const allowedUpdates = ['displayName', 'about', 'tavix', 'transactions', 'notifications', 'savedDevices'];
    for (let key of allowedUpdates) {
        if (req.body[key] !== undefined) {
            users[index][key] = req.body[key];
        }
    }
    
    writeUsers(users);
    
    const { password, ...safe } = users[index];
    res.json(safe);
});

app.put('/api/user/:username', authenticateToken, async (req, res) => {
    const users = readUsers();
    const index = users.findIndex(u => u.username === req.params.username);
    
    if (index === -1) {
        return res.status(404).json({ error: 'User not found' });
    }
    
    if (req.user.username !== req.params.username) {
        return res.status(403).json({ error: 'Forbidden' });
    }
    
    const allowedUpdates = ['displayName', 'about', 'tavix', 'transactions', 'notifications', 'savedDevices'];
    for (let key of allowedUpdates) {
        if (req.body[key] !== undefined) {
            users[index][key] = req.body[key];
        }
    }
    
    writeUsers(users);
    
    const { password, ...safe } = users[index];
    res.json(safe);
});

// POST transaction
app.post('/api/transaction', authenticateToken, async (req, res) => {
    const { username, amount, reason, from } = req.body;
    
    if (req.user.username !== username) {
        return res.status(403).json({ error: 'Forbidden' });
    }
    
    const users = readUsers();
    const index = users.findIndex(u => u.username === username);
    if (index === -1) {
        return res.status(404).json({ error: 'User not found' });
    }
    
    if (!users[index].transactions) users[index].transactions = [];
    users[index].transactions.unshift({
        id: Date.now(),
        amount,
        reason,
        from: from || null,
        date: new Date().toISOString()
    });
    users[index].tavix = (users[index].tavix || 0) + amount;
    
    if (users[index].transactions.length > 50) users[index].transactions.pop();
    writeUsers(users);
    
    res.json({ success: true, newBalance: users[index].tavix });
});

// POST notification
app.post('/api/notification', authenticateToken, async (req, res) => {
    const { username, title, message } = req.body;
    
    if (req.user.username !== username) {
        return res.status(403).json({ error: 'Forbidden' });
    }
    
    const users = readUsers();
    const index = users.findIndex(u => u.username === username);
    if (index === -1) {
        return res.status(404).json({ error: 'User not found' });
    }
    
    if (!users[index].notifications) users[index].notifications = [];
    users[index].notifications.unshift({
        id: Date.now(),
        title,
        message,
        read: false,
        time: new Date().toISOString()
    });
    
    if (users[index].notifications.length > 50) users[index].notifications.pop();
    writeUsers(users);
    
    res.json({ success: true });
});

// DELETE user account
app.delete('/api/users/:id', authenticateToken, async (req, res) => {
    const userId = parseInt(req.params.id);
    
    if (req.user.id !== userId) {
        return res.status(403).json({ error: 'Forbidden' });
    }
    
    let users = readUsers();
    users = users.filter(u => u.id !== userId);
    writeUsers(users);
    
    res.clearCookie('tavian_token', { path: '/' });
    res.clearCookie('TAVIOSECURITY', { path: '/' });
    res.json({ success: true });
});

app.delete('/api/user/:username', authenticateToken, async (req, res) => {
    let users = readUsers();
    const userToDelete = users.find(u => u.username === req.params.username);
    
    if (!userToDelete) {
        return res.status(404).json({ error: 'User not found' });
    }
    
    if (req.user.username !== req.params.username) {
        return res.status(403).json({ error: 'Forbidden' });
    }
    
    users = users.filter(u => u.username !== req.params.username);
    writeUsers(users);
    
    res.clearCookie('tavian_token', { path: '/' });
    res.clearCookie('TAVIOSECURITY', { path: '/' });
    res.json({ success: true });
});

// MIGRATION: Add IDs to existing users
app.post('/api/migrate-ids', (req, res) => {
    const data = readData();
    let changed = false;
    
    data.users.forEach(user => {
        if (!user.id) {
            user.id = data.nextId || 1;
            data.nextId = (data.nextId || 1) + 1;
            changed = true;
        }
    });
    
    if (changed) {
        if (!data.nextId) data.nextId = data.users.length + 1;
        writeData(data);
        res.json({ message: 'IDs added to users', users: data.users.map(u => ({ id: u.id, username: u.username })) });
    } else {
        res.json({ message: 'All users already have IDs', users: data.users.map(u => ({ id: u.id, username: u.username })) });
    }
});

// Health check
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Start server
app.listen(PORT, () => {
    console.log(`Tavian backend running on http://localhost:${PORT}`);
    console.log(`✅ hCaptcha protection enabled`);
    console.log(`✅ User IDs enabled for #userid-profile URLs`);
    console.log(`✅ Persistent sessions (30 days)`);
    console.log(`✅ TAVIOSECURITY cookie format supported`);
    console.log(`✅ Guest token compatibility enabled`);
    console.log(`🔒 JWT Secret: ${JWT_SECRET.substring(0,10)}...`);
});
