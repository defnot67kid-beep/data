const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Secret keys
const JWT_SECRET = "TAVIAN_SUPER_SECRET_KEY_CHANGE_THIS_12345";
const SECURE_COOKIE_KEY = "tavian_security";

// Data file path
const DATA_FILE = path.join(__dirname, 'data.json');

// Initialize data file
if (!fs.existsSync(DATA_FILE)) {
    fs.writeFileSync(DATA_FILE, JSON.stringify({ users: [] }, null, 2));
}

// ============= CORS CONFIGURATION =============
app.use(cors({
    origin: function(origin, callback) {
        // Allow all origins for testing
        callback(null, true);
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
    allowedHeaders: ['Content-Type', 'Authorization', 'Cookie', 'X-Requested-With']
}));

app.options('*', cors());
app.use(express.json());
app.use(cookieParser());

// Helper functions
function readUsers() {
    const data = fs.readFileSync(DATA_FILE);
    return JSON.parse(data).users;
}

function writeUsers(users) {
    fs.writeFileSync(DATA_FILE, JSON.stringify({ users }, null, 2));
}

// Generate a secure session token for a user
function generateSecureToken(username) {
    // Create a token that includes username and a timestamp
    const payload = {
        username: username,
        timestamp: Date.now(),
        nonce: Math.random().toString(36).substring(2, 15)
    };
    return jwt.sign(payload, JWT_SECRET, { expiresIn: '30d' });
}

// Verify a secure token
function verifySecureToken(token) {
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        return decoded;
    } catch (error) {
        return null;
    }
}

// ============= AUTH MIDDLEWARE =============
function authenticateToken(req, res, next) {
    // First try to get from Authorization header
    const authHeader = req.headers.authorization;
    let token = null;
    
    if (authHeader && authHeader.startsWith('Bearer ')) {
        token = authHeader.substring(7);
    }
    
    // Then try cookie
    if (!token) {
        token = req.cookies.tavian_token;
    }
    
    if (!token) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        return res.status(401).json({ error: 'Invalid token' });
    }
}

// ============= API ENDPOINTS =============

// GET all users (public)
app.get('/api/users', (req, res) => {
    const users = readUsers();
    const safeUsers = users.map(u => {
        const { password, ...safe } = u;
        return safe;
    });
    res.json(safeUsers);
});

// GET current user via secure cookie
app.get('/api/me', authenticateToken, (req, res) => {
    const users = readUsers();
    const user = users.find(u => u.username === req.user.username);
    if (!user) {
        return res.status(404).json({ error: 'User not found' });
    }
    const { password, ...safe } = user;
    res.json(safe);
});

// Auto-login endpoint - checks if user has valid cookie and returns user data
app.get('/api/auto-login', (req, res) => {
    const token = req.cookies.tavian_token;
    
    if (!token) {
        return res.status(401).json({ error: 'No session found' });
    }
    
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const users = readUsers();
        const user = users.find(u => u.username === decoded.username);
        
        if (!user) {
            return res.status(401).json({ error: 'User not found' });
        }
        
        // Refresh the token (extend session)
        const newToken = generateSecureToken(user.username);
        res.cookie('tavian_token', newToken, {
            httpOnly: true,
            secure: false, // Set to true if using HTTPS
            sameSite: 'lax',
            maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
            path: '/'
        });
        
        const { password, ...safe } = user;
        res.json({ success: true, user: safe });
    } catch (error) {
        res.clearCookie('tavian_token');
        res.status(401).json({ error: 'Invalid session' });
    }
});

// POST register
app.post('/api/register', async (req, res) => {
    const users = readUsers();
    const { username, email, password, displayName } = req.body;
    
    if (users.find(u => u.username.toLowerCase() === username.toLowerCase())) {
        return res.status(400).json({ error: 'Username already taken' });
    }
    if (users.find(u => u.email.toLowerCase() === email.toLowerCase())) {
        return res.status(400).json({ error: 'Email already exists' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    const isOwner = username.toLowerCase() === 'realgysj';
    
    const newUser = {
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
    
    // Generate secure token
    const token = generateSecureToken(newUser.username);
    
    // Set secure cookie
    res.cookie('tavian_token', token, {
        httpOnly: true,
        secure: false,
        sameSite: 'lax',
        maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
        path: '/'
    });
    
    const { password: _, ...safe } = newUser;
    res.status(201).json(safe);
});

// POST login - sets secure cookie
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
    
    // Generate secure token
    const token = generateSecureToken(user.username);
    
    // Set secure cookie
    res.cookie('tavian_token', token, {
        httpOnly: true,
        secure: false,
        sameSite: 'lax',
        maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
        path: '/'
    });
    
    const { password: _, ...safe } = user;
    res.json(safe);
});

// POST logout - clears the cookie
app.post('/api/logout', (req, res) => {
    res.clearCookie('tavian_token', { path: '/' });
    res.json({ success: true });
});

// PUT update user
app.put('/api/user/:username', authenticateToken, async (req, res) => {
    if (req.user.username !== req.params.username) {
        return res.status(403).json({ error: 'Forbidden' });
    }
    
    const users = readUsers();
    const index = users.findIndex(u => u.username === req.params.username);
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
app.delete('/api/user/:username', authenticateToken, async (req, res) => {
    if (req.user.username !== req.params.username) {
        return res.status(403).json({ error: 'Forbidden' });
    }
    
    let users = readUsers();
    users = users.filter(u => u.username !== req.params.username);
    writeUsers(users);
    
    res.clearCookie('tavian_token', { path: '/' });
    res.json({ success: true });
});

// Health check
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Start server
app.listen(PORT, () => {
    console.log(`Tavian backend running on http://localhost:${PORT}`);
    console.log(`API endpoints:`);
    console.log(`  GET  /api/health - Health check`);
    console.log(`  GET  /api/users - Get all users`);
    console.log(`  GET  /api/me - Get current user`);
    console.log(`  GET  /api/auto-login - Auto-login via cookie`);
    console.log(`  POST /api/register - Register`);
    console.log(`  POST /api/login - Login`);
    console.log(`  POST /api/logout - Logout`);
});
