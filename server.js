const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Secret key for JWT
const JWT_SECRET = "TAVIAN_SUPER_SECRET_KEY_CHANGE_THIS_12345";

// Data file path
const DATA_FILE = path.join(__dirname, 'data.json');

// Initialize data file
if (!fs.existsSync(DATA_FILE)) {
    fs.writeFileSync(DATA_FILE, JSON.stringify({ users: [] }, null, 2));
}

// ============= FIXED CORS CONFIGURATION =============
// Allow all origins for testing (change this in production)
const allowedOrigins = [
    'http://localhost:5500',
    'http://127.0.0.1:5500',
    'http://localhost:3000',
    'http://127.0.0.1:3000',
    'http://localhost:3001',
    'http://127.0.0.1:3001',
    'https://tavian-app.onrender.com',
    'null' // for file:// protocol
];

app.use(cors({
    origin: function(origin, callback) {
        // Allow requests with no origin (like mobile apps or curl)
        if (!origin) return callback(null, true);
        if (allowedOrigins.indexOf(origin) !== -1 || true) { // true = allow all for testing
            callback(null, true);
        } else {
            console.log('Origin not allowed:', origin);
            callback(null, true); // Still allow for testing
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
    allowedHeaders: ['Content-Type', 'Authorization', 'Cookie', 'X-Requested-With']
}));

// Handle preflight requests
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

// ============= AUTH MIDDLEWARE =============
function authenticateToken(req, res, next) {
    const token = req.cookies.tavian_token;
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

// GET current user
app.get('/api/me', authenticateToken, (req, res) => {
    const users = readUsers();
    const user = users.find(u => u.username === req.user.username);
    if (!user) {
        return res.status(404).json({ error: 'User not found' });
    }
    const { password, ...safe } = user;
    res.json(safe);
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
    
    const token = jwt.sign({ username: newUser.username }, JWT_SECRET, { expiresIn: '7d' });
    
    res.cookie('tavian_token', token, {
        httpOnly: true,
        secure: false,
        sameSite: 'lax',
        maxAge: 7 * 24 * 60 * 60 * 1000
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
    
    const token = jwt.sign({ username: user.username }, JWT_SECRET, { expiresIn: '7d' });
    
    res.cookie('tavian_token', token, {
        httpOnly: true,
        secure: false,
        sameSite: 'lax',
        maxAge: 7 * 24 * 60 * 60 * 1000
    });
    
    const { password: _, ...safe } = user;
    res.json(safe);
});

// POST logout
app.post('/api/logout', (req, res) => {
    res.clearCookie('tavian_token');
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
    
    res.clearCookie('tavian_token');
    res.json({ success: true });
});

// Simple test endpoint
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
    console.log(`  POST /api/register - Register`);
    console.log(`  POST /api/login - Login`);
    console.log(`  POST /api/logout - Logout`);
});
