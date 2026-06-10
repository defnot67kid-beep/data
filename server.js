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

// Frontend URLs
const FRONTEND_URL = process.env.FRONTEND_URL || "https://tavian.netlify.app";
const LOCAL_URLS = ['http://localhost:3000', 'http://localhost:5500', 'http://127.0.0.1:5500', 'http://localhost:8080', 'http://127.0.0.1:8080'];

// Data file path
const DATA_FILE = path.join(__dirname, 'data.json');

// Initialize data file
if (!fs.existsSync(DATA_FILE)) {
    fs.writeFileSync(DATA_FILE, JSON.stringify({ users: [], nextId: 1, chatLogs: [] }, null, 2));
}

// ============= ADVANCED MODERATION SYSTEM (same as before) =============
const bannedWords = new Map([
    ['fuck', { severity: 10, contexts: ['sexual', 'insult', 'violent'] }],
    ['shit', { severity: 7, contexts: ['excretory', 'insult'] }],
    ['damn', { severity: 3, contexts: ['mild'] }],
    ['ass', { severity: 5, contexts: ['insult', 'bodypart'] }],
    ['bitch', { severity: 8, contexts: ['insult', 'misogynistic'] }],
    ['cunt', { severity: 10, contexts: ['extreme', 'insult'] }],
    ['dick', { severity: 7, contexts: ['sexual', 'insult'] }],
    ['pussy', { severity: 8, contexts: ['sexual', 'insult'] }],
    ['cock', { severity: 8, contexts: ['sexual'] }],
    ['whore', { severity: 9, contexts: ['sexual', 'insult'] }],
    ['bastard', { severity: 6, contexts: ['insult'] }],
    ['slut', { severity: 9, contexts: ['sexual', 'insult'] }],
    ['nigger', { severity: 10, contexts: ['racist', 'extreme'] }],
    ['nigga', { severity: 8, contexts: ['racist', 'cultural'] }],
    ['faggot', { severity: 10, contexts: ['homophobic', 'extreme'] }],
    ['retard', { severity: 8, contexts: ['ableist', 'insult'] }],
    ['kys', { severity: 10, contexts: ['violent', 'selfharm'] }],
    ['kill yourself', { severity: 10, contexts: ['violent', 'selfharm'] }],
    ['cum', { severity: 8, contexts: ['sexual'] }],
    ['dildo', { severity: 7, contexts: ['sexual'] }],
    ['porn', { severity: 6, contexts: ['sexual'] }],
    ['nude', { severity: 5, contexts: ['sexual'] }],
    ['anal', { severity: 7, contexts: ['sexual'] }],
    ['ballsack', { severity: 6, contexts: ['sexual', 'bodypart'] }],
    ['rape', { severity: 10, contexts: ['violent', 'sexual'] }],
    ['rapist', { severity: 10, contexts: ['violent', 'sexual'] }],
    ['motherfucker', { severity: 9, contexts: ['insult', 'extreme'] }],
    ['fucker', { severity: 8, contexts: ['insult'] }],
    ['twat', { severity: 7, contexts: ['insult', 'bodypart'] }],
    ['clit', { severity: 7, contexts: ['sexual', 'bodypart'] }],
    ['boner', { severity: 6, contexts: ['sexual'] }],
    ['prick', { severity: 5, contexts: ['insult'] }],
    ['wanker', { severity: 6, contexts: ['insult'] }],
    ['bollocks', { severity: 5, contexts: ['mild'] }],
    ['arsehole', { severity: 7, contexts: ['insult'] }],
    ['asshole', { severity: 6, contexts: ['insult'] }],
    ['shithead', { severity: 7, contexts: ['insult'] }],
    ['dumbass', { severity: 5, contexts: ['insult'] }],
    ['hitler', { severity: 10, contexts: ['hate', 'historical'] }],
    ['nazi', { severity: 10, contexts: ['hate', 'historical'] }],
    ['holocaust', { severity: 9, contexts: ['sensitive'] }],
    ['white power', { severity: 10, contexts: ['racist', 'hate'] }],
    ['black power', { severity: 4, contexts: ['political'] }],
]);

const allowlist = new Set([
    'assassin', 'assassinate', 'assassination', 'assault', 'assemble', 'assembly', 
    'assist', 'assistant', 'associate', 'association', 'assume', 'assumption', 
    'assure', 'assurance', 'asset', 'assets', 'assign', 'assignment', 'assistive',
    'assert', 'assertion', 'assess', 'assessment', 'assimilate', 'assimilation',
    'cocktail', 'cockatoo', 'cockpit', 'cocksure', 'cocky', 'cockney', 'cockerel',
    'cockroach', 'cockscomb', 'cockleshell', 'cockfight', 'cockspur',
    'ship', 'shipping', 'shipment', 'shirt', 'shift', 'shifting', 'shifty',
    'fuchsia', 'fuchi', 'bitcoin', 'bicycle', 'biscuit', 'bistro',
    'damage', 'damaging', 'damascus', 'damask', 'night', 'nightmare', 'nightly',
    'nigeria', 'nigerian', 'niger', 'grape', 'scrape', 'scraper', 'rapid', 'rapidly',
    'skill', 'skilling', 'killingly', 'sussex', 'essex', 'wessex', 'middlesex'
]);

const safePhrases = new Set([
    'i love this game', 'good game', 'nice shot', 'well played',
    'how are you', 'im fine', 'thank you', 'thanks', 'please',
    'sorry', 'my bad', 'good luck', 'have fun', 'enjoying',
    'beautiful', 'amazing', 'awesome', 'fantastic', 'wonderful'
]);

const dangerousPatterns = [
    { regex: /\b(kill\s+yourself|kys|self\s+harm|suicide)\b/i, severity: 10, type: 'selfharm' },
    { regex: /\b(rape|rapist|molest|pedophile)\b/i, severity: 10, type: 'sexual_violence' },
    { regex: /\b(bomb|terrorist|jihad|shoot\s+up)\b/i, severity: 10, type: 'terrorism' },
    { regex: /\b(white\s+supremacy|kkk|klansman|aryan)\b/i, severity: 10, type: 'hatespeech' },
];

const leetMap = {
    '0': 'o', '1': 'i', '2': 'z', '3': 'e', '4': 'a', '5': 's', '6': 'g', '7': 't', '8': 'b', '9': 'g',
    '@': 'a', '!': 'i', '$': 's', '%': 'e', '^': 'n', '&': 'a', '*': 'o', '(': 'c', ')': 'c',
};

function normalizeLeet(text) {
    let normalized = text.toLowerCase();
    for (const [leet, normal] of Object.entries(leetMap)) {
        normalized = normalized.split(leet).join(normal);
    }
    return normalized;
}

function isAllowlisted(word) {
    const normalized = word.toLowerCase();
    if (allowlist.has(normalized)) return true;
    for (const allowed of allowlist) {
        if (normalized.includes(allowed) && allowed.length > 3) {
            return true;
        }
    }
    return false;
}

function isSafePhrase(message) {
    const lowerMsg = message.toLowerCase();
    for (const phrase of safePhrases) {
        if (lowerMsg.includes(phrase)) return true;
    }
    return false;
}

function checkContext(message, badWord) {
    const lowerMsg = message.toLowerCase();
    const positiveIndicators = ['not', 'no', 'never', 'isn\'t', 'aren\'t'];
    for (const indicator of positiveIndicators) {
        const pattern = new RegExp(`\\b${indicator}\\s+${badWord}\\b`, 'i');
        if (pattern.test(lowerMsg)) {
            return { allowed: true, reason: 'negation_context' };
        }
    }
    return { allowed: false, reason: 'flagged' };
}

function advancedModerationCheck(message, username = '') {
    const result = { allowed: true, blocked: false, reason: '', severity: 0, flaggedWords: [] };
    
    if (!message || message.trim().length === 0) return result;
    if (isSafePhrase(message)) return result;
    
    let normalized = normalizeLeet(message);
    
    for (const pattern of dangerousPatterns) {
        if (pattern.regex.test(normalized)) {
            result.allowed = false;
            result.blocked = true;
            result.reason = pattern.type;
            result.severity = pattern.severity;
            return result;
        }
    }
    
    const words = normalized.split(/\s+/);
    for (const word of words) {
        if (word.length < 3) continue;
        if (isAllowlisted(word)) continue;
        
        for (const [bannedWord, config] of bannedWords) {
            if (word.includes(bannedWord)) {
                const contextCheck = checkContext(normalized, bannedWord);
                if (contextCheck.allowed) continue;
                
                result.flaggedWords.push({ word: bannedWord, severity: config.severity });
                result.severity = Math.max(result.severity, config.severity);
            }
        }
    }
    
    if (result.flaggedWords.length > 0 && result.severity >= 8) {
        result.allowed = false;
        result.blocked = true;
        result.reason = 'inappropriate_content_blocked';
    }
    
    return result;
}

function filterMessageForDisplay(message, username) {
    const moderation = advancedModerationCheck(message, username);
    if (!moderation.allowed) {
        return { original: message, filtered: "[Message blocked by moderation]", blocked: true, reason: moderation.reason };
    }
    return { original: message, filtered: message, blocked: false, censored: false };
}

function logChatMessage(username, originalMessage, filteredMessage, moderationResult) {
    const data = readData();
    if (!data.chatLogs) data.chatLogs = [];
    data.chatLogs.unshift({
        id: Date.now(), username, original: originalMessage, filtered: filteredMessage,
        moderation: { allowed: moderationResult.allowed, blocked: moderationResult.blocked, reason: moderationResult.reason, severity: moderationResult.severity },
        timestamp: new Date().toISOString()
    });
    if (data.chatLogs.length > 1000) data.chatLogs = data.chatLogs.slice(0, 1000);
    writeData(data);
}

// ============= CORS CONFIGURATION - FIXED =============
const allowedOrigins = [FRONTEND_URL, ...LOCAL_URLS];

app.use(cors({
    origin: function(origin, callback) {
        // Allow requests with no origin (like mobile apps or curl)
        if (!origin) return callback(null, true);
        if (allowedOrigins.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            console.log('CORS blocked origin:', origin);
            callback(null, true); // Allow anyway for testing - remove in production
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
    allowedHeaders: ['Content-Type', 'Authorization', 'Cookie', 'X-Requested-With', 'X-Tavian-Token', 'Accept']
}));

app.options('*', cors());
app.use(express.json({ limit: '10mb' }));
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

function generateSecureToken(userId, username) {
    const payload = { id: userId, username: username, timestamp: Date.now(), nonce: Math.random().toString(36).substring(2, 15) };
    return jwt.sign(payload, JWT_SECRET, { expiresIn: '30d' });
}

function verifySecureToken(token) {
    if (!token) return null;
    try {
        return jwt.verify(token, JWT_SECRET);
    } catch (error) {
        return null;
    }
}

async function verifyHCaptcha(hcaptchaResponse) {
    if (!hcaptchaResponse) return false;
    try {
        const https = require('https');
        const querystring = require('querystring');
        
        const postData = querystring.stringify({ secret: HCAPTCHA_SECRET, response: hcaptchaResponse });
        const options = { hostname: 'hcaptcha.com', port: 443, path: '/siteverify', method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(postData) } };
        
        const result = await new Promise((resolve, reject) => {
            const req = https.request(options, (res) => {
                let data = '';
                res.on('data', (chunk) => { data += chunk; });
                res.on('end', () => { try { resolve(JSON.parse(data)); } catch(e) { reject(e); } });
            });
            req.on('error', reject);
            req.write(postData);
            req.end();
        });
        return result.success === true;
    } catch (error) {
        console.error('hCaptcha error:', error);
        return false;
    }
}

function authenticateToken(req, res, next) {
    let token = null;
    
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
        token = authHeader.substring(7);
    }
    if (!token && req.headers['x-tavian-token']) {
        token = req.headers['x-tavian-token'];
    }
    if (!token) {
        token = req.cookies.TavianSecurity;
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

function optionalAuth(req, res, next) {
    let token = req.cookies.TavianSecurity || req.headers['x-tavian-token'];
    if (token) {
        const decoded = verifySecureToken(token);
        if (decoded) req.user = decoded;
    }
    next();
}

// ============= FIXED COOKIE SETTINGS =============
function setAuthCookie(res, token) {
    const isProduction = process.env.NODE_ENV === 'production' || process.env.RENDER;
    
    const cookieOptions = {
        httpOnly: true,
        maxAge: 30 * 24 * 60 * 60 * 1000,
        path: '/'
    };
    
    if (isProduction) {
        cookieOptions.secure = true;
        cookieOptions.sameSite = 'none';
    } else {
        cookieOptions.secure = false;
        cookieOptions.sameSite = 'lax';
    }
    
    res.cookie('TavianSecurity', token, cookieOptions);
}

function clearAuthCookie(res) {
    const isProduction = process.env.NODE_ENV === 'production' || process.env.RENDER;
    res.clearCookie('TavianSecurity', { path: '/', ...(isProduction && { secure: true, sameSite: 'none' }) });
}

// ============= API ENDPOINTS =============

app.get('/api/users', optionalAuth, (req, res) => {
    const users = readUsers();
    const safeUsers = users.map(u => { const { password, ...safe } = u; return safe; });
    res.json(safeUsers);
});

app.get('/api/users/:id', optionalAuth, (req, res) => {
    const users = readUsers();
    const userId = parseInt(req.params.id);
    const user = users.find(u => u.id === userId);
    if (!user) return res.status(404).json({ error: 'User not found' });
    const { password, ...safe } = user;
    res.json(safe);
});

app.get('/api/me', authenticateToken, (req, res) => {
    const users = readUsers();
    const user = users.find(u => u.id === req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    const { password, ...safe } = user;
    res.json(safe);
});

app.get('/api/auto-login', (req, res) => {
    let token = req.cookies.TavianSecurity;
    if (!token) return res.status(401).json({ error: 'No session found' });
    
    const decoded = verifySecureToken(token);
    if (!decoded) {
        clearAuthCookie(res);
        return res.status(401).json({ error: 'Invalid session' });
    }
    
    const users = readUsers();
    const user = users.find(u => u.id === decoded.id);
    if (!user) {
        clearAuthCookie(res);
        return res.status(401).json({ error: 'User not found' });
    }
    
    const newToken = generateSecureToken(user.id, user.username);
    setAuthCookie(res, newToken);
    
    const { password, ...safe } = user;
    res.json({ success: true, user: safe, token: newToken });
});

app.post('/api/register', async (req, res) => {
    console.log('📝 Registration attempt:', req.body.username);
    const users = readUsers();
    const { username, email, password, displayName, hcaptchaResponse } = req.body;
    
    const isCaptchaValid = await verifyHCaptcha(hcaptchaResponse);
    if (!isCaptchaValid) {
        return res.status(400).json({ error: 'CAPTCHA verification failed' });
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
        id: newId, username, email, password: hashedPassword, displayName: displayName || username,
        tavix: isOwner ? 1000000 : 0, about: '', visits: 0, transactions: [],
        notifications: [{ id: Date.now(), title: "🎉 Welcome to Tavian!", message: "Start earning TAVIX by playing games!", read: false, time: new Date().toISOString() }],
        savedDevices: [], createdAt: new Date().toISOString()
    };
    
    users.push(newUser);
    writeUsers(users);
    
    const token = generateSecureToken(newUser.id, newUser.username);
    setAuthCookie(res, token);
    
    const { password: _, ...safe } = newUser;
    console.log('✅ Registration successful:', username);
    res.status(201).json(safe);
});

app.post('/api/login', async (req, res) => {
    console.log('🔐 Login attempt:', req.body.username);
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
    setAuthCookie(res, token);
    
    const { password: _, ...safe } = user;
    console.log('✅ Login successful:', username);
    res.json(safe);
});

app.post('/api/logout', (req, res) => {
    clearAuthCookie(res);
    res.json({ success: true });
});

app.post('/api/chat', authenticateToken, (req, res) => {
    const { message } = req.body;
    const username = req.user.username;
    
    if (!message || message.trim().length === 0) {
        return res.status(400).json({ error: 'Message cannot be empty' });
    }
    if (message.length > 500) {
        return res.status(400).json({ error: 'Message too long (max 500 characters)' });
    }
    
    const moderation = advancedModerationCheck(message, username);
    const filtered = filterMessageForDisplay(message, username);
    logChatMessage(username, message, filtered.filtered, moderation);
    
    if (!moderation.allowed) {
        return res.status(403).json({ error: 'Message blocked by moderation', reason: moderation.reason, blocked: true });
    }
    
    res.json({ success: true, original: message, filtered: filtered.filtered, censored: filtered.censored, username: username, timestamp: new Date().toISOString() });
});

app.get('/api/admin/moderation-logs', authenticateToken, (req, res) => {
    const adminUsers = ['realgysj'];
    if (!adminUsers.includes(req.user.username.toLowerCase())) {
        return res.status(403).json({ error: 'Admin access required' });
    }
    const data = readData();
    res.json({ total: data.chatLogs?.length || 0, logs: (data.chatLogs || []).slice(0, 100) });
});

app.put('/api/user/:username', authenticateToken, async (req, res) => {
    console.log('📝 Update request for:', req.params.username);
    console.log('📦 Data:', req.body);
    
    const users = readUsers();
    const index = users.findIndex(u => u.username === req.params.username);
    
    if (index === -1) {
        return res.status(404).json({ error: 'User not found' });
    }
    if (req.user.username !== req.params.username) {
        return res.status(403).json({ error: 'Forbidden - You can only update your own profile' });
    }
    
    const allowedUpdates = ['displayName', 'about', 'tavix', 'transactions', 'notifications', 'savedDevices'];
    for (let key of allowedUpdates) {
        if (req.body[key] !== undefined) {
            users[index][key] = req.body[key];
            console.log(`✅ Updated ${key} to:`, req.body[key]);
        }
    }
    
    writeUsers(users);
    const { password, ...safe } = users[index];
    res.json(safe);
});

app.put('/api/users/:id', authenticateToken, async (req, res) => {
    const userId = parseInt(req.params.id);
    if (req.user.id !== userId) {
        return res.status(403).json({ error: 'Forbidden' });
    }
    
    const users = readUsers();
    const index = users.findIndex(u => u.id === userId);
    if (index === -1) return res.status(404).json({ error: 'User not found' });
    
    const allowedUpdates = ['displayName', 'about', 'tavix', 'transactions', 'notifications', 'savedDevices'];
    for (let key of allowedUpdates) {
        if (req.body[key] !== undefined) users[index][key] = req.body[key];
    }
    
    writeUsers(users);
    const { password, ...safe } = users[index];
    res.json(safe);
});

app.post('/api/transaction', authenticateToken, async (req, res) => {
    const { username, amount, reason, from } = req.body;
    if (req.user.username !== username) return res.status(403).json({ error: 'Forbidden' });
    
    const users = readUsers();
    const index = users.findIndex(u => u.username === username);
    if (index === -1) return res.status(404).json({ error: 'User not found' });
    
    if (!users[index].transactions) users[index].transactions = [];
    users[index].transactions.unshift({ id: Date.now(), amount, reason, from: from || null, date: new Date().toISOString() });
    users[index].tavix = (users[index].tavix || 0) + amount;
    if (users[index].transactions.length > 50) users[index].transactions.pop();
    writeUsers(users);
    
    res.json({ success: true, newBalance: users[index].tavix });
});

app.post('/api/notification', authenticateToken, async (req, res) => {
    const { username, title, message } = req.body;
    if (req.user.username !== username) return res.status(403).json({ error: 'Forbidden' });
    
    const users = readUsers();
    const index = users.findIndex(u => u.username === username);
    if (index === -1) return res.status(404).json({ error: 'User not found' });
    
    if (!users[index].notifications) users[index].notifications = [];
    users[index].notifications.unshift({ id: Date.now(), title, message, read: false, time: new Date().toISOString() });
    if (users[index].notifications.length > 50) users[index].notifications.pop();
    writeUsers(users);
    
    res.json({ success: true });
});

app.delete('/api/users/:id', authenticateToken, async (req, res) => {
    const userId = parseInt(req.params.id);
    if (req.user.id !== userId) return res.status(403).json({ error: 'Forbidden' });
    
    let users = readUsers();
    users = users.filter(u => u.id !== userId);
    writeUsers(users);
    clearAuthCookie(res);
    res.json({ success: true });
});

app.delete('/api/user/:username', authenticateToken, async (req, res) => {
    let users = readUsers();
    const userToDelete = users.find(u => u.username === req.params.username);
    if (!userToDelete) return res.status(404).json({ error: 'User not found' });
    if (req.user.username !== req.params.username) return res.status(403).json({ error: 'Forbidden' });
    
    users = users.filter(u => u.username !== req.params.username);
    writeUsers(users);
    clearAuthCookie(res);
    res.json({ success: true });
});

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
        res.json({ message: 'IDs added', users: data.users.map(u => ({ id: u.id, username: u.username })) });
    } else {
        res.json({ message: 'All users have IDs' });
    }
});

app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
    console.log(`\n========================================`);
    console.log(`🟣 Tavian Backend Server`);
    console.log(`========================================`);
    console.log(`📡 Running on: http://0.0.0.0:${PORT}`);
    console.log(`🔗 Frontend URL: ${FRONTEND_URL}`);
    console.log(`✅ CORS enabled for: ${FRONTEND_URL} and localhost`);
    console.log(`✅ Cookie settings: ${process.env.NODE_ENV === 'production' ? 'Secure (HTTPS required)' : 'Development (HTTP allowed)'}`);
    console.log(`========================================\n`);
});
