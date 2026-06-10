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

// Frontend URL (Netlify)
const FRONTEND_URL = process.env.FRONTEND_URL || "https://tavian.netlify.app";

// Data file path
const DATA_FILE = path.join(__dirname, 'data.json');

// Initialize data file
if (!fs.existsSync(DATA_FILE)) {
    fs.writeFileSync(DATA_FILE, JSON.stringify({ users: [], nextId: 1, chatLogs: [], redeemCodes: [] }, null, 2));
}

// ============= REDEEM CODE SYSTEM =============
function generateRedeemCode(amount, createdBy, expiresInDays = 30) {
    const code = Math.random().toString(36).substring(2, 10).toUpperCase();
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + expiresInDays);
    
    const codeData = {
        code,
        amount,
        createdBy,
        usedBy: [],
        createdAt: new Date().toISOString(),
        expiresAt: expiresAt.toISOString(),
        maxUses: 1
    };
    
    const data = readData();
    if (!data.redeemCodes) data.redeemCodes = [];
    data.redeemCodes.push(codeData);
    writeData(data);
    
    return code;
}

async function useRedeemCode(code, username) {
    const data = readData();
    const codes = data.redeemCodes || [];
    const codeData = codes.find(c => c.code === code);
    
    if (!codeData) return { success: false, error: "Invalid code" };
    if (new Date(codeData.expiresAt) < new Date()) return { success: false, error: "Code expired" };
    if (codeData.usedBy.length >= codeData.maxUses) return { success: false, error: "Code already used" };
    if (codeData.usedBy.includes(username)) return { success: false, error: "You already used this code" };
    
    codeData.usedBy.push(username);
    const index = codes.findIndex(c => c.code === code);
    if (index !== -1) {
        data.redeemCodes[index] = codeData;
        writeData(data);
    }
    
    return { success: true, amount: codeData.amount };
}

// ============= ADVANCED MODERATION SYSTEM =============

// Comprehensive banned words with context awareness
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
]);

// Comprehensive allowlist
const allowlist = new Set([
    'assassin', 'assassinate', 'assassination', 'assault', 'assemble', 'assembly', 
    'assist', 'assistant', 'associate', 'association', 'assume', 'assumption', 
    'assure', 'assurance', 'asset', 'assets', 'assign', 'assignment', 'assistive',
    'cocktail', 'cockatoo', 'cockpit', 'cocksure', 'cocky', 'cockney', 'cockerel',
    'cockroach', 'cockscomb', 'cockleshell', 'cockfight', 'cockspur',
    'ship', 'shipping', 'shipment', 'shirt', 'shift', 'shifting', 'shifty',
    'bitcoin', 'bicycle', 'biscuit', 'bistro', 'bilingual', 'binary', 'binding',
    'damage', 'damaging', 'damascus', 'damask', 'damnation', 'damocles',
    'night', 'nightmare', 'nightly', 'nightfall', 'nightclub', 'nightingale',
    'nigeria', 'nigerian', 'niger', 'nigerien', 'nighthawk', 'nightshade',
    'grape', 'drapery', 'scrape', 'scraper', 'scraping', 'scrapped', 'crape',
    'skill', 'skilling', 'killingly', 'killdeer', 'killjoy', 'killifish',
    'sussex', 'essex', 'wessex', 'middlesex', 'sexes', 'sexism', 'sexist',
]);

const safePhrases = new Set([
    'i love this game', 'good game', 'nice shot', 'well played',
    'how are you', 'im fine', 'thank you', 'thanks', 'please',
    'sorry', 'my bad', 'good luck', 'have fun', 'enjoying',
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
    normalized = normalized.replace(/(.)\1{2,}/g, '$1$1');
    return normalized;
}

function isAllowlisted(word) {
    const normalized = word.toLowerCase();
    if (allowlist.has(normalized)) return true;
    for (const allowed of allowlist) {
        if (normalized.includes(allowed) && allowed.length > 3) {
            const remaining = normalized.replace(allowed, '');
            if (remaining.length === 0 || /^[aeiou\s]+$/i.test(remaining)) return true;
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
    const positiveIndicators = ['not', 'no', 'never', 'isn\'t', 'aren\'t', 'wasn\'t', 'weren\'t'];
    for (const indicator of positiveIndicators) {
        const pattern = new RegExp(`\\b${indicator}\\s+${badWord}\\b`, 'i');
        if (pattern.test(lowerMsg)) return { allowed: true, reason: 'negation_context' };
    }
    if (lowerMsg.includes('"') || lowerMsg.includes('\'')) {
        const quotedPattern = new RegExp(`["'][^"']*${badWord}[^"']*["']`, 'i');
        if (quotedPattern.test(lowerMsg)) return { allowed: true, reason: 'quoted_context' };
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
            result.allowed = false; result.blocked = true; result.reason = pattern.type; result.severity = pattern.severity;
            return result;
        }
    }
    
    const words = normalized.split(/\s+/);
    for (const word of words) {
        if (word.length < 3) continue;
        if (isAllowlisted(word)) continue;
        for (const [bannedWord, config] of bannedWords) {
            if (word.includes(bannedWord) || bannedWord.includes(word)) {
                const contextCheck = checkContext(normalized, bannedWord);
                if (contextCheck.allowed) continue;
                result.flaggedWords.push({ word: bannedWord, severity: config.severity, match: word });
                result.severity = Math.max(result.severity, config.severity);
            }
        }
    }
    
    if (result.flaggedWords.length > 0) {
        if (result.severity >= 8) {
            result.allowed = false; result.blocked = true; result.reason = 'inappropriate_content_blocked';
        } else if (result.severity >= 5) {
            result.allowed = true; result.blocked = false; result.reason = 'mild_profanity_allowed';
        }
    }
    return result;
}

function filterMessageForDisplay(message, username) {
    const moderation = advancedModerationCheck(message, username);
    if (!moderation.allowed) {
        return { original: message, filtered: "[Message blocked by moderation]", blocked: true, reason: moderation.reason };
    }
    let filtered = message;
    if (moderation.severity >= 5 && moderation.severity < 8) {
        for (const flagged of moderation.flaggedWords) {
            const regex = new RegExp(`\\b${flagged.word}\\b`, 'gi');
            filtered = filtered.replace(regex, '*'.repeat(flagged.word.length));
        }
    }
    return { original: message, filtered: filtered, blocked: false, censored: filtered !== message };
}

function logChatMessage(username, originalMessage, filteredMessage, moderationResult) {
    const data = readData();
    if (!data.chatLogs) data.chatLogs = [];
    data.chatLogs.unshift({
        id: Date.now(), username, original: originalMessage, filtered: filteredMessage,
        moderation: { allowed: moderationResult.allowed, blocked: moderationResult.blocked, reason: moderationResult.reason, severity: moderationResult.severity, flaggedWords: moderationResult.flaggedWords },
        timestamp: new Date().toISOString()
    });
    if (data.chatLogs.length > 1000) data.chatLogs = data.chatLogs.slice(0, 1000);
    writeData(data);
}

// ============= CORS CONFIGURATION =============
app.use(cors({
    origin: [FRONTEND_URL, 'http://localhost:3000', 'http://localhost:5500', 'http://127.0.0.1:5500'],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
    allowedHeaders: ['Content-Type', 'Authorization', 'Cookie', 'X-Requested-With', 'X-Tavian-Token']
}));

app.options('*', cors());
app.use(express.json());
app.use(cookieParser());

// Helper functions
function readData() { const data = fs.readFileSync(DATA_FILE); return JSON.parse(data); }
function writeData(data) { fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2)); }
function readUsers() { return readData().users; }
function writeUsers(users) { const data = readData(); data.users = users; writeData(data); }
function getNextId() { const data = readData(); const nextId = data.nextId || 1; data.nextId = nextId + 1; writeData(data); return nextId; }
function generateSecureToken(userId, username) { return jwt.sign({ id: userId, username, timestamp: Date.now(), nonce: Math.random().toString(36).substring(2, 15) }, JWT_SECRET, { expiresIn: '30d' }); }
function verifySecureToken(token) { if (!token) return null; try { return jwt.verify(token, JWT_SECRET); } catch (error) { return null; } }

async function verifyHCaptcha(hcaptchaResponse) {
    if (!hcaptchaResponse) return false;
    try {
        const https = require('https');
        const querystring = require('querystring');
        const postData = querystring.stringify({ secret: HCAPTCHA_SECRET, response: hcaptchaResponse });
        const result = await new Promise((resolve, reject) => {
            const req = https.request({ hostname: 'hcaptcha.com', port: 443, path: '/siteverify', method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(postData) } }, (res) => {
                let data = '';
                res.on('data', (chunk) => { data += chunk; });
                res.on('end', () => { try { resolve(JSON.parse(data)); } catch(e) { reject(e); } });
            });
            req.on('error', reject);
            req.write(postData);
            req.end();
        });
        return result.success === true;
    } catch (error) { console.error('hCaptcha verification error:', error); return false; }
}

function authenticateToken(req, res, next) {
    let token = req.headers.authorization?.startsWith('Bearer ') ? req.headers.authorization.substring(7) : req.headers['x-tavian-token'] || req.cookies.TavianSecurity;
    if (!token) return res.status(401).json({ error: 'Not authenticated' });
    const decoded = verifySecureToken(token);
    if (!decoded) return res.status(401).json({ error: 'Invalid token' });
    req.user = decoded;
    next();
}

function optionalAuth(req, res, next) {
    let token = req.headers.authorization?.startsWith('Bearer ') ? req.headers.authorization.substring(7) : req.headers['x-tavian-token'] || req.cookies.TavianSecurity;
    if (token) { const decoded = verifySecureToken(token); if (decoded) req.user = decoded; }
    next();
}

function setAuthCookie(res, token) { res.cookie('TavianSecurity', token, { httpOnly: true, secure: true, sameSite: 'none', maxAge: 30 * 24 * 60 * 60 * 1000, path: '/' }); }
function clearAuthCookie(res) { res.clearCookie('TavianSecurity', { path: '/', secure: true, sameSite: 'none' }); }

// ============= API ENDPOINTS =============

app.get('/api/users', optionalAuth, (req, res) => {
    const users = readUsers();
    res.json(users.map(u => { const { password, ...safe } = u; return safe; }));
});

app.get('/api/users/:id', optionalAuth, (req, res) => {
    const user = readUsers().find(u => u.id === parseInt(req.params.id));
    if (!user) return res.status(404).json({ error: 'User not found' });
    const { password, ...safe } = user;
    res.json(safe);
});

app.get('/api/me', authenticateToken, (req, res) => {
    const user = readUsers().find(u => u.id === req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    const { password, ...safe } = user;
    res.json(safe);
});

app.get('/api/auto-login', (req, res) => {
    let token = req.cookies.TavianSecurity;
    if (!token) return res.status(401).json({ error: 'No session found' });
    const decoded = verifySecureToken(token);
    if (!decoded) { clearAuthCookie(res); return res.status(401).json({ error: 'Invalid session' }); }
    const user = readUsers().find(u => u.id === decoded.id);
    if (!user) { clearAuthCookie(res); return res.status(401).json({ error: 'User not found' }); }
    const newToken = generateSecureToken(user.id, user.username);
    setAuthCookie(res, newToken);
    const { password, ...safe } = user;
    res.json({ success: true, user: safe, token: newToken });
});

app.post('/api/register', async (req, res) => {
    const users = readUsers();
    const { username, email, password, displayName, hcaptchaResponse } = req.body;
    if (!await verifyHCaptcha(hcaptchaResponse)) return res.status(400).json({ error: 'CAPTCHA verification failed. Please try again.' });
    if (users.find(u => u.username.toLowerCase() === username.toLowerCase())) return res.status(400).json({ error: 'Username already taken' });
    if (users.find(u => u.email.toLowerCase() === email.toLowerCase())) return res.status(400).json({ error: 'Email already exists' });
    const hashedPassword = await bcrypt.hash(password, 10);
    const isOwner = username.toLowerCase() === 'realgysj';
    const newUser = { id: getNextId(), username, email, password: hashedPassword, displayName: displayName || username, tavix: isOwner ? 1000000 : 0, about: '', visits: 0, transactions: [], notifications: [{ id: Date.now(), title: "🎉 Welcome to Tavian!", message: isOwner ? "You received 1,000,000 TAVIX as owner!" : "Start earning TAVIX by playing games!", read: false, time: new Date().toISOString() }], savedDevices: [], createdAt: new Date().toISOString() };
    users.push(newUser);
    writeUsers(users);
    const token = generateSecureToken(newUser.id, newUser.username);
    setAuthCookie(res, token);
    const { password: _, ...safe } = newUser;
    res.status(201).json(safe);
});

app.post('/api/login', async (req, res) => {
    const user = readUsers().find(u => u.username.toLowerCase() === req.body.username.toLowerCase());
    if (!user || !await bcrypt.compare(req.body.password, user.password)) return res.status(401).json({ error: 'Invalid username or password' });
    const token = generateSecureToken(user.id, user.username);
    setAuthCookie(res, token);
    const { password, ...safe } = user;
    res.json(safe);
});

app.post('/api/logout', (req, res) => { clearAuthCookie(res); res.json({ success: true }); });

// REDEEM CODE ENDPOINTS
app.post('/api/redeem', authenticateToken, async (req, res) => {
    const { code } = req.body;
    if (!code?.trim()) return res.status(400).json({ error: 'Please enter a code' });
    const result = await useRedeemCode(code.toUpperCase(), req.user.username);
    if (!result.success) return res.status(400).json({ error: result.error });
    const users = readUsers();
    const userIndex = users.findIndex(u => u.username === req.user.username);
    if (userIndex !== -1) {
        users[userIndex].tavix += result.amount;
        users[userIndex].transactions = users[userIndex].transactions || [];
        users[userIndex].transactions.unshift({ id: Date.now(), amount: result.amount, reason: `Redeemed code: ${code}`, from: null, date: new Date().toISOString() });
        users[userIndex].notifications = users[userIndex].notifications || [];
        users[userIndex].notifications.unshift({ id: Date.now(), title: "🎁 Code Redeemed!", message: `You received ${result.amount} TAVIX from code ${code}`, read: false, time: new Date().toISOString() });
        writeUsers(users);
    }
    res.json({ success: true, amount: result.amount, message: `Successfully redeemed ${result.amount} TAVIX!` });
});

app.post('/api/admin/create-code', authenticateToken, (req, res) => {
    if (!['realgysj'].includes(req.user.username.toLowerCase())) return res.status(403).json({ error: 'Admin access required' });
    const { amount, expiresInDays = 30 } = req.body;
    if (!amount || amount <= 0) return res.status(400).json({ error: 'Invalid amount' });
    const code = generateRedeemCode(amount, req.user.username, expiresInDays);
    res.json({ success: true, code, amount, expiresInDays });
});

app.get('/api/admin/redeem-codes', authenticateToken, (req, res) => {
    if (!['realgysj'].includes(req.user.username.toLowerCase())) return res.status(403).json({ error: 'Admin access required' });
    res.json({ codes: readData().redeemCodes || [] });
});

// CHAT ENDPOINT (with moderation)
app.post('/api/chat', authenticateToken, (req, res) => {
    const { message } = req.body;
    if (!message?.trim()) return res.status(400).json({ error: 'Message cannot be empty' });
    if (message.length > 500) return res.status(400).json({ error: 'Message too long (max 500 characters)' });
    const moderation = advancedModerationCheck(message, req.user.username);
    const filtered = filterMessageForDisplay(message, req.user.username);
    logChatMessage(req.user.username, message, filtered.filtered, moderation);
    if (!moderation.allowed) return res.status(403).json({ error: 'Message blocked by moderation', reason: moderation.reason, blocked: true });
    res.json({ success: true, original: message, filtered: filtered.filtered, censored: filtered.censored, username: req.user.username, timestamp: new Date().toISOString() });
});

app.get('/api/admin/moderation-logs', authenticateToken, (req, res) => {
    if (!['realgysj', 'admin'].includes(req.user.username.toLowerCase())) return res.status(403).json({ error: 'Admin access required' });
    const logs = readData().chatLogs || [];
    res.json({ total: logs.length, logs: logs.slice(0, 100) });
});

// USER UPDATE ENDPOINTS
app.put('/api/users/:id', authenticateToken, async (req, res) => {
    const userId = parseInt(req.params.id);
    if (req.user.id !== userId) return res.status(403).json({ error: 'Forbidden' });
    const users = readUsers();
    const index = users.findIndex(u => u.id === userId);
    if (index === -1) return res.status(404).json({ error: 'User not found' });
    const allowedUpdates = ['displayName', 'about', 'tavix', 'transactions', 'notifications', 'savedDevices'];
    for (let key of allowedUpdates) if (req.body[key] !== undefined) users[index][key] = req.body[key];
    writeUsers(users);
    const { password, ...safe } = users[index];
    res.json(safe);
});

app.put('/api/user/:username', authenticateToken, async (req, res) => {
    const users = readUsers();
    const index = users.findIndex(u => u.username === req.params.username);
    if (index === -1) return res.status(404).json({ error: 'User not found' });
    if (req.user.username !== req.params.username) return res.status(403).json({ error: 'Forbidden' });
    const allowedUpdates = ['displayName', 'about', 'tavix', 'transactions', 'notifications', 'savedDevices'];
    for (let key of allowedUpdates) if (req.body[key] !== undefined) users[index][key] = req.body[key];
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
    users[index].transactions = users[index].transactions || [];
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
    users[index].notifications = users[index].notifications || [];
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
    if (!users.find(u => u.username === req.params.username)) return res.status(404).json({ error: 'User not found' });
    if (req.user.username !== req.params.username) return res.status(403).json({ error: 'Forbidden' });
    users = users.filter(u => u.username !== req.params.username);
    writeUsers(users);
    clearAuthCookie(res);
    res.json({ success: true });
});

app.get('/api/health', (req, res) => { res.json({ status: 'ok', timestamp: new Date().toISOString() }); });

app.listen(PORT, () => {
    console.log(`\n========================================`);
    console.log(`🟣 Tavian Backend Server - COMPLETE EDITION`);
    console.log(`========================================`);
    console.log(`📡 Running on: http://localhost:${PORT}`);
    console.log(`🔗 Frontend URL: ${FRONTEND_URL}`);
    console.log(`✅ Redeem code system: ACTIVE`);
    console.log(`✅ Advanced moderation system: ACTIVE (${bannedWords.size} banned words)`);
    console.log(`✅ Chat filtering: ENABLED`);
    console.log(`✅ Admin endpoints: /api/admin/create-code`);
    console.log(`========================================\n`);
});
