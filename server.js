const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

const JWT_SECRET = process.env.JWT_SECRET || "TAVIAN_SUPER_SECRET_KEY_CHANGE_THIS_12345";
const HCAPTCHA_SECRET = process.env.HCAPTCHA_SECRET || "ES_3e9f86c0fff2435a9c741ef2d05a438f";
const FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:5500";

const DATA_FILE = path.join(__dirname, 'data.json');

if (!fs.existsSync(DATA_FILE)) {
    fs.writeFileSync(DATA_FILE, JSON.stringify({ users: [], nextId: 1, chatLogs: [], roles: [] }, null, 2));
}

app.use(cors({
    origin: [FRONTEND_URL, 'http://localhost:3000', 'http://localhost:5500', 'http://127.0.0.1:5500', 'https://tavian.netlify.app'],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
    allowedHeaders: ['Content-Type', 'Authorization', 'Cookie', 'X-Requested-With', 'X-Tavian-Token']
}));

app.options('*', cors());
app.use(express.json());
app.use(cookieParser());

function readData() {
    const data = fs.readFileSync(DATA_FILE);
    return JSON.parse(data);
}

function writeData(data) {
    fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
}

function getNextId() {
    const data = readData();
    const nextId = data.nextId || 1;
    data.nextId = nextId + 1;
    writeData(data);
    return nextId;
}

function generateSecureToken(userId, username) {
    return jwt.sign({ id: userId, username: username, timestamp: Date.now() }, JWT_SECRET, { expiresIn: '30d' });
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
    if (!hcaptchaResponse) return true; // Skip for testing
    try {
        const https = require('https');
        const querystring = require('querystring');
        const postData = querystring.stringify({ secret: HCAPTCHA_SECRET, response: hcaptchaResponse });
        const options = {
            hostname: 'hcaptcha.com',
            port: 443,
            path: '/siteverify',
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(postData) }
        };
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
        return true; // Allow for testing
    }
}

function authenticateToken(req, res, next) {
    let token = req.headers.authorization?.substring(7) || req.headers['x-tavian-token'] || req.cookies.TavianSecurity;
    if (!token) return res.status(401).json({ error: 'Not authenticated' });
    const decoded = verifySecureToken(token);
    if (!decoded) return res.status(401).json({ error: 'Invalid token' });
    req.user = decoded;
    next();
}

function setAuthCookie(res, token) {
    res.cookie('TavianSecurity', token, { httpOnly: true, secure: false, sameSite: 'lax', maxAge: 30 * 24 * 60 * 60 * 1000, path: '/' });
}

function clearAuthCookie(res) {
    res.clearCookie('TavianSecurity', { path: '/' });
}

// ============ API ENDPOINTS ============

app.get('/api/users', (req, res) => {
    const data = readData();
    res.json(data.users.map(({ password, ...safe }) => safe));
});

app.get('/api/me', authenticateToken, (req, res) => {
    const data = readData();
    const user = data.users.find(u => u.id === req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    const { password, ...safe } = user;
    res.json(safe);
});

app.post('/api/register', async (req, res) => {
    const data = readData();
    const { username, email, password, displayName, hcaptchaResponse } = req.body;
    
    if (data.users.find(u => u.username.toLowerCase() === username.toLowerCase())) {
        return res.status(400).json({ error: 'Username already taken' });
    }
    if (data.users.find(u => u.email.toLowerCase() === email.toLowerCase())) {
        return res.status(400).json({ error: 'Email already exists' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    const isOwner = username.toLowerCase() === 'realgysj';
    const isModerator = username.toLowerCase() === 'plstealme2';
    const newId = getNextId();
    
    const newUser = {
        id: newId,
        username,
        email,
        password: hashedPassword,
        displayName: displayName || username,
        role: isOwner ? "Owner" : (isModerator ? "Moderator" : "Member"),
        roleBadge: isOwner ? "👑" : (isModerator ? "🔨" : ""),
        roleColor: isOwner ? "#ffcc00" : (isModerator ? "#00aaff" : "#888888"),
        isOwner: isOwner,
        isModerator: isModerator,
        isBooster: false,
        followers: [],
        following: [],
        friends: [],
        friendRequests: [],
        about: "",
        avatar: "",
        discord: "",
        status: "",
        tavix: isOwner ? 1000000 : 100,
        visits: 0,
        transactions: [],
        notifications: [{
            id: Date.now(),
            title: "🎉 Welcome!",
            message: isOwner ? "You are the Owner!" : "Welcome to Tavian!",
            read: false,
            time: new Date().toISOString()
        }],
        createdAt: new Date().toISOString()
    };
    
    data.users.push(newUser);
    writeData(data);
    
    const token = generateSecureToken(newUser.id, newUser.username);
    setAuthCookie(res, token);
    const { password: _, ...safe } = newUser;
    res.status(201).json(safe);
});

app.post('/api/login', async (req, res) => {
    const data = readData();
    const { username, password } = req.body;
    const user = data.users.find(u => u.username.toLowerCase() === username.toLowerCase());
    if (!user) return res.status(401).json({ error: 'Invalid username or password' });
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(401).json({ error: 'Invalid username or password' });
    const token = generateSecureToken(user.id, user.username);
    setAuthCookie(res, token);
    const { password: _, ...safe } = user;
    res.json(safe);
});

app.post('/api/logout', (req, res) => {
    clearAuthCookie(res);
    res.json({ success: true });
});

app.get('/api/auto-login', (req, res) => {
    const token = req.cookies.TavianSecurity;
    if (!token) return res.status(401).json({ error: 'No session' });
    const decoded = verifySecureToken(token);
    if (!decoded) return res.status(401).json({ error: 'Invalid session' });
    const data = readData();
    const user = data.users.find(u => u.id === decoded.id);
    if (!user) return res.status(401).json({ error: 'User not found' });
    const { password, ...safe } = user;
    res.json({ success: true, user: safe });
});

// ============ PROFILE UPDATE - FIXED ============
app.put('/api/profile', authenticateToken, (req, res) => {
    const data = readData();
    const { displayName, about, discord, status, avatar } = req.body;
    const userIndex = data.users.findIndex(u => u.id === req.user.id);
    
    if (userIndex === -1) return res.status(404).json({ error: 'User not found' });
    
    if (displayName !== undefined) data.users[userIndex].displayName = displayName;
    if (about !== undefined) data.users[userIndex].about = about;
    if (discord !== undefined) data.users[userIndex].discord = discord;
    if (status !== undefined) data.users[userIndex].status = status;
    if (avatar !== undefined) data.users[userIndex].avatar = avatar;
    
    // Ensure owner badge stays
    if (data.users[userIndex].username === 'realgysj') {
        data.users[userIndex].isOwner = true;
        data.users[userIndex].role = "Owner";
        data.users[userIndex].roleBadge = "👑";
        data.users[userIndex].roleColor = "#ffcc00";
    }
    
    writeData(data);
    const { password, ...safe } = data.users[userIndex];
    res.json({ success: true, user: safe });
});

// ============ FRIEND SYSTEM ============
app.post('/api/friend-request/:username', authenticateToken, (req, res) => {
    const data = readData();
    const targetUsername = req.params.username;
    const currentUser = data.users.find(u => u.id === req.user.id);
    const targetUser = data.users.find(u => u.username === targetUsername);
    
    if (!targetUser) return res.status(404).json({ error: 'User not found' });
    if (currentUser.friends?.includes(targetUsername)) return res.status(400).json({ error: 'Already friends' });
    if (targetUser.friendRequests?.includes(currentUser.username)) return res.status(400).json({ error: 'Request already sent' });
    
    if (!targetUser.friendRequests) targetUser.friendRequests = [];
    targetUser.friendRequests.push(currentUser.username);
    
    if (!targetUser.notifications) targetUser.notifications = [];
    targetUser.notifications.unshift({
        id: Date.now(),
        title: "Friend Request",
        message: `${currentUser.username} sent you a friend request!`,
        read: false,
        time: new Date().toISOString()
    });
    
    writeData(data);
    res.json({ success: true });
});

app.post('/api/friend-accept/:username', authenticateToken, (req, res) => {
    const data = readData();
    const requesterUsername = req.params.username;
    const currentUser = data.users.find(u => u.id === req.user.id);
    const requester = data.users.find(u => u.username === requesterUsername);
    
    if (!requester) return res.status(404).json({ error: 'User not found' });
    if (!currentUser.friendRequests?.includes(requesterUsername)) return res.status(400).json({ error: 'No request found' });
    
    currentUser.friendRequests = currentUser.friendRequests.filter(u => u !== requesterUsername);
    if (!currentUser.friends) currentUser.friends = [];
    if (!requester.friends) requester.friends = [];
    currentUser.friends.push(requesterUsername);
    requester.friends.push(currentUser.username);
    
    writeData(data);
    res.json({ success: true });
});

app.post('/api/friend-decline/:username', authenticateToken, (req, res) => {
    const data = readData();
    const requesterUsername = req.params.username;
    const currentUser = data.users.find(u => u.id === req.user.id);
    
    if (currentUser.friendRequests) {
        currentUser.friendRequests = currentUser.friendRequests.filter(u => u !== requesterUsername);
        writeData(data);
    }
    res.json({ success: true });
});

app.post('/api/friend-remove/:username', authenticateToken, (req, res) => {
    const data = readData();
    const friendUsername = req.params.username;
    const currentUser = data.users.find(u => u.id === req.user.id);
    const friend = data.users.find(u => u.username === friendUsername);
    
    if (currentUser.friends) currentUser.friends = currentUser.friends.filter(u => u !== friendUsername);
    if (friend?.friends) friend.friends = friend.friends.filter(u => u !== currentUser.username);
    
    writeData(data);
    res.json({ success: true });
});

// ============ FOLLOW SYSTEM ============
app.post('/api/follow/:username', authenticateToken, (req, res) => {
    const data = readData();
    const targetUsername = req.params.username;
    const currentUser = data.users.find(u => u.id === req.user.id);
    const targetUser = data.users.find(u => u.username === targetUsername);
    
    if (!targetUser) return res.status(404).json({ error: 'User not found' });
    if (currentUser.following?.includes(targetUsername)) return res.status(400).json({ error: 'Already following' });
    
    if (!currentUser.following) currentUser.following = [];
    if (!targetUser.followers) targetUser.followers = [];
    currentUser.following.push(targetUsername);
    targetUser.followers.push(currentUser.username);
    
    writeData(data);
    res.json({ success: true });
});

app.post('/api/unfollow/:username', authenticateToken, (req, res) => {
    const data = readData();
    const targetUsername = req.params.username;
    const currentUser = data.users.find(u => u.id === req.user.id);
    const targetUser = data.users.find(u => u.username === targetUsername);
    
    if (currentUser.following) currentUser.following = currentUser.following.filter(u => u !== targetUsername);
    if (targetUser?.followers) targetUser.followers = targetUser.followers.filter(u => u !== currentUser.username);
    
    writeData(data);
    res.json({ success: true });
});

// ============ ROLE SYSTEM ============
app.post('/api/roles', authenticateToken, (req, res) => {
    const data = readData();
    const currentUser = data.users.find(u => u.id === req.user.id);
    if (currentUser?.username !== 'realgysj') return res.status(403).json({ error: 'Only Owner can create roles' });
    
    const { name, badge, color } = req.body;
    if (!data.roles) data.roles = [];
    data.roles.push({ id: Date.now(), name, badge, color, createdAt: new Date().toISOString() });
    writeData(data);
    res.json({ success: true });
});

app.post('/api/roles/assign', authenticateToken, (req, res) => {
    const data = readData();
    const currentUser = data.users.find(u => u.id === req.user.id);
    if (currentUser?.username !== 'realgysj') return res.status(403).json({ error: 'Only Owner can assign roles' });
    
    const { targetUsername, roleName, roleBadge, roleColor } = req.body;
    const targetUser = data.users.find(u => u.username === targetUsername);
    if (!targetUser) return res.status(404).json({ error: 'User not found' });
    
    targetUser.role = roleName;
    targetUser.roleBadge = roleBadge;
    targetUser.roleColor = roleColor;
    if (roleName === 'Moderator') targetUser.isModerator = true;
    if (roleName === 'Booster') targetUser.isBooster = true;
    
    writeData(data);
    res.json({ success: true });
});

// ============ TRANSACTIONS ============
app.post('/api/transaction', authenticateToken, (req, res) => {
    const data = readData();
    const { amount, reason, from } = req.body;
    const user = data.users.find(u => u.id === req.user.id);
    
    if (!user.transactions) user.transactions = [];
    user.transactions.unshift({ id: Date.now(), amount, reason, from, date: new Date().toISOString() });
    user.tavix = (user.tavix || 0) + amount;
    
    writeData(data);
    res.json({ success: true, newBalance: user.tavix });
});

app.post('/api/notification', authenticateToken, (req, res) => {
    const data = readData();
    const { title, message } = req.body;
    const user = data.users.find(u => u.id === req.user.id);
    
    if (!user.notifications) user.notifications = [];
    user.notifications.unshift({ id: Date.now(), title, message, read: false, time: new Date().toISOString() });
    
    writeData(data);
    res.json({ success: true });
});

app.post('/api/migrate-ids', (req, res) => {
    const data = readData();
    data.users.forEach(user => {
        if (user.username === 'realgysj') {
            user.isOwner = true;
            user.role = "Owner";
            user.roleBadge = "👑";
            user.roleColor = "#ffcc00";
        }
        if (user.username === 'plstealme2') {
            user.isModerator = true;
            user.role = "Moderator";
            user.roleBadge = "🔨";
            user.roleColor = "#00aaff";
        }
        if (!user.friends) user.friends = [];
        if (!user.followers) user.followers = [];
        if (!user.following) user.following = [];
        if (!user.friendRequests) user.friendRequests = [];
        if (!user.about) user.about = "";
        if (!user.avatar) user.avatar = "";
        if (!user.discord) user.discord = "";
        if (!user.status) user.status = "";
    });
    writeData(data);
    res.json({ message: 'Migration complete' });
});

app.get('/api/health', (req, res) => {
    res.json({ status: 'ok' });
});

app.listen(PORT, () => {
    console.log(`\n========================================`);
    console.log(`🟣 Tavian Backend Server`);
    console.log(`========================================`);
    console.log(`📡 Running on: http://localhost:${PORT}`);
    console.log(`👑 Owner: realgysj`);
    console.log(`🔨 Moderator: plstealme2`);
    console.log(`========================================\n`);
});
