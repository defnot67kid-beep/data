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
const JWT_SECRET = process.env.JWT_SECRET || "TAVIAN_SUPER_SECRET_KEY_CHANGE_THIS_12345";
const HCAPTCHA_SECRET = process.env.HCAPTCHA_SECRET || "ES_3e9f86c0fff2435a9c741ef2d05a438f";

// Frontend URL
const FRONTEND_URL = process.env.FRONTEND_URL || "https://tavian.netlify.app";

// Data file path
const DATA_FILE = path.join(__dirname, 'data.json');

// Initialize data file
if (!fs.existsSync(DATA_FILE)) {
    fs.writeFileSync(DATA_FILE, JSON.stringify({ users: [], nextId: 1, chatLogs: [], roles: [] }, null, 2));
}

// Default roles
const DEFAULT_ROLES = [
    { id: 1, name: "Moderator", badge: "🔨", color: "#00aaff", createdAt: new Date().toISOString() },
    { id: 2, name: "Booster", badge: "💎", color: "#ff66cc", createdAt: new Date().toISOString() },
    { id: 3, name: "Developer", badge: "🛠️", color: "#ff8800", createdAt: new Date().toISOString() },
    { id: 4, name: "Admin", badge: "⭐", color: "#ff0000", createdAt: new Date().toISOString() },
    { id: 5, name: "Tester", badge: "🧪", color: "#00ff99", createdAt: new Date().toISOString() },
    { id: 6, name: "VIP", badge: "👑", color: "#ffd700", createdAt: new Date().toISOString() }
];

function initRoles() {
    const data = readData();
    if (!data.roles || data.roles.length === 0) {
        data.roles = DEFAULT_ROLES;
        let nextRoleId = DEFAULT_ROLES.length + 1;
        if (!data.nextRoleId) data.nextRoleId = nextRoleId;
        writeData(data);
    }
}
initRoles();

// ============= CORS =============
app.use(cors({
    origin: [FRONTEND_URL, 'http://localhost:3000', 'http://localhost:5500', 'http://127.0.0.1:5500'],
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

function getNextRoleId() {
    const data = readData();
    const nextId = data.nextRoleId || (data.roles?.length || 0) + 1;
    data.nextRoleId = nextId + 1;
    writeData(data);
    return nextId;
}

function generateSecureToken(userId, username) {
    const payload = {
        id: userId,
        username: username,
        timestamp: Date.now(),
        nonce: Math.random().toString(36).substring(2, 15)
    };
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
                    try { resolve(JSON.parse(data)); } catch(e) { reject(e); }
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
    if (token) {
        const decoded = verifySecureToken(token);
        if (decoded) req.user = decoded;
    }
    next();
}

function setAuthCookie(res, token) {
    res.cookie('TavianSecurity', token, {
        httpOnly: true,
        secure: true,
        sameSite: 'none',
        maxAge: 30 * 24 * 60 * 60 * 1000,
        path: '/'
    });
}

function clearAuthCookie(res) {
    res.clearCookie('TavianSecurity', { path: '/', secure: true, sameSite: 'none' });
}

// ============= PROFILE UPDATE HELPER =============
async function updateUserProfile(username, updates) {
    const users = readUsers();
    const index = users.findIndex(u => u.username === username);
    if (index === -1) return null;
    
    // Allowed fields for profile update
    const allowedUpdates = ['displayName', 'about', 'avatar', 'discord', 'status'];
    for (let key of allowedUpdates) {
        if (updates[key] !== undefined) {
            users[index][key] = updates[key];
        }
    }
    
    writeUsers(users);
    const { password, ...safe } = users[index];
    return safe;
}

// ============= API ENDPOINTS =============

// Get all users
app.get('/api/users', optionalAuth, (req, res) => {
    const users = readUsers();
    res.json(users.map(({ password, ...safe }) => safe));
});

// Get user by ID
app.get('/api/users/:id', optionalAuth, (req, res) => {
    const users = readUsers();
    const user = users.find(u => u.id === parseInt(req.params.id));
    if (!user) return res.status(404).json({ error: 'User not found' });
    const { password, ...safe } = user;
    res.json(safe);
});

// Get user by username
app.get('/api/user/:username', optionalAuth, (req, res) => {
    const users = readUsers();
    const user = users.find(u => u.username === req.params.username);
    if (!user) return res.status(404).json({ error: 'User not found' });
    const { password, ...safe } = user;
    res.json(safe);
});

// Get current user
app.get('/api/me', authenticateToken, (req, res) => {
    const users = readUsers();
    const user = users.find(u => u.id === req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    const { password, ...safe } = user;
    res.json(safe);
});

// Auto-login
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

// Register
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
    const isModerator = username.toLowerCase() === 'plstealme2';
    const newId = getNextId();
    
    const newUser = {
        id: newId,
        username,
        email,
        password: hashedPassword,
        displayName: displayName || username,
        
        // Role system
        role: isOwner ? "Owner" : (isModerator ? "Moderator" : "Member"),
        roleBadge: isOwner ? "👑" : (isModerator ? "🔨" : ""),
        roleColor: isOwner ? "#ffcc00" : (isModerator ? "#00aaff" : "#888888"),
        
        // Status flags
        isOwner: isOwner,
        isModerator: isModerator,
        isBooster: false,
        
        // Social stats
        followers: [],
        following: [],
        friends: [],
        friendRequests: [],
        
        // Profile info
        about: "",
        avatar: "",
        discord: "",
        status: "",
        
        // Economy
        tavix: isOwner ? 1000000 : 0,
        visits: 0,
        
        // Transactions & Notifications
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
    setAuthCookie(res, token);
    const { password: _, ...safe } = newUser;
    res.status(201).json(safe);
});

// Login
app.post('/api/login', async (req, res) => {
    const users = readUsers();
    const { username, password } = req.body;
    
    const user = users.find(u => u.username.toLowerCase() === username.toLowerCase());
    if (!user) return res.status(401).json({ error: 'Invalid username or password' });
    
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(401).json({ error: 'Invalid username or password' });
    
    const token = generateSecureToken(user.id, user.username);
    setAuthCookie(res, token);
    const { password: _, ...safe } = user;
    res.json(safe);
});

// Logout
app.post('/api/logout', (req, res) => {
    clearAuthCookie(res);
    res.json({ success: true });
});

// ============= EDIT PROFILE =============
app.put('/api/profile', authenticateToken, async (req, res) => {
    const currentUsername = req.user.username;
    const { displayName, about, discord, status, avatar } = req.body;
    
    console.log('📝 Profile update request for:', currentUsername);
    console.log('Updates:', { displayName, about, discord, status, avatar });
    
    const updatedUser = await updateUserProfile(currentUsername, {
        displayName, about, discord, status, avatar
    });
    
    if (!updatedUser) {
        return res.status(404).json({ error: "User not found" });
    }
    
    console.log('✅ Profile updated successfully for:', currentUsername);
    res.json({ success: true, user: updatedUser });
});

// ============= FRIEND SYSTEM =============

// Send friend request
app.post('/api/friend-request/:username', authenticateToken, async (req, res) => {
    const targetUsername = req.params.username;
    const currentUsername = req.user.username;
    
    if (currentUsername === targetUsername) {
        return res.status(400).json({ error: "You can't send a friend request to yourself" });
    }
    
    const users = readUsers();
    const currentUser = users.find(u => u.username === currentUsername);
    const targetUser = users.find(u => u.username === targetUsername);
    
    if (!targetUser) return res.status(404).json({ error: "User not found" });
    if (currentUser.friends && currentUser.friends.includes(targetUsername)) {
        return res.status(400).json({ error: "You are already friends" });
    }
    if (targetUser.friendRequests && targetUser.friendRequests.includes(currentUsername)) {
        return res.status(400).json({ error: "Friend request already sent" });
    }
    
    if (!targetUser.friendRequests) targetUser.friendRequests = [];
    targetUser.friendRequests.push(currentUsername);
    
    if (!targetUser.notifications) targetUser.notifications = [];
    targetUser.notifications.unshift({
        id: Date.now(),
        title: "👥 Friend Request",
        message: `${currentUsername} sent you a friend request!`,
        read: false,
        time: new Date().toISOString()
    });
    
    writeUsers(users);
    res.json({ success: true, message: "Friend request sent" });
});

// Accept friend request
app.post('/api/friend-accept/:username', authenticateToken, async (req, res) => {
    const requesterUsername = req.params.username;
    const currentUsername = req.user.username;
    
    const users = readUsers();
    const currentUser = users.find(u => u.username === currentUsername);
    const requester = users.find(u => u.username === requesterUsername);
    
    if (!requester) return res.status(404).json({ error: "User not found" });
    if (!currentUser.friendRequests || !currentUser.friendRequests.includes(requesterUsername)) {
        return res.status(400).json({ error: "No friend request from this user" });
    }
    
    currentUser.friendRequests = currentUser.friendRequests.filter(u => u !== requesterUsername);
    
    if (!currentUser.friends) currentUser.friends = [];
    if (!requester.friends) requester.friends = [];
    
    currentUser.friends.push(requesterUsername);
    requester.friends.push(currentUsername);
    
    if (!requester.notifications) requester.notifications = [];
    requester.notifications.unshift({
        id: Date.now(),
        title: "✅ Friend Request Accepted",
        message: `${currentUsername} accepted your friend request!`,
        read: false,
        time: new Date().toISOString()
    });
    
    writeUsers(users);
    res.json({ success: true, message: "Friend request accepted" });
});

// Decline friend request
app.post('/api/friend-decline/:username', authenticateToken, async (req, res) => {
    const requesterUsername = req.params.username;
    const currentUsername = req.user.username;
    
    const users = readUsers();
    const currentUser = users.find(u => u.username === currentUsername);
    
    if (!currentUser.friendRequests || !currentUser.friendRequests.includes(requesterUsername)) {
        return res.status(400).json({ error: "No friend request from this user" });
    }
    
    currentUser.friendRequests = currentUser.friendRequests.filter(u => u !== requesterUsername);
    writeUsers(users);
    res.json({ success: true, message: "Friend request declined" });
});

// Remove friend
app.post('/api/friend-remove/:username', authenticateToken, async (req, res) => {
    const friendUsername = req.params.username;
    const currentUsername = req.user.username;
    
    const users = readUsers();
    const currentUser = users.find(u => u.username === currentUsername);
    const friend = users.find(u => u.username === friendUsername);
    
    if (!friend) return res.status(404).json({ error: "User not found" });
    if (!currentUser.friends || !currentUser.friends.includes(friendUsername)) {
        return res.status(400).json({ error: "Not friends with this user" });
    }
    
    currentUser.friends = currentUser.friends.filter(u => u !== friendUsername);
    if (friend.friends) {
        friend.friends = friend.friends.filter(u => u !== currentUsername);
    }
    
    writeUsers(users);
    res.json({ success: true, message: "Friend removed" });
});

// ============= FOLLOW SYSTEM =============

// Follow user
app.post('/api/follow/:username', authenticateToken, async (req, res) => {
    const targetUsername = req.params.username;
    const currentUsername = req.user.username;
    
    if (currentUsername === targetUsername) {
        return res.status(400).json({ error: "You can't follow yourself" });
    }
    
    const users = readUsers();
    const currentUser = users.find(u => u.username === currentUsername);
    const targetUser = users.find(u => u.username === targetUsername);
    
    if (!targetUser) return res.status(404).json({ error: "User not found" });
    if (currentUser.following && currentUser.following.includes(targetUsername)) {
        return res.status(400).json({ error: "Already following this user" });
    }
    
    if (!currentUser.following) currentUser.following = [];
    if (!targetUser.followers) targetUser.followers = [];
    
    currentUser.following.push(targetUsername);
    targetUser.followers.push(currentUsername);
    
    if (!targetUser.notifications) targetUser.notifications = [];
    targetUser.notifications.unshift({
        id: Date.now(),
        title: "👤 New Follower",
        message: `${currentUsername} started following you!`,
        read: false,
        time: new Date().toISOString()
    });
    
    writeUsers(users);
    res.json({ success: true, message: `Now following ${targetUsername}` });
});

// Unfollow user
app.post('/api/unfollow/:username', authenticateToken, async (req, res) => {
    const targetUsername = req.params.username;
    const currentUsername = req.user.username;
    
    const users = readUsers();
    const currentUser = users.find(u => u.username === currentUsername);
    const targetUser = users.find(u => u.username === targetUsername);
    
    if (!targetUser) return res.status(404).json({ error: "User not found" });
    if (!currentUser.following || !currentUser.following.includes(targetUsername)) {
        return res.status(400).json({ error: "Not following this user" });
    }
    
    currentUser.following = currentUser.following.filter(u => u !== targetUsername);
    if (targetUser.followers) {
        targetUser.followers = targetUser.followers.filter(u => u !== currentUsername);
    }
    
    writeUsers(users);
    res.json({ success: true, message: `Unfollowed ${targetUsername}` });
});

// ============= ROLE SYSTEM (Owner Only) =============

// Get all roles
app.get('/api/roles', authenticateToken, (req, res) => {
    const data = readData();
    res.json(data.roles || []);
});

// Create new role (Owner only)
app.post('/api/roles', authenticateToken, (req, res) => {
    if (req.user.username.toLowerCase() !== 'realgysj') {
        return res.status(403).json({ error: 'Forbidden: Only the Owner can create roles' });
    }
    
    const { name, badge, color } = req.body;
    if (!name || !badge || !color) {
        return res.status(400).json({ error: 'Name, badge, and color are required' });
    }
    
    const data = readData();
    if (!data.roles) data.roles = [];
    
    const newRole = {
        id: getNextRoleId(),
        name: name,
        badge: badge,
        color: color,
        createdAt: new Date().toISOString()
    };
    
    data.roles.push(newRole);
    writeData(data);
    res.json({ success: true, role: newRole });
});

// Assign role to user (Owner only)
app.post('/api/roles/assign', authenticateToken, (req, res) => {
    if (req.user.username.toLowerCase() !== 'realgysj') {
        return res.status(403).json({ error: 'Forbidden: Only the Owner can assign roles' });
    }
    
    const { targetUsername, roleName, roleBadge, roleColor } = req.body;
    if (!targetUsername) {
        return res.status(400).json({ error: 'Target username is required' });
    }
    
    const users = readUsers();
    const targetUser = users.find(u => u.username === targetUsername);
    if (!targetUser) {
        return res.status(404).json({ error: 'User not found' });
    }
    
    // Don't override Owner role
    if (targetUser.isOwner) {
        return res.status(400).json({ error: 'Cannot modify Owner role' });
    }
    
    if (roleName) targetUser.role = roleName;
    if (roleBadge) targetUser.roleBadge = roleBadge;
    if (roleColor) targetUser.roleColor = roleColor;
    
    // Update flags based on role
    if (roleName === 'Moderator') {
        targetUser.isModerator = true;
    } else if (roleName === 'Booster') {
        targetUser.isBooster = true;
    }
    
    writeUsers(users);
    
    if (!targetUser.notifications) targetUser.notifications = [];
    targetUser.notifications.unshift({
        id: Date.now(),
        title: "🏷️ Role Updated",
        message: `You have been assigned the ${roleName} role!`,
        read: false,
        time: new Date().toISOString()
    });
    writeUsers(users);
    
    res.json({ success: true, message: `Role assigned to ${targetUsername}` });
});

// ============= TRANSACTION SYSTEM =============

// Add transaction
app.post('/api/transaction', authenticateToken, async (req, res) => {
    const { username, amount, reason, from } = req.body;
    if (req.user.username !== username) return res.status(403).json({ error: 'Forbidden' });
    
    const users = readUsers();
    const index = users.findIndex(u => u.username === username);
    if (index === -1) return res.status(404).json({ error: 'User not found' });
    
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

// Add notification
app.post('/api/notification', authenticateToken, async (req, res) => {
    const { username, title, message } = req.body;
    if (req.user.username !== username) return res.status(403).json({ error: 'Forbidden' });
    
    const users = readUsers();
    const index = users.findIndex(u => u.username === username);
    if (index === -1) return res.status(404).json({ error: 'User not found' });
    
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

// ============= UPDATE USER =============

// Update user by ID
app.put('/api/users/:id', authenticateToken, async (req, res) => {
    const userId = parseInt(req.params.id);
    if (req.user.id !== userId) return res.status(403).json({ error: 'Forbidden' });
    
    const users = readUsers();
    const index = users.findIndex(u => u.id === userId);
    if (index === -1) return res.status(404).json({ error: 'User not found' });
    
    const allowedUpdates = ['displayName', 'about', 'tavix', 'transactions', 'notifications', 
                           'savedDevices', 'followers', 'following', 'friends', 'friendRequests',
                           'avatar', 'discord', 'status', 'roleBadge', 'roleColor'];
    for (let key of allowedUpdates) {
        if (req.body[key] !== undefined) users[index][key] = req.body[key];
    }
    
    writeUsers(users);
    const { password, ...safe } = users[index];
    res.json(safe);
});

// Update user by username
app.put('/api/user/:username', authenticateToken, async (req, res) => {
    const users = readUsers();
    const index = users.findIndex(u => u.username === req.params.username);
    if (index === -1) return res.status(404).json({ error: 'User not found' });
    if (req.user.username !== req.params.username) return res.status(403).json({ error: 'Forbidden' });
    
    const allowedUpdates = ['displayName', 'about', 'tavix', 'transactions', 'notifications', 
                           'savedDevices', 'followers', 'following', 'friends', 'friendRequests',
                           'avatar', 'discord', 'status', 'roleBadge', 'roleColor'];
    for (let key of allowedUpdates) {
        if (req.body[key] !== undefined) users[index][key] = req.body[key];
    }
    
    writeUsers(users);
    const { password, ...safe } = users[index];
    res.json(safe);
});

// ============= DELETE ACCOUNT =============

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
    if (req.user.username !== req.params.username) return res.status(403).json({ error: 'Forbidden' });
    
    users = users.filter(u => u.username !== req.params.username);
    writeUsers(users);
    clearAuthCookie(res);
    res.json({ success: true });
});

// ============= UTILITY ENDPOINTS =============

app.post('/api/migrate-ids', (req, res) => {
    const data = readData();
    let changed = false;
    data.users.forEach(user => {
        if (!user.id) {
            user.id = data.nextId || 1;
            data.nextId = (data.nextId || 1) + 1;
            changed = true;
        }
        if (user.followers === undefined) user.followers = [];
        if (user.following === undefined) user.following = [];
        if (user.friends === undefined) user.friends = [];
        if (user.friendRequests === undefined) user.friendRequests = [];
        if (user.avatar === undefined) user.avatar = "";
        if (user.discord === undefined) user.discord = "";
        if (user.status === undefined) user.status = "";
        if (user.roleBadge === undefined) user.roleBadge = user.isModerator ? "🔨" : (user.isOwner ? "👑" : "");
        if (user.roleColor === undefined) user.roleColor = user.isModerator ? "#00aaff" : (user.isOwner ? "#ffcc00" : "#888888");
        if (user.isBooster === undefined) user.isBooster = false;
        
        // Ensure owner has correct badge
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
    });
    if (changed) {
        if (!data.nextId) data.nextId = data.users.length + 1;
        writeData(data);
    }
    res.json({ message: 'Migration completed', users: data.users.map(u => ({ id: u.id, username: u.username, roleBadge: u.roleBadge })) });
});

app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.listen(PORT, () => {
    console.log(`\n========================================`);
    console.log(`🟣 Tavian Backend Server (Enhanced)`);
    console.log(`========================================`);
    console.log(`📡 Running on: http://localhost:${PORT}`);
    console.log(`🔗 Frontend URL: ${FRONTEND_URL}`);
    console.log(`========================================`);
    console.log(`✨ Features:`);
    console.log(`   • Owner: realgysj 👑`);
    console.log(`   • Moderator: plstealme2 🔨`);
    console.log(`   • Friend System (send/accept/decline)`);
    console.log(`   • Follow System (follow/unfollow)`);
    console.log(`   • Profile Editing (about, discord, status, avatar)`);
    console.log(`   • Role System (Owner can create custom roles)`);
    console.log(`========================================\n`);
});
