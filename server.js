const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch');
const path = require('path');
const crypto = require('crypto');
const { MongoClient } = require('mongodb');

const app = express();
app.use(cors());
app.use(express.json());

const MONGO_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017';
const DB_NAME = 'maya-app';
let mongoClient = null;

async function getDb() {
    if (!mongoClient) {
        mongoClient = new MongoClient(MONGO_URI);
        await mongoClient.connect();
    }
    return mongoClient.db(DB_NAME);
}

async function seedAdmin() {
    try {
        const db = await getDb();
        const users = db.collection('users');
        var existing = await users.findOne({ employeeId: 'ancel' });
        if (!existing) {
            await users.insertOne({
                id: 'USR001',
                employeeId: 'ancel',
                fullName: 'Ancel Claudio',
                password: 'maya2026',
                role: 'ADMIN',
                securityQuestion: 'What is your pet\'s name?',
                securityAnswer: 'maya',
                createdAt: new Date().toISOString()
            });
            console.log('Seed admin created');
        } else if (!existing.securityQuestion) {
            // Fix existing admin if missing security fields
            await users.updateOne({ employeeId: 'ancel' }, { $set: { securityQuestion: 'What is your pet\'s name?', securityAnswer: 'maya' } });
            console.log('Seed admin security question added');
        }
    } catch (e) {
        console.error('MONGO FAILED:', e.message);
        process.exit(1);
    }
}

function getRoleLevel(role) {
    var levels = { 'ADMIN': 6, 'CLIENT': 5, 'OPERATIONS MANAGER': 4, 'TEAM LEADER': 3, 'AGENT': 2, 'TRAINING': 1 };
    return levels[role] || 0;
}

function generateToken(user) {
    var payload = JSON.stringify({ id: user.employeeId, name: user.fullName, role: user.role, exp: Date.now() + (12 * 60 * 60 * 1000) });
    var cipher = crypto.createCipheriv('aes-256-cbc', crypto.createHash('sha256').update('maya-secret-salt-2025').digest(), Buffer.alloc(16, 'maya-calculator-iv'));
    var token = cipher.update(payload, 'utf8', 'hex');
    token += cipher.final('hex');
    return token;
}

function verifyToken(token) {
    try {
        var decipher = crypto.createDecipheriv('aes-256-cbc', crypto.createHash('sha256').update('maya-secret-salt-2025').digest(), Buffer.alloc(16, 'maya-calculator-iv'));
        var payload = decipher.update(token, 'hex', 'utf8');
        payload += decipher.final('utf8');
        var data = JSON.parse(payload);
        if (data.exp < Date.now()) return null;
        return data;
    } catch (e) { return null; }
}

function authMiddleware(req, res, next) {
    var token = req.headers['x-maya-token'] || req.query.token;
    if (!token) return res.status(401).json({ error: 'No token provided' });
    var user = verifyToken(token);
    if (!user) return res.status(401).json({ error: 'Invalid or expired token' });
    req.user = user;
    next();
}

app.get('/', function(req, res) { res.sendFile(path.join(__dirname, 'public', 'login.html')); });
app.get('/app', function(req, res) { res.sendFile(path.join(__dirname, 'public', 'index.html')); });

app.post('/api/auth/login', async function(req, res) {
    var employeeId = (req.body.employeeId || '').toLowerCase();
    var password = req.body.password;
    if (!employeeId || !password) return res.status(400).json({ error: 'Employee ID and password are required' });
    try {
        const db = await getDb();
        var user = await db.collection('users').findOne({ employeeId: employeeId });
        if (!user || user.password !== password) return res.status(401).json({ error: 'Invalid Employee ID or Password' });
        res.json({ token: generateToken(user), user: { employeeId: user.employeeId, fullName: user.fullName, role: user.role } });
    } catch (e) { res.status(500).json({ error: 'Database error' }); }
});

app.get('/api/auth/verify', authMiddleware, function(req, res) { res.json({ valid: true, user: req.user }); });

app.get('/api/auth/users', authMiddleware, async function(req, res) {
    if (getRoleLevel(req.user.role) < 3) return res.status(403).json({ error: 'Not authorized' });
    try {
        const db = await getDb();
        res.json((await db.collection('users').find({}).toArray()).map(function(u) { return { id: u.id, employeeId: u.employeeId, fullName: u.fullName, role: u.role, createdAt: u.createdAt }; }));
    } catch (e) { res.status(500).json({ error: 'Database error' }); }
});

app.post('/api/auth/users', authMiddleware, async function(req, res) {
    var creatorLevel = getRoleLevel(req.user.role);
    if (creatorLevel < 3) return res.status(403).json({ error: 'Not authorized' });
    var fullName = req.body.fullName, employeeId = (req.body.employeeId || '').toLowerCase(), password = req.body.password;
    var securityQuestion = req.body.securityQuestion, securityAnswer = req.body.securityAnswer;
    if (!fullName || !employeeId || !password) return res.status(400).json({ error: 'All fields required' });
    if (password.length < 6) return res.status(400).json({ error: 'Password min 6 characters' });
    if (!securityQuestion || !securityAnswer) return res.status(400).json({ error: 'Security question and answer required' });
    try {
        const db = await getDb();
        if (await db.collection('users').findOne({ employeeId: employeeId })) return res.status(409).json({ error: 'Employee ID already exists' });
        var newUser = {
            id: 'USR' + Date.now().toString().slice(-6),
            employeeId: employeeId,
            fullName: fullName,
            password: password,
            role: 'AGENT',
            securityQuestion: securityQuestion,
            securityAnswer: securityAnswer.toLowerCase().trim(),
            createdAt: new Date().toISOString()
        };
        await db.collection('users').insertOne(newUser);
        res.status(201).json({ message: 'Account created for ' + fullName, user: { id: newUser.id, employeeId: newUser.employeeId, fullName: newUser.fullName, role: newUser.role, createdAt: newUser.createdAt } });
    } catch (e) { res.status(500).json({ error: 'Database error' }); }
});

app.delete('/api/auth/users/:employeeId', authMiddleware, async function(req, res) {
    var creatorLevel = getRoleLevel(req.user.role);
    if (creatorLevel < 3) return res.status(403).json({ error: 'Not authorized' });
    var targetId = req.params.employeeId.toLowerCase();
    if (targetId === req.user.id) return res.status(400).json({ error: 'Cannot delete own account' });
    try {
        const db = await getDb();
        var targetUser = await db.collection('users').findOne({ employeeId: targetId });
        if (!targetUser) return res.status(404).json({ error: 'User not found' });
        if (getRoleLevel(targetUser.role) >= creatorLevel) return res.status(403).json({ error: 'Cannot delete equal or higher role' });
        await db.collection('users').deleteOne({ employeeId: targetId });
        res.json({ message: 'Account "' + targetId + '" deleted' });
    } catch (e) { res.status(500).json({ error: 'Database error' }); }
});

app.post('/api/auth/check-user', async function(req, res) {
    var employeeId = (req.body.employeeId || '').toLowerCase();
    if (!employeeId) return res.status(400).json({ error: 'Employee ID required' });
    try {
        var user = await (await getDb()).collection('users').findOne({ employeeId: employeeId });
        if (!user) return res.status(404).json({ error: 'No account found' });
        res.json({ found: true, employeeId: user.employeeId, fullName: user.fullName, securityQuestion: user.securityQuestion || null });
    } catch (e) { res.status(500).json({ error: 'Database error' }); }
});

app.post('/api/auth/verify-security', async function(req, res) {
    var employeeId = (req.body.employeeId || '').toLowerCase();
    var answer = (req.body.answer || '').trim().toLowerCase();
    if (!employeeId || !answer) return res.status(400).json({ error: 'All fields required' });
    try {
        var user = await (await getDb()).collection('users').findOne({ employeeId: employeeId });
        if (!user) return res.status(404).json({ error: 'No account found' });
        if (!user.securityAnswer || answer !== user.securityAnswer.toLowerCase()) {
            return res.status(401).json({ error: 'Incorrect answer' });
        }
        res.json({ verified: true });
    } catch (e) { res.status(500).json({ error: 'Database error' }); }
});

app.post('/api/auth/reset-password', async function(req, res) {
    var employeeId = (req.body.employeeId || '').toLowerCase();
    var newPassword = req.body.newPassword;
    var securityQuestion = req.body.securityQuestion || null;
    var securityAnswer = req.body.securityAnswer || null;
    if (!employeeId || !newPassword) return res.status(400).json({ error: 'All fields required' });
    if (newPassword.length < 6) return res.status(400).json({ error: 'Password min 6 characters' });
    try {
        var db = await getDb();
        var result = await db.collection('users').updateOne({ employeeId: employeeId }, { $set: { password: newPassword, securityQuestion: securityQuestion, securityAnswer: securityAnswer ? securityAnswer.toLowerCase().trim() : null } });
        if (result.matchedCount === 0) return res.status(404).json({ error: 'No account found' });
        res.json({ message: 'Password updated' });
    } catch (e) { res.status(500).json({ error: 'Database error' }); }
});

app.post('/api/chat', async function(req, res) {
    var token = (req.headers.authorization || '').replace('Bearer ', '').trim();
    if (token !== process.env.RENDER_AUTH_KEY) return res.status(401).json({ error: { message: 'Please contact support.' } });
    if (!process.env.GROQ_API_KEY) return res.status(500).json({ error: { message: 'Please contact support.' } });
    try {
        var response = await fetch('https://api.groq.com/openai/v1/chat/completions', { method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + process.env.GROQ_API_KEY }, body: JSON.stringify(req.body) });
        res.status(response.status).json(await response.json());
    } catch (err) { res.status(500).json({ error: { message: 'Proxy error: ' + err.message } }); }
});

app.get('/api/health', async function(req, res) {
    var dbStatus = 'disconnected';
    try { await (await getDb()).command({ ping: 1 }); dbStatus = 'connected'; } catch (e) { dbStatus = 'error'; }
    res.json({ status: 'online', database: dbStatus, groqKeySet: !!process.env.GROQ_API_KEY, authKeySet: !!process.env.RENDER_AUTH_KEY });
});

app.use(express.static(path.join(__dirname, 'public')));

var PORT = process.env.PORT || 10000;
app.listen(PORT, async function() {
    console.log('Maya app running on port ' + PORT);
    await seedAdmin();
});
