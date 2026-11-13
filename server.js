const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');
const { MongoClient } = require('mongodb');

const app = express();
app.use(cors());
app.use(express.json());

// Required for Render to get the real user IP instead of the proxy IP
app.set('trust proxy', true);

const MONGO_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017';
const DB_NAME = 'maya-app';
let mongoClient = null;

// ========================================
// IP WHITELISTING MIDDLEWARE (TOGGLEABLE)
// ========================================
// [v1.1 FIX] Was: process.env.IP_WHITELIST_ENABLED === 'false'
// The old comparison was INVERTED:
//   - Setting IP_WHITELIST_ENABLED=false actually ENABLED the whitelist
//     (and with an empty ALLOWED_IPS list it blocked EVERYONE - total lockout).
//   - Setting IP_WHITELIST_ENABLED=true kept it DISABLED (could never be turned on).
// Correct behavior now:
//   - unset or "false"  -> whitelist OFF (all IPs allowed)
//   - "true"            -> whitelist ON  (only ALLOWED_IPS get through)
const IP_WHITELIST_ENABLED = process.env.IP_WHITELIST_ENABLED === 'true';
const allowedIpsEnv = process.env.ALLOWED_IPS || '';
const allowedIps = allowedIpsEnv.split(',').map(ip => ip.trim()).filter(Boolean);

console.log('=== IP WHITELIST ===');
console.log('Enabled:', IP_WHITELIST_ENABLED ? 'YES' : 'NO (all IPs allowed)');
if (IP_WHITELIST_ENABLED) {
    console.log('Whitelisted IPs:', allowedIps.length > 0 ? allowedIps : '[NONE - ALL BLOCKED]');
}
console.log('====================');

app.use((req, res, next) => {
    // Toggle off = allow everyone
    if (!IP_WHITELIST_ENABLED) {
        return next();
    }

    // Toggle on but no IPs listed = block everyone
    if (allowedIps.length === 0) {
        console.log('BLOCKED - Whitelist enabled but empty');
        return res.status(403).send(`
            <!DOCTYPE html>
            <html lang="en">
            <head><meta charset="UTF-8"><title>Access Denied</title></head>
            <body style="font-family: 'Inter', sans-serif; background-color: #08090A; color: #fca5a5; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; text-align: center;">
                <div>
                    <h1 style="font-size: 24px; margin-bottom: 10px;">403 - Access Denied</h1>
                    <p>IP whitelist is enabled but no IPs are configured.</p>
                    <p style="color: #71717a; font-size: 14px; margin-top: 20px;">Set ALLOWED_IPS environment variable</p>
                </div>
            </body>
            </html>
        `);
    }

    // Get real IP
    let clientIp = req.headers['x-forwarded-for'] ||
                   req.headers['x-real-ip'] ||
                   req.socket.remoteAddress ||
                   '';
    clientIp = clientIp.split(',')[0].trim();
    const cleanIp = clientIp.replace(/^::ffff:/, '');

    console.log(`[IP] ${cleanIp} -> ${req.path}`);

    if (allowedIps.includes(cleanIp)) {
        next();
    } else {
        console.log(`DENIED - ${cleanIp} not in [${allowedIps.join(', ')}]`);
        res.status(403).send(`
            <!DOCTYPE html>
            <html lang="en">
            <head><meta charset="UTF-8"><title>Access Denied</title></head>
            <body style="font-family: 'Inter', sans-serif; background-color: #08090A; color: #fca5a5; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; text-align: center;">
                <div>
                    <h1 style="font-size: 24px; margin-bottom: 10px;">403 - Access Denied</h1>
                    <p>Your IP address (${cleanIp}) is not authorized to access this terminal.</p>
                    <p style="color: #71717a; font-size: 14px; margin-top: 20px;">Maya Internal Infrastructure</p>
                </div>
            </body>
            </html>
        `);
    }
});

// [v1.2] announcements shown on the Home dashboard (edit as needed)
const ANNOUNCEMENTS = [
    { title: 'v3.9.1 - Login loop fixed', body: 'Signing in now always lands on the terminal, even when the older server routing is still deployed.', date: '2026-11-13' },
    { title: 'v3.9.0 - Tool Navigator & Home Dashboard', body: 'Press Ctrl+K to open the tool navigator. Star your favorite tools to pin them to the Home dashboard.', date: '2026-11-13' },
    { title: 'Quick Notepad added', body: 'A private scratchpad is now available from the tool navigator. It autosaves on this device, per account.', date: '2026-11-13' },
    { title: 'Change password in-app', body: 'Click your name in the header, then Change Password. No admin needed.', date: '2026-11-13' }
];

// [v1.2] real client IP (Render sits behind a proxy; trust proxy is enabled)
function clientIp(req) {
    var raw = req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || req.socket.remoteAddress || '';
    return raw.split(',')[0].trim().replace(/^::ffff:/, '') || 'unknown';
}

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
        } else {
            // [v1.2] SELF-HEAL: the owner (ancel) is always ADMIN.
            // Fixes databases where the role was stored lowercase, edited
            // by mistake, or created by an older version without a role.
            var fixes = {};
            if (existing.role !== 'ADMIN') fixes.role = 'ADMIN';
            if (!existing.id) fixes.id = 'USR001';
            if (!existing.securityQuestion) { fixes.securityQuestion = 'What is your pet\'s name?'; fixes.securityAnswer = 'maya'; }
            if (Object.keys(fixes).length) {
                await users.updateOne({ employeeId: 'ancel' }, { $set: fixes });
                console.log('Seed admin self-healed:', Object.keys(fixes).join(', '));
            }
        }
    } catch (e) {
        console.error('MONGO FAILED:', e.message);
        process.exit(1);
    }
}

function getRoleLevel(role) {
    var levels = { 'ADMIN': 6, 'CLIENT': 5, 'OPERATIONS MANAGER': 4, 'TEAM LEADER': 3, 'AGENT': 2, 'TRAINING': 1 };
    return levels[String(role || '').toUpperCase()] || 0;
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

// ========================================
// STATIC PAGES
// ========================================
// [v1.2] Robust page resolution: works with BOTH file layouts.
//   layout A (flat):    public/index.html + public/login.html
//   layout B (folders): public/index.html + public/login/index.html
// The terminal opens at / and the login page at /login, matching the
// v3.8+ frontend redirect logic (old "/"=login + "/app"=terminal layout
// caused an infinite login loop and is no longer supported).
function resolvePage() {
    for (var i = 0; i < arguments.length; i++) {
        var p = path.join(__dirname, 'public', arguments[i]);
        if (fs.existsSync(p)) return p;
    }
    return path.join(__dirname, 'public', arguments[0]);
}
app.get('/', function(req, res) { res.sendFile(resolvePage('index.html')); });
app.get(['/login', '/login/'], function(req, res) { res.sendFile(resolvePage('login.html', 'login/index.html')); });
app.get(['/app', '/app/'], function(req, res) { res.redirect(302, '/'); });

app.post('/api/auth/login', async function(req, res) {
    var employeeId = (req.body.employeeId || '').toLowerCase();
    var password = req.body.password;
    if (!employeeId || !password) return res.status(400).json({ error: 'Employee ID and password are required' });
    try {
        const db = await getDb();
        var user = await db.collection('users').findOne({ employeeId: employeeId });
        if (!user || user.password !== password) return res.status(401).json({ error: 'Invalid Employee ID or Password' });
        // [v1.2] track sign-ins for the profile popup (last 5, newest first)
        var now = new Date().toISOString();
        var history = [{ time: now, ip: clientIp(req) }].concat(user.loginHistory || []).slice(0, 5);
        await db.collection('users').updateOne({ employeeId: employeeId }, { $set: { lastLogin: now, loginHistory: history } });
        res.json({
            token: generateToken(user),
            user: { employeeId: user.employeeId, fullName: user.fullName, role: String(user.role || '').toUpperCase(), lastLogin: now, loginHistory: history }
        });
    } catch (e) { res.status(500).json({ error: 'Database error' }); }
});

// [v1.2] change password (profile popup) - requires the current password
app.post('/api/auth/change-password', authMiddleware, async function(req, res) {
    var currentPassword = req.body.currentPassword;
    var newPassword = req.body.newPassword;
    if (!currentPassword || !newPassword) return res.status(400).json({ error: 'All fields required' });
    if (newPassword.length < 6) return res.status(400).json({ error: 'Password min 6 characters' });
    try {
        const db = await getDb();
        var user = await db.collection('users').findOne({ employeeId: req.user.id });
        if (!user) return res.status(404).json({ error: 'No account found' });
        if (user.password !== currentPassword) return res.status(401).json({ error: 'Current password is incorrect' });
        await db.collection('users').updateOne({ employeeId: req.user.id }, { $set: { password: newPassword } });
        res.json({ message: 'Password changed successfully' });
    } catch (e) { res.status(500).json({ error: 'Database error' }); }
});

// [v1.2] verify now enriches the token payload with fresh DB data
// (lastLogin + loginHistory for the profile popup) and normalizes role casing
app.get('/api/auth/verify', authMiddleware, async function(req, res) {
    var extra = { lastLogin: null, loginHistory: [] };
    try {
        var u = await (await getDb()).collection('users').findOne({ employeeId: req.user.id });
        if (u) extra = { lastLogin: u.lastLogin || null, loginHistory: u.loginHistory || [] };
    } catch (e) {}
    res.json({ valid: true, user: {
        id: req.user.id,
        name: req.user.name,
        role: String(req.user.role || '').toUpperCase(),
        lastLogin: extra.lastLogin,
        loginHistory: extra.loginHistory
    } });
});

app.get('/api/auth/users', authMiddleware, async function(req, res) {
    if (getRoleLevel(req.user.role) < 3) return res.status(403).json({ error: 'Not authorized' });
    try {
        const db = await getDb();
        res.json((await db.collection('users').find({}).toArray()).map(function(u) {
            return {
                id: u.id,
                employeeId: u.employeeId,
                fullName: u.fullName,
                securityQuestion: u.securityQuestion || null,
                createdAt: u.createdAt,
                role: String(u.role || '').toUpperCase()
            };
        }));
    } catch (e) { res.status(500).json({ error: 'Database error' }); }
});

app.post('/api/auth/users', authMiddleware, async function(req, res) {
    var creatorLevel = getRoleLevel(req.user.role);
    if (creatorLevel < 3) return res.status(403).json({ error: 'Not authorized' });
    var fullName = req.body.fullName, employeeId = (req.body.employeeId || '').toLowerCase(), password = req.body.password;
    var role = req.body.role;
    var securityQuestion = req.body.securityQuestion, securityAnswer = req.body.securityAnswer;
    if (!fullName || !employeeId || !password) return res.status(400).json({ error: 'All fields required' });
    if (password.length < 6) return res.status(400).json({ error: 'Password min 6 characters' });
    // [v1.1] normalize role casing so lookups/role levels always match
    if (!role) role = 'AGENT';
    role = String(role).toUpperCase();
    if (getRoleLevel(role) >= creatorLevel) return res.status(403).json({ error: 'Cannot create equal or higher role' });
    if (!securityQuestion || !securityAnswer) return res.status(400).json({ error: 'Security question and answer required' });
    try {
        const db = await getDb();
        if (await db.collection('users').findOne({ employeeId: employeeId })) return res.status(409).json({ error: 'Employee ID already exists' });
        var newUser = {
            id: 'USR' + Date.now().toString().slice(-6),
            employeeId: employeeId,
            fullName: fullName,
            password: password,
            role: role,
            securityQuestion: securityQuestion,
            securityAnswer: securityAnswer.toLowerCase().trim(),
            createdAt: new Date().toISOString()
        };
        await db.collection('users').insertOne(newUser);
        res.status(201).json({ message: 'Account created for ' + fullName, user: { id: newUser.id, employeeId: newUser.employeeId, fullName: newUser.fullName, role: newUser.role, createdAt: newUser.createdAt } });
    } catch (e) { res.status(500).json({ error: 'Database error' }); }
});

app.put('/api/auth/users/:employeeId', authMiddleware, async function(req, res) {
    var creatorLevel = getRoleLevel(req.user.role);
    if (creatorLevel < 3) return res.status(403).json({ error: 'Not authorized' });
    var targetId = req.params.employeeId.toLowerCase();
    if (targetId === req.user.id) return res.status(400).json({ error: 'Cannot edit own account' });
    try {
        const db = await getDb();
        var targetUser = await db.collection('users').findOne({ employeeId: targetId });
        if (!targetUser) return res.status(404).json({ error: 'User not found' });
        if (getRoleLevel(targetUser.role) >= creatorLevel) return res.status(403).json({ error: 'Cannot edit equal or higher role' });

        var updateFields = {};
        if (req.body.fullName) updateFields.fullName = req.body.fullName;
        if (req.body.role) {
            // [v1.1] normalize role casing
            var newRole = String(req.body.role).toUpperCase();
            if (getRoleLevel(newRole) >= creatorLevel) return res.status(403).json({ error: 'Cannot assign equal or higher role' });
            updateFields.role = newRole;
        }
        if (req.body.password) {
            if (req.body.password.length < 6) return res.status(400).json({ error: 'Password min 6 characters' });
            updateFields.password = req.body.password;
        }
        if (req.body.securityQuestion) updateFields.securityQuestion = req.body.securityQuestion;
        if (req.body.securityAnswer) updateFields.securityAnswer = req.body.securityAnswer.toLowerCase().trim();

        if (Object.keys(updateFields).length === 0) return res.status(400).json({ error: 'No changes provided' });

        await db.collection('users').updateOne({ employeeId: targetId }, { $set: updateFields });
        res.json({ message: 'Account "' + targetId + '" updated' });
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
    res.json({
        status: 'online',
        version: 'v1.2.1',
        frontend: 'v3.9.1',
        database: dbStatus,
        announcements: ANNOUNCEMENTS,
        groqKeySet: !!process.env.GROQ_API_KEY,
        authKeySet: !!process.env.RENDER_AUTH_KEY,
        ipWhitelist: {
            enabled: IP_WHITELIST_ENABLED,
            allowedIps: IP_WHITELIST_ENABLED ? allowedIps : 'disabled'
        }
    });
});

// ========================================
// SECURE FX RATES API PROXY
// ========================================
app.get('/api/fx-rates', async function(req, res) {
    let fxApiUrl = process.env.FX_API_URL || 'https://open.er-api.com/v6/latest/PHP';
    if (!fxApiUrl.startsWith('http://') && !fxApiUrl.startsWith('https://')) {
        fxApiUrl = 'https://' + fxApiUrl;
    }
    try {
        const response = await fetch(fxApiUrl);
        if (!response.ok) throw new Error('Network response was not ok');
        const data = await response.json();
        res.json(data);
    } catch (err) {
        console.error('FX API Error:', err);
        res.status(500).json({ error: 'Failed to fetch live exchange rates' });
    }
});

// ========================================
// TICKETING & NOTES API
// ========================================
app.get('/api/notes', authMiddleware, async function(req, res) {
    try {
        const db = await getDb();
        const notes = await db.collection('notes').find({}).sort({ createdAt: -1 }).toArray();
        res.json(notes);
    } catch (e) { res.status(500).json({ error: 'Database error' }); }
});

app.post('/api/notes', authMiddleware, async function(req, res) {
    const { subject, details } = req.body;
    if (!subject) return res.status(400).json({ error: 'Subject is required' });
    try {
        const db = await getDb();
        // [v1.1] retry until the random ticket id is unique (avoids duplicates)
        var noteId;
        do {
            noteId = 'TKT-' + Math.floor(Math.random() * 900000 + 100000);
        } while (await db.collection('notes').findOne({ id: noteId }));
        const newNote = {
            id: noteId,
            userId: req.user.id,
            userName: req.user.name,
            subject,
            details: details || '',
            status: 'Open',
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString()
        };
        await db.collection('notes').insertOne(newNote);
        res.status(201).json({ message: 'Ticket created', note: newNote });
    } catch (e) { res.status(500).json({ error: 'Database error' }); }
});

app.put('/api/notes/:id', authMiddleware, async function(req, res) {
    const noteId = req.params.id;
    const { subject, details, status } = req.body;
    try {
        const db = await getDb();
        const note = await db.collection('notes').findOne({ id: noteId });
        if (!note) return res.status(404).json({ error: 'Ticket not found' });

        const isCreator = note.userId === req.user.id;
        const isTLPlus = getRoleLevel(req.user.role) >= 3;

        if (note.status === 'Closed' && !isTLPlus) {
            return res.status(403).json({ error: 'Ticket is closed. Only TLs and above can edit.' });
        }

        if (!isCreator && !isTLPlus) {
            return res.status(403).json({ error: 'You can only view this ticket. Only the creator or TLs+ can edit.' });
        }

        const updateFields = { updatedAt: new Date().toISOString() };
        if (subject) updateFields.subject = subject;
        if (details !== undefined) updateFields.details = details;
        if (status) updateFields.status = status;

        await db.collection('notes').updateOne({ id: noteId }, { $set: updateFields });
        res.json({ message: 'Ticket updated' });
    } catch (e) { res.status(500).json({ error: 'Database error' }); }
});

app.delete('/api/notes/:id', authMiddleware, async function(req, res) {
    const noteId = req.params.id;
    if (getRoleLevel(req.user.role) < 3) return res.status(403).json({ error: 'Only TLs and above can delete tickets' });
    try {
        const db = await getDb();
        await db.collection('notes').deleteOne({ id: noteId });
        res.json({ message: 'Ticket deleted' });
    } catch (e) { res.status(500).json({ error: 'Database error' }); }
});

// ========================================
// SECURE EMAIL API PROXY
// ========================================
app.post('/api/email/send', authMiddleware, async function(req, res) {
    let { to_email, to_name, subject, receipt_html, receipt_summary, total_amount, principal, interest_total, installments, note, from_name, type } = req.body;

    if (type === 'contact') {
        to_email = process.env.ADMIN_EMAIL;
        to_name = 'Admin';
    }

    if (!to_email || !subject) {
        return res.status(400).json({ error: 'Recipient email and subject are required' });
    }

    const serviceId = process.env.EMAILJS_SERVICE_ID;
    const templateId = process.env.EMAILJS_TEMPLATE_ID;
    const publicKey = process.env.EMAILJS_PUBLIC_KEY;

    if (!serviceId || !templateId || !publicKey) {
        console.error('Missing EmailJS environment variables on server');
        return res.status(500).json({ error: 'Email service is not configured on the server.' });
    }

    try {
        const response = await fetch('https://api.emailjs.com/api/v1.0/email/send', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                service_id: serviceId,
                template_id: templateId,
                user_id: publicKey,
                template_params: {
                    to_email,
                    to_name: to_name || 'Customer',
                    from_name: from_name || req.user.name || 'Maya Agent',
                    subject,
                    receipt_html: receipt_html || '',
                    receipt_summary: receipt_summary || '',
                    total_amount: total_amount || 'N/A',
                    principal: principal || 'N/A',
                    interest_total: interest_total || 'N/A',
                    installments: installments || 'N/A',
                    note: note || ''
                }
            })
        });

        if (!response.ok) {
            const errData = await response.json();
            console.error('EmailJS Error:', errData);
            return res.status(500).json({ error: 'Failed to send email via provider' });
        }

        res.json({ message: 'Email sent successfully' });
    } catch (err) {
        console.error('Email Send Error:', err);
        res.status(500).json({ error: 'Server error sending email' });
    }
});

app.use(express.static(path.join(__dirname, 'public')));

// [v1.1] unknown /api/* paths return JSON (not the static 404 HTML),
// so the frontend fetch handlers always get parseable error bodies
app.use('/api', function(req, res) {
    res.status(404).json({ error: 'Not found' });
});

var PORT = process.env.PORT || 10000;
app.listen(PORT, async function() {
    console.log('Maya app running on port ' + PORT);
    await seedAdmin();
});
