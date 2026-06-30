console.log('=== SERVER VERSION: DATA-API ===');
const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch');
const path = require('path');
const crypto = require('crypto');

const app = express();
app.use(cors());
app.use(express.json());

// ============================================================
// ATLAS DATA API (HTTPS — no MongoDB driver, no TLS issues)
// ============================================================
const DATA_API_URL = process.env.ATLAS_DATA_API_URL;
const DATA_API_KEY = process.env.ATLAS_DATA_API_KEY;
const DB_NAME = process.env.ATLAS_CLUSTER || 'maya-app';

async function atlas(action, collection, payload) {
    var res = await fetch(DATA_API_URL + '/action/' + action, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'api-key': DATA_API_KEY
        },
        body: JSON.stringify(Object.assign({
            dataSource: 'Cluster0',
            database: DB_NAME,
            collection: collection
        }, payload))
    });
    var json = await res.json();
    if (json.error) throw new Error(json.error);
    return json;
}

async function seedAdmin() {
    try {
        var result = await atlas('findOne', 'users', {
            filter: { employeeId: 'ancel' }
        });
        if (!result.document) {
            await atlas('insertOne', 'users', {
                document: {
                    id: 'USR001',
                    employeeId: 'ancel',
                    fullName: 'Ancel Claudio',
                    password: 'maya2026',
                    role: 'ADMIN',
                    createdAt: new Date().toISOString()
                }
            });
            console.log('Seed admin created');
        }
    } catch (e) {
        console.error('SEED FAILED:', e.message);
        process.exit(1);
    }
}

// ROLE HIERARCHY MAP
function getRoleLevel(role) {
    var levels = {
        'ADMIN': 6,
        'CLIENT': 5,
        'OPERATIONS MANAGER': 4,
        'TEAM LEADER': 3,
        'AGENT': 2,
        'TRAINING': 1
    };
    return levels[role] || 0;
}

function generateToken(user) {
    var payload = JSON.stringify({
        id: user.employeeId,
        name: user.fullName,
        role: user.role,
        exp: Date.now() + (12 * 60 * 60 * 1000)
    });
    var cipher = crypto.createCipheriv('aes-256-cbc',
        crypto.createHash('sha256').update('maya-secret-salt-2025').digest(),
        Buffer.alloc(16, 'maya-calculator-iv')
    );
    var token = cipher.update(payload, 'utf8', 'hex');
    token += cipher.final('hex');
    return token;
}

function verifyToken(token) {
    try {
        var decipher = crypto.createDecipheriv('aes-256-cbc',
            crypto.createHash('sha256').update('maya-secret-salt-2025').digest(),
            Buffer.alloc(16, 'maya-calculator-iv')
        );
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

app.get('/', function(req, res) {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/app', function(req, res) {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// LOGIN
app.post('/api/auth/login', async function(req, res) {
    var employeeId = (req.body.employeeId || '').toLowerCase();
    var password = req.body.password;
    if (!employeeId || !password) {
        return res.status(400).json({ error: 'Employee ID and password are required' });
    }
    try {
        var result = await atlas('findOne', 'users', {
            filter: { employeeId: employeeId }
        });
        var user = result.document;
        if (!user || user.password !== password) {
            return res.status(401).json({ error: 'Invalid Employee ID or Password' });
        }
        var token = generateToken(user);
        res.json({
            token: token,
            user: { employeeId: user.employeeId, fullName: user.fullName, role: user.role }
        });
    } catch (e) {
        console.error('Login error:', e.message);
        res.status(500).json({ error: 'Database error' });
    }
});

// VERIFY TOKEN
app.get('/api/auth/verify', authMiddleware, function(req, res) {
    res.json({ valid: true, user: req.user });
});

// GET ALL USERS
app.get('/api/auth/users', authMiddleware, async function(req, res) {
    if (getRoleLevel(req.user.role) < 3) {
        return res.status(403).json({ error: 'Not authorized to view accounts' });
    }
    try {
        var result = await atlas('find', 'users', { filter: {} });
        res.json(result.documents.map(function(u) {
            return { id: u.id, employeeId: u.employeeId, fullName: u.fullName, role: u.role, createdAt: u.createdAt };
        }));
    } catch (e) {
        console.error('Get users error:', e.message);
        res.status(500).json({ error: 'Database error' });
    }
});

// CREATE USER
app.post('/api/auth/users', authMiddleware, async function(req, res) {
    var creatorLevel = getRoleLevel(req.user.role);
    if (creatorLevel < 3) {
        return res.status(403).json({ error: 'Not authorized to create accounts' });
    }
    var fullName = req.body.fullName;
    var employeeId = (req.body.employeeId || '').toLowerCase();
    var password = req.body.password;
    var role = req.body.role;
    if (!fullName || !employeeId || !password || !role) {
        return res.status(400).json({ error: 'All fields are required' });
    }
    if (password.length < 6) {
        return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }
    if (getRoleLevel(role) >= creatorLevel) {
        return res.status(403).json({ error: 'Cannot create an account with equal or higher privileges than your own' });
    }
    try {
        var existing = await atlas('findOne', 'users', {
            filter: { employeeId: employeeId }
        });
        if (existing.document) {
            return res.status(409).json({ error: 'Employee ID already exists' });
        }
        var newUser = {
            id: 'USR' + Date.now().toString().slice(-6),
            employeeId: employeeId,
            fullName: fullName,
            password: password,
            role: role,
            createdAt: new Date().toISOString()
        };
        await atlas('insertOne', 'users', { document: newUser });
        res.status(201).json({
            message: 'Account created for ' + fullName,
            user: { id: newUser.id, employeeId: newUser.employeeId, fullName: newUser.fullName, role: newUser.role, createdAt: newUser.createdAt }
        });
    } catch (e) {
        console.error('Create user error:', e.message);
        res.status(500).json({ error: 'Database error' });
    }
});

// DELETE USER
app.delete('/api/auth/users/:employeeId', authMiddleware, async function(req, res) {
    var creatorLevel = getRoleLevel(req.user.role);
    if (creatorLevel < 3) {
        return res.status(403).json({ error: 'Not authorized to delete accounts' });
    }
    var targetId = req.params.employeeId.toLowerCase();
    if (targetId === req.user.id) {
        return res.status(400).json({ error: 'Cannot delete your own account' });
    }
    try {
        var targetResult = await atlas('findOne', 'users', {
            filter: { employeeId: targetId }
        });
        var targetUser = targetResult.document;
        if (!targetUser) {
            return res.status(404).json({ error: 'User not found' });
        }
        if (getRoleLevel(targetUser.role) >= creatorLevel) {
            return res.status(403).json({ error: 'Cannot delete an account with equal or higher privileges than your own' });
        }
        await atlas('deleteOne', 'users', {
            filter: { employeeId: targetId }
        });
        res.json({ message: 'Account "' + targetId + '" deleted' });
    } catch (e) {
        console.error('Delete user error:', e.message);
        res.status(500).json({ error: 'Database error' });
    }
});

// CHECK USER EXISTS
app.post('/api/auth/check-user', async function(req, res) {
    var employeeId = (req.body.employeeId || '').toLowerCase();
    if (!employeeId) {
        return res.status(400).json({ error: 'Employee ID is required' });
    }
    try {
        var result = await atlas('findOne', 'users', {
            filter: { employeeId: employeeId }
        });
        var user = result.document;
        if (!user) {
            return res.status(404).json({ error: 'No account found with that Employee ID' });
        }
        res.json({ found: true, employeeId: user.employeeId, fullName: user.fullName });
    } catch (e) {
        console.error('Check user error:', e.message);
        res.status(500).json({ error: 'Database error' });
    }
});

// RESET PASSWORD
app.post('/api/auth/reset-password', async function(req, res) {
    var employeeId = (req.body.employeeId || '').toLowerCase();
    var newPassword = req.body.newPassword;
    if (!employeeId || !newPassword) {
        return res.status(400).json({ error: 'Employee ID and new password are required' });
    }
    if (newPassword.length < 6) {
        return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }
    try {
        var result = await atlas('updateOne', 'users', {
            filter: { employeeId: employeeId },
            update: { $set: { password: newPassword } }
        });
        if (result.modifiedCount === 0) {
            return res.status(404).json({ error: 'No account found with that Employee ID' });
        }
        res.json({ message: 'Password updated successfully' });
    } catch (e) {
        console.error('Reset password error:', e.message);
        res.status(500).json({ error: 'Database error' });
    }
});

// AI CHAT PROXY
app.post('/api/chat', async function(req, res) {
    var authHeader = req.headers.authorization || '';
    var token = authHeader.replace('Bearer ', '').trim();
    if (token !== process.env.RENDER_AUTH_KEY) {
        return res.status(401).json({ error: { message: 'Please contact support.' } });
    }
    if (!process.env.GROQ_API_KEY) {
        return res.status(500).json({ error: { message: 'Please contact support.' } });
    }
    try {
        var response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + process.env.GROQ_API_KEY
            },
            body: JSON.stringify(req.body)
        });
        var data = await response.json();
        res.status(response.status).json(data);
    } catch (err) {
        console.error('Proxy error:', err.message);
        res.status(500).json({ error: { message: 'Proxy error: ' + err.message } });
    }
});

// HEALTH CHECK
app.get('/api/health', async function(req, res) {
    var dbStatus = 'disconnected';
    try {
        await atlas('findOne', 'users', { filter: { employeeId: '__health__' } });
        dbStatus = 'connected';
    } catch (e) {
        dbStatus = 'error: ' + e.message;
    }
    res.json({
        status: 'online',
        database: dbStatus,
        groqKeySet: !!process.env.GROQ_API_KEY,
        authKeySet: !!process.env.RENDER_AUTH_KEY
    });
});

app.use(express.static(path.join(__dirname, 'public')));

var PORT = process.env.PORT || 10000;
app.listen(PORT, async function() {
    console.log('===================================');
    console.log('Maya app running on port ' + PORT);
    console.log('===================================');
    await seedAdmin();
});
