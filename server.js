const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch');
const path = require('path');
const crypto = require('crypto');
const { MongoClient } = require('mongodb');

const app = express();

app.use(cors());
app.use(express.json());

// ============================================================
// MONGODB SETUP
// ============================================================
const MONGO_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017';
const DB_NAME = 'maya-app';
let mongoClient = null;
let dbConnectionPromise = null;

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

// Clean URI — remove any TLS/SSL query params so our driver options control it
function cleanUri(uri) {
    var cleaned = uri.replace(/[?&](tls|ssl|tlsAllowInvalidCertificates|tlsCAFile|retryWrites|w)=[^&]*/gi, '');
    cleaned = cleaned.replace(/\?&/, '?').replace(/[?&]$/, '');
    if (!cleaned.includes('?') && uri.includes('?')) {
        cleaned += '?';
    }
    return cleaned;
}

function isSecureConnection(uri) {
    return uri.startsWith('mongodb+srv://') || uri.includes('mongodb.net') || uri.includes('ssl=true') || uri.includes('tls=true');
}

async function connectWithRetry(maxRetries) {
    var secure = isSecureConnection(MONGO_URI);
    var baseUri = cleanUri(MONGO_URI);

    // Build strategies
    var strategies = [];

    if (secure) {
        strategies.push({
            name: 'TLS strict',
            options: {
                tls: true,
                serverSelectionTimeoutMS: 8000,
                connectTimeoutMS: 8000,
                maxPoolSize: 5
            }
        });
        strategies.push({
            name: 'TLS skip verify',
            options: {
                tls: true,
                tlsAllowInvalidCertificates: true,
                serverSelectionTimeoutMS: 8000,
                connectTimeoutMS: 8000,
                maxPoolSize: 5
            }
        });
    }

    strategies.push({
        name: 'No TLS',
        options: {
            serverSelectionTimeoutMS: 8000,
            connectTimeoutMS: 8000,
            maxPoolSize: 5
        }
    });

    for (var s = 0; s < strategies.length; s++) {
        var strat = strategies[s];
        for (var r = 0; r < maxRetries; r++) {
            var client;
            try {
                console.log('[' + strat.name + '] attempt ' + (r + 1) + '/' + maxRetries);
                client = new MongoClient(baseUri, strat.options);
                await client.connect();
                await client.db(DB_NAME).command({ ping: 1 });
                console.log('Connected via [' + strat.name + ']');
                return client;
            } catch (e) {
                var msg = e.message || '';
                console.log('  -> ' + msg.slice(0, 120));
                try { if (client) await client.close(); } catch (_) {}
                if (r < maxRetries - 1) await sleep(3000 * (r + 1));
            }
        }
    }

    throw new Error('All strategies exhausted');
}

async function getDb() {
    if (!mongoClient) {
        if (!dbConnectionPromise) {
            dbConnectionPromise = connectWithRetry(2);
        }
        mongoClient = await dbConnectionPromise;
    }
    return mongoClient.db(DB_NAME);
}

process.on('SIGINT', async () => {
    if (mongoClient) {
        try { await mongoClient.close(); } catch (_) {}
        console.log('MongoDB closed');
    }
    process.exit(0);
});

// Seed default admin on first run
async function seedAdmin() {
    try {
        const db = await getDb();
        const users = db.collection('users');
        const existing = await users.countDocuments();
        if (existing === 0) {
            await users.insertOne({
                id: 'USR001',
                employeeId: 'ancel',
                fullName: 'Ancel Claudio',
                password: 'maya2026',
                role: 'ADMIN',
                createdAt: new Date().toISOString()
            });
            console.log('Seed admin created');
        }
    } catch (e) {
        console.error('=====================================');
        console.error('MONGO FAILED: ' + e.message);
        console.error('=====================================');
        console.error('Fix: Change MONGODB_URI in Render to');
        console.error('the mongodb:// format (NOT mongodb+srv://)');
        console.error('Get it from Atlas > Connect > Drivers');
        console.error('=====================================');
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

app.post('/api/auth/login', async function(req, res) {
    var employeeId = (req.body.employeeId || '').toLowerCase();
    var password = req.body.password;
    if (!employeeId || !password) {
        return res.status(400).json({ error: 'Employee ID and password are required' });
    }
    try {
        const db = await getDb();
        var user = await db.collection('users').findOne({ employeeId: employeeId });
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

app.get('/api/auth/verify', authMiddleware, function(req, res) {
    res.json({ valid: true, user: req.user });
});

app.get('/api/auth/users', authMiddleware, async function(req, res) {
    if (getRoleLevel(req.user.role) < 3) {
        return res.status(403).json({ error: 'Not authorized to view accounts' });
    }
    try {
        const db = await getDb();
        const users = await db.collection('users').find({}).toArray();
        res.json(users.map(function(u) {
            return { id: u.id, employeeId: u.employeeId, fullName: u.fullName, role: u.role, createdAt: u.createdAt };
        }));
    } catch (e) {
        console.error('Get users error:', e.message);
        res.status(500).json({ error: 'Database error' });
    }
});

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
        const db = await getDb();
        var existing = await db.collection('users').findOne({ employeeId: employeeId });
        if (existing) {
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
        await db.collection('users').insertOne(newUser);
        res.status(201).json({
            message: 'Account created for ' + fullName,
            user: { id: newUser.id, employeeId: newUser.employeeId, fullName: newUser.fullName, role: newUser.role, createdAt: newUser.createdAt }
        });
    } catch (e) {
        console.error('Create user error:', e.message);
        res.status(500).json({ error: 'Database error' });
    }
});

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
        const db = await getDb();
        var targetUser = await db.collection('users').findOne({ employeeId: targetId });
        if (!targetUser) {
            return res.status(404).json({ error: 'User not found' });
        }
        if (getRoleLevel(targetUser.role) >= creatorLevel) {
            return res.status(403).json({ error: 'Cannot delete an account with equal or higher privileges than your own' });
        }
        await db.collection('users').deleteOne({ employeeId: targetId });
        res.json({ message: 'Account "' + targetId + '" deleted' });
    } catch (e) {
        console.error('Delete user error:', e.message);
        res.status(500).json({ error: 'Database error' });
    }
});

app.post('/api/auth/check-user', async function(req, res) {
    var employeeId = (req.body.employeeId || '').toLowerCase();
    if (!employeeId) {
        return res.status(400).json({ error: 'Employee ID is required' });
    }
    try {
        const db = await getDb();
        var user = await db.collection('users').findOne({ employeeId: employeeId });
        if (!user) {
            return res.status(404).json({ error: 'No account found with that Employee ID' });
        }
        res.json({ found: true, employeeId: user.employeeId, fullName: user.fullName });
    } catch (e) {
        console.error('Check user error:', e.message);
        res.status(500).json({ error: 'Database error' });
    }
});

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
        const db = await getDb();
        var result = await db.collection('users').updateOne(
            { employeeId: employeeId },
            { $set: { password: newPassword } }
        );
        if (result.matchedCount === 0) {
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
        const db = await getDb();
        await db.command({ ping: 1 });
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
