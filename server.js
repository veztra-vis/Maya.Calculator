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

async function connectWithRetry(maxRetries) {
    var isAtlas = MONGO_URI.startsWith('mongodb+srv://');

    // Strip conflicting TLS params from URI so driver options take over cleanly
    var cleanUri = MONGO_URI.replace(/[?&](tls|ssl|tlsAllowInvalidCertificates|tlsCAFile)=[^&]*/gi, '');
    // If we stripped params but left a dangling ? or &, fix it
    cleanUri = cleanUri.replace(/\?&/, '?').replace(/[?&]$/, '');

    var attempts = [];

    // Strategy 1: Standard TLS with cert validation
    if (isAtlas) {
        attempts.push({
            name: 'TLS strict',
            options: {
                tls: true,
                tlsAllowInvalidCertificates: false,
                serverSelectionTimeoutMS: 8000,
                connectTimeoutMS: 8000,
                maxPoolSize: 10,
                retryWrites: false,
                directConnection: false
            }
        });
    }

    // Strategy 2: TLS with relaxed cert validation (common Render fix)
    if (isAtlas) {
        attempts.push({
            name: 'TLS relaxed',
            options: {
                tls: true,
                tlsAllowInvalidCertificates: true,
                serverSelectionTimeoutMS: 8000,
                connectTimeoutMS: 8000,
                maxPoolSize: 10,
                retryWrites: false,
                directConnection: false
            }
        });
    }

    // Strategy 3: No TLS (local fallback)
    if (!isAtlas) {
        attempts.push({
            name: 'No TLS (local)',
            options: {
                serverSelectionTimeoutMS: 5000,
                connectTimeoutMS: 5000
            }
        });
    }

    for (var a = 0; a < attempts.length; a++) {
        var strategy = attempts[a];
        for (var r = 0; r < maxRetries; r++) {
            try {
                console.log('MongoDB attempt [' + strategy.name + '] retry ' + (r + 1) + '/' + maxRetries);
                var client = new MongoClient(cleanUri, strategy.options);
                await client.connect();
                // Verify it actually works
                await client.db(DB_NAME).command({ ping: 1 });
                console.log('MongoDB connected via [' + strategy.name + ']');
                return client;
            } catch (e) {
                console.log('  Failed: ' + e.message.slice(0, 100));
                try { await client.close(); } catch (_) {}
                if (r < maxRetries - 1) {
                    await sleep(3000 * (r + 1)); // Backoff: 3s, 6s, 9s...
                }
            }
        }
    }

    throw new Error('All connection strategies failed after ' + maxRetries + ' retries each');
}

async function getDb() {
    if (!mongoClient) {
        if (!dbConnectionPromise) {
            dbConnectionPromise = connectWithRetry(3);
        }
        mongoClient = await dbConnectionPromise;
    }
    return mongoClient.db(DB_NAME);
}

// Graceful shutdown
process.on('SIGINT', async () => {
    if (mongoClient) {
        await mongoClient.close();
        console.log('MongoDB connection closed');
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
            console.log('Seed admin created in MongoDB');
        }
    } catch (e) {
        console.error('=====================================');
        console.error('MongoDB connection failed on startup');
        console.error('Error:', e.message);
        console.error('=====================================');
        console.error('Check these in Render:');
        console.error('1. MONGODB_URI env var is set correctly');
        console.error('2. IP is whitelisted in Atlas (use 0.0.0.0/0 for Render)');
        console.error('3. Database user credentials in URI are correct');
        console.error('4. Atlas free tier cluster may need manual wake-up');
        console.error('   Go to Atlas dashboard and click "Connect" to wake it');
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

// Serve login at root
app.get('/', function(req, res) {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Serve dashboard at /app
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
        const db = await getDb();
        var user = await db.collection('users').findOne({ employeeId: employeeId });
        if (!user || user.password !== password) {
            return res.status(401).json({ error: 'Invalid Employee ID or Password' });
        }
        var token = generateToken(user);
        res.json({
            token: token,
            user: {
                employeeId: user.employeeId,
                fullName: user.fullName,
                role: user.role
            }
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
        const db = await getDb();
        const users = await db.collection('users').find({}).toArray();
        var safe = users.map(function(u) {
            return {
                id: u.id,
                employeeId: u.employeeId,
                fullName: u.fullName,
                role: u.role,
                createdAt: u.createdAt
            };
        });
        res.json(safe);
    } catch (e) {
        console.error('Get users error:', e.message);
        res.status(500).json({ error: 'Database error' });
    }
});

// CREATE USER
app.post('/api/auth/users', authMiddleware, async function(req, res) {
    var creatorRole = req.user.role;
    var creatorLevel = getRoleLevel(creatorRole);
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

// DELETE USER
app.delete('/api/auth/users/:employeeId', authMiddleware, async function(req, res) {
    var creatorRole = req.user.role;
    var creatorLevel = getRoleLevel(creatorRole);
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

// CHECK USER EXISTS
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

// ============================================================
// AI CHAT PROXY
// ============================================================
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
        message: 'Maya API is running',
        database: dbStatus,
        groqKeySet: !!process.env.GROQ_API_KEY,
        authKeySet: !!process.env.RENDER_AUTH_KEY
    });
});

// STATIC FILES
app.use(express.static(path.join(__dirname, 'public')));

// START SERVER
var PORT = process.env.PORT || 10000;
app.listen(PORT, async function() {
    console.log('===================================');
    console.log('Maya app running on port ' + PORT);
    console.log('===================================');
    await seedAdmin();
});
