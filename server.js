const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const app = express();

app.use(cors());
app.use(express.json());

// ============================================================
// AUTH — all inline, no separate file needed
// ============================================================
const USERS_FILE = path.join(__dirname, 'users.json');

function readUsers() {
    try {
        if (!fs.existsSync(USERS_FILE)) {
            var seed = [{
                id: 'USR001',
                employeeId: 'ancel',
                fullName: 'Ancel Claudio',
                password: 'maya2026',
                role: 'ADMIN',
                createdAt: new Date().toISOString()
            }];
            fs.writeFileSync(USERS_FILE, JSON.stringify(seed, null, 2));
            return seed;
        }
        return JSON.parse(fs.readFileSync(USERS_FILE, 'utf-8'));
    } catch (e) { return []; }
}

function writeUsers(users) {
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

// ROLE HIERARCHY MAP
// Higher number = more power. 0 = No access.
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
app.post('/api/auth/login', function(req, res) {
    var employeeId = (req.body.employeeId || '').toLowerCase();
    var password = req.body.password;
    if (!employeeId || !password) {
        return res.status(400).json({ error: 'Employee ID and password are required' });
    }
    var users = readUsers();
    var user = null;
    for (var i = 0; i < users.length; i++) {
        if (users[i].employeeId === employeeId && users[i].password === password) {
            user = users[i]; break;
        }
    }
    if (!user) {
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
});

// VERIFY TOKEN
app.get('/api/auth/verify', authMiddleware, function(req, res) {
    res.json({ valid: true, user: req.user });
});

// GET ALL USERS
app.get('/api/auth/users', authMiddleware, function(req, res) {
    // Only roles Team Leader and above can view the user list
    if (getRoleLevel(req.user.role) < 3) {
        return res.status(403).json({ error: 'Not authorized to view accounts' });
    }
    var users = readUsers();
    var safe = [];
    for (var i = 0; i < users.length; i++) {
        safe.push({
            id: users[i].id,
            employeeId: users[i].employeeId,
            fullName: users[i].fullName,
            role: users[i].role,
            createdAt: users[i].createdAt
        });
    }
    res.json(safe);
});

// CREATE USER
app.post('/api/auth/users', authMiddleware, function(req, res) {
    var creatorRole = req.user.role;
    var creatorLevel = getRoleLevel(creatorRole);
    
    // Only Team Leader (3) and above can create accounts
    if (creatorLevel < 3) {
        return res.status(403).json({ error: 'Not authorized to create accounts' });
    }
    
    var fullName = req.body.fullName;
    var employeeId = req.body.employeeId;
    var password = req.body.password;
    var role = req.body.role;
    
    if (!fullName || !employeeId || !password || !role) {
        return res.status(400).json({ error: 'All fields are required' });
    }
    if (password.length < 6) {
        return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    // Hierarchy Enforcement: Cannot create an account with equal or higher role than yourself
    if (getRoleLevel(role) >= creatorLevel) {
        return res.status(403).json({ error: 'Cannot create an account with equal or higher privileges than your own' });
    }

    var users = readUsers();
    for (var i = 0; i < users.length; i++) {
        if (users[i].employeeId === employeeId.toLowerCase()) {
            return res.status(409).json({ error: 'Employee ID already exists' });
        }
    }
    var newUser = {
        id: 'USR' + String(users.length + 1).padStart(3, '0'),
        employeeId: employeeId.toLowerCase(),
        fullName: fullName,
        password: password,
        role: role,
        createdAt: new Date().toISOString()
    };
    users.push(newUser);
    writeUsers(users);
    res.status(201).json({
        message: 'Account created for ' + fullName,
        user: { id: newUser.id, employeeId: newUser.employeeId, fullName: newUser.fullName, role: newUser.role, createdAt: newUser.createdAt }
    });
});

// DELETE USER
app.delete('/api/auth/users/:employeeId', authMiddleware, function(req, res) {
    var creatorRole = req.user.role;
    var creatorLevel = getRoleLevel(creatorRole);
    
    // Only Team Leader (3) and above can delete accounts
    if (creatorLevel < 3) {
        return res.status(403).json({ error: 'Not authorized to delete accounts' });
    }
    
    var targetId = req.params.employeeId.toLowerCase();
    if (targetId === req.user.id) {
        return res.status(400).json({ error: 'Cannot delete your own account' });
    }
    
    var users = readUsers();
    var targetUser = null;
    for (var i = 0; i < users.length; i++) {
        if (users[i].employeeId === targetId) {
            targetUser = users[i];
            break;
        }
    }

    if (!targetUser) {
        return res.status(404).json({ error: 'User not found' });
    }

    // Hierarchy Enforcement: Cannot delete an account with equal or higher role than yourself
    if (getRoleLevel(targetUser.role) >= creatorLevel) {
        return res.status(403).json({ error: 'Cannot delete an account with equal or higher privileges than your own' });
    }

    var newUsers = users.filter(function(u) { return u.employeeId !== targetId; });
    writeUsers(newUsers);
    res.json({ message: 'Account "' + targetId + '" deleted' });
});

// CHECK USER EXISTS
app.post('/api/auth/check-user', function(req, res) {
    var employeeId = (req.body.employeeId || '').toLowerCase();
    if (!employeeId) {
        return res.status(400).json({ error: 'Employee ID is required' });
    }
    var users = readUsers();
    var user = users.find(function(u) { return u.employeeId === employeeId; });
    if (!user) {
        return res.status(404).json({ error: 'No account found with that Employee ID' });
    }
    res.json({ found: true, employeeId: user.employeeId, fullName: user.fullName });
});

// RESET PASSWORD
app.post('/api/auth/reset-password', function(req, res) {
    var employeeId = (req.body.employeeId || '').toLowerCase();
    var newPassword = req.body.newPassword;
    if (!employeeId || !newPassword) {
        return res.status(400).json({ error: 'Employee ID and new password are required' });
    }
    if (newPassword.length < 6) {
        return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }
    var users = readUsers();
    var user = users.find(function(u) { return u.employeeId === employeeId; });
    if (!user) {
        return res.status(404).json({ error: 'No account found with that Employee ID' });
    }
    user.password = newPassword;
    writeUsers(users);
    res.json({ message: 'Password updated successfully' });
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
app.get('/api/health', function(req, res) {
    res.json({
        status: 'online',
        message: 'Maya API is running',
        groqKeySet: !!process.env.GROQ_API_KEY,
        authKeySet: !!process.env.RENDER_AUTH_KEY
    });
});

// STATIC FILES
app.use(express.static(path.join(__dirname, 'public')));

// START SERVER
var PORT = process.env.PORT || 10000;
app.listen(PORT, function() {
    console.log('===================================');
    console.log('Maya app running on port ' + PORT);
    console.log('===================================');
});
