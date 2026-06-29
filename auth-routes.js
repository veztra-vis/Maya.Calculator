const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const USERS_FILE = path.join(__dirname, 'users.json');

function readUsers() {
    try {
        if (!fs.existsSync(USERS_FILE)) {
            const seed = [{
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
    } catch (e) {
        return [];
    }
}

function writeUsers(users) {
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

function generateToken(user) {
    const payload = JSON.stringify({
        id: user.employeeId,
        name: user.fullName,
        role: user.role,
        exp: Date.now() + (12 * 60 * 60 * 1000)
    });
    const cipher = crypto.createCipheriv('aes-256-cbc',
        crypto.createHash('sha256').update('maya-secret-salt-2025').digest(),
        Buffer.alloc(16, 'maya-calculator-iv')
    );
    let token = cipher.update(payload, 'utf8', 'hex');
    token += cipher.final('hex');
    return token;
}

function verifyToken(token) {
    try {
        const decipher = crypto.createDecipheriv('aes-256-cbc',
            crypto.createHash('sha256').update('maya-secret-salt-2025').digest(),
            Buffer.alloc(16, 'maya-calculator-iv')
        );
        let payload = decipher.update(token, 'hex', 'utf8');
        payload += decipher.final('utf8');
        const data = JSON.parse(payload);
        if (data.exp < Date.now()) return null;
        return data;
    } catch (e) {
        return null;
    }
}

function authMiddleware(req, res, next) {
    const token = req.headers['x-maya-token'] || req.query.token;
    if (!token) return res.status(401).json({ error: 'No token provided' });
    const user = verifyToken(token);
    if (!user) return res.status(401).json({ error: 'Invalid or expired token' });
    req.user = user;
    next();
}

function setupAuthRoutes(app) {

    // Serve login page at root
    app.get('/', (req, res) => {
        res.sendFile(path.join(__dirname, 'public', 'login.html'));
    });

    // Serve dashboard at /app
    app.get('/app', (req, res) => {
        res.sendFile(path.join(__dirname, 'public', 'index.html'));
    });

    // LOGIN
    app.post('/api/auth/login', (req, res) => {
        const { employeeId, password } = req.body;
        if (!employeeId || !password) {
            return res.status(400).json({ error: 'Employee ID and password are required' });
        }
        const users = readUsers();
        const user = users.find(u => u.employeeId === employeeId && u.password === password);
        if (!user) {
            return res.status(401).json({ error: 'Invalid Employee ID or Password' });
        }
        const token = generateToken(user);
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
    app.get('/api/auth/verify', authMiddleware, (req, res) => {
        res.json({ valid: true, user: req.user });
    });

    // GET ALL USERS
    app.get('/api/auth/users', authMiddleware, (req, res) => {
        const users = readUsers();
        const safe = users.map(u => ({
            id: u.id,
            employeeId: u.employeeId,
            fullName: u.fullName,
            role: u.role,
            createdAt: u.createdAt
        }));
        res.json(safe);
    });

    // CREATE USER
    app.post('/api/auth/users', authMiddleware, (req, res) => {
        const creatorRole = req.user.role;
        const allowed = ['ADMIN', 'TEAM LEADER', 'OPERATIONS MANAGER', 'CLIENT'];
        if (allowed.indexOf(creatorRole) === -1) {
            return res.status(403).json({ error: 'Not authorized to create accounts' });
        }

        const { fullName, employeeId, password, role } = req.body;
        if (!fullName || !employeeId || !password || !role) {
            return res.status(400).json({ error: 'All fields are required' });
        }
        if (password.length < 6) {
            return res.status(400).json({ error: 'Password must be at least 6 characters' });
        }
        if (role === 'ADMIN' && creatorRole !== 'ADMIN') {
            return res.status(403).json({ error: 'Only ADMIN can create ADMIN accounts' });
        }

        const users = readUsers();
        if (users.find(u => u.employeeId === employeeId)) {
            return res.status(409).json({ error: 'Employee ID already exists' });
        }

        const newUser = {
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
    app.delete('/api/auth/users/:employeeId', authMiddleware, (req, res) => {
        if (req.user.role !== 'ADMIN') {
            return res.status(403).json({ error: 'Only ADMIN can delete accounts' });
        }
        const targetId = req.params.employeeId;
        if (targetId === req.user.id) {
            return res.status(400).json({ error: 'Cannot delete your own account' });
        }

        let users = readUsers();
        const before = users.length;
        users = users.filter(u => u.employeeId !== targetId);
        if (users.length === before) {
            return res.status(404).json({ error: 'User not found' });
        }
        writeUsers(users);
        res.json({ message: 'Account "' + targetId + '" deleted' });
    });

    // CHECK IF USER EXISTS
    app.post('/api/auth/check-user', (req, res) => {
        const { employeeId } = req.body;
        if (!employeeId) {
            return res.status(400).json({ error: 'Employee ID is required' });
        }
        const users = readUsers();
        const user = users.find(u => u.employeeId === employeeId);
        if (!user) {
            return res.status(404).json({ error: 'No account found with that Employee ID' });
        }
        res.json({ found: true, employeeId: user.employeeId, fullName: user.fullName });
    });

    // RESET PASSWORD
    app.post('/api/auth/reset-password', (req, res) => {
        const { employeeId, newPassword } = req.body;
        if (!employeeId || !newPassword) {
            return res.status(400).json({ error: 'Employee ID and new password are required' });
        }
        if (newPassword.length < 6) {
            return res.status(400).json({ error: 'Password must be at least 6 characters' });
        }

        const users = readUsers();
        const user = users.find(u => u.employeeId === employeeId);
        if (!user) {
            return res.status(404).json({ error: 'No account found with that Employee ID' });
        }

        user.password = newPassword;
        writeUsers(users);
        res.json({ message: 'Password updated successfully' });
    });
}

module.exports = { setupAuthRoutes, authMiddleware };
