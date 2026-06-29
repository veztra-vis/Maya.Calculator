const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch');
const path = require('path');
const { setupAuthRoutes } = require('./auth-routes.js');

const app = express();

app.use(cors());
app.use(express.json());

// Serve static files from /public
app.use(express.static(path.join(__dirname, 'public')));

// ============================================================
// AUTH ROUTES (login, users, etc.)
// ============================================================
setupAuthRoutes(app);

// ============================================================
// AI CHAT PROXY
// ============================================================
app.post('/api/chat', async function(req, res) {
    var authHeader = req.headers.authorization || '';
    var token = authHeader.replace('Bearer ', '').trim();

    if (token !== process.env.RENDER_AUTH_KEY) {
        return res.status(401).json({ 
            error: { message: 'Unauthorized — API_KEY mismatch' } 
        });
    }

    if (!process.env.GROQ_API_KEY) {
        return res.status(500).json({ 
            error: { message: 'GROQ_API_KEY not set on server' } 
        });
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

// ============================================================
// HEALTH CHECK
// ============================================================
app.get('/api/health', function(req, res) {
    res.json({
        status: 'online',
        message: 'Maya API is running',
        groqKeySet: !!process.env.GROQ_API_KEY,
        authKeySet: !!process.env.RENDER_AUTH_KEY
    });
});

// ============================================================
// START SERVER
// ============================================================
var PORT = process.env.PORT || 10000;
app.listen(PORT, function() {
    console.log('===================================');
    console.log('Maya app running on port ' + PORT);
    console.log('Login:  http://localhost:' + PORT + '/');
    console.log('Dashboard: http://localhost:' + PORT + '/app');
    console.log('GROQ_API_KEY set: ' + !!process.env.GROQ_API_KEY);
    console.log('RENDER_AUTH_KEY set: ' + !!process.env.RENDER_AUTH_KEY);
    console.log('===================================');
});
