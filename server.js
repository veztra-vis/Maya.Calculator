const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch');
const path = require('path');
const app = express();

app.use(cors());
app.use(express.json());

// Serve everything in /public as static files
app.use(express.static(path.join(__dirname, 'public')));

// Health check — visit this in your browser to test if server is alive
app.get('/api/health', function(req, res) {
    res.json({
        status: 'online',
        message: 'Maya API Proxy is running',
        groqKeySet: !!process.env.GROQ_API_KEY,
        authKeySet: !!process.env.RENDER_AUTH_KEY,
        groqKeyPrefix: process.env.GROQ_API_KEY ? process.env.GROQ_API_KEY.substring(0, 6) + '...' : 'NOT SET'
    });
});

// The AI chat proxy endpoint
app.post('/api/chat', async function(req, res) {
    var authHeader = req.headers.authorization || '';
    var token = authHeader.replace('Bearer ', '').trim();

    if (token !== process.env.RENDER_AUTH_KEY) {
        return res.status(401).json({ error: { message: 'Unauthorized — API_KEY in HTML does not match RENDER_AUTH_KEY env var on server' } });
    }

    if (!process.env.GROQ_API_KEY) {
        return res.status(500).json({ error: { message: 'GROQ_API_KEY environment variable is not set on the server' } });
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

// All other routes serve index.html (so direct URL access works)
app.get('*', function(req, res) {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

var PORT = process.env.PORT || 10000;
app.listen(PORT, function() {
    console.log('===================================');
    console.log('Maya app running on port ' + PORT);
    console.log('GROQ_API_KEY set: ' + !!process.env.GROQ_API_KEY);
    console.log('RENDER_AUTH_KEY set: ' + !!process.env.RENDER_AUTH_KEY);
    console.log('===================================');
});
