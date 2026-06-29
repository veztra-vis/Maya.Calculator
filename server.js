const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch');
const path = require('path');
const app = express();

app.use(cors());
app.use(express.json());

// Serve static files (logo.png, etc.) from the "public" folder
app.use(express.static(path.join(__dirname, 'public')));

// Serve the main HTML page
app.get('/', function(req, res) {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Health check — visit /api/health in browser to confirm server is alive
app.get('/api/health', function(req, res) {
    res.json({
        status: 'online',
        message: 'Maya API Proxy is running',
        groqKeySet: !!process.env.GROQ_API_KEY,
        authKeySet: !!process.env.RENDER_AUTH_KEY
    });
});

// The AI chat proxy endpoint
app.post('/api/chat', async function(req, res) {
    var authHeader = req.headers.authorization || '';
    var token = authHeader.replace('Bearer ', '').trim();

    if (token !== process.env.RENDER_AUTH_KEY) {
        return res.status(401).json({ error: { message: 'Unauthorized' } });
    }

    if (!process.env.GROQ_API_KEY) {
        return res.status(500).json({ error: { message: 'GROQ_API_KEY not set on server' } });
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

var PORT = process.env.PORT || 3000;
app.listen(PORT, function() {
    console.log('Maya app running on port ' + PORT);
});
