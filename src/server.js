const express = require('express');
const helmet = require('helmet');
const { add, subtract, multiply, divide } = require('./calculator');

const app = express();
const PORT = process.env.PORT || 3000;
const SECURITY_GATE_ENABLED = process.env.SECURITY_GATE_ENABLED !== 'false';

// Security Gate Configuration
if (SECURITY_GATE_ENABLED) {
    // Hardened Security Gate Headers via Helmet
    app.use(helmet({
        contentSecurityPolicy: {
            directives: {
                defaultSrc: ["'self'"],
                styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
                fontSrc: ["'self'", "https://fonts.gstatic.com"],
                scriptSrc: ["'self'", "'unsafe-inline'"],
                imgSrc: ["'self'", "data:"]
            }
        },
        frameguard: { action: 'deny' },
        noSniff: true,
        hidePoweredBy: true,
        xssFilter: true,
        hsts: {
            maxAge: 31536000,
            includeSubDomains: true,
            preload: true
        }
    }));
} else {
    // Baseline / Vulnerable Mode (for demonstrating DAST baseline alerts):
    // Leaves default Express headers, missing CSP, missing X-Frame-Options, exposing X-Powered-By
    console.warn("⚠️  WARNING: Running in INSECURE mode (Security Gate disabled) for DAST baseline detection.");
}

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Health Check Endpoint (used by Docker and Orchestration)
app.get('/health', (req, res) => {
    res.status(200).json({
        status: 'UP',
        timestamp: new Date().toISOString(),
        service: 'devsecops-calculator-service',
        securityGateActive: SECURITY_GATE_ENABLED
    });
});

// Calculator REST API Endpoint
app.post('/api/calculate', (req, res) => {
    try {
        const { op, a, b } = req.body;
        const numA = parseFloat(a);
        const numB = parseFloat(b);

        if (isNaN(numA) || isNaN(numB)) {
            return res.status(400).json({ error: 'Operands must be valid numbers' });
        }

        let result;
        switch (op) {
            case 'add':
                result = add(numA, numB);
                break;
            case 'subtract':
                result = subtract(numA, numB);
                break;
            case 'multiply':
                result = multiply(numA, numB);
                break;
            case 'divide':
                result = divide(numA, numB);
                break;
            default:
                return res.status(400).json({ error: 'Invalid operation. Use add, subtract, multiply, or divide.' });
        }

        return res.json({ success: true, operation: op, a: numA, b: numB, result });
    } catch (err) {
        return res.status(400).json({ error: err.message });
    }
});

// Interactive Web UI Dashboard
app.get('/', (req, res) => {
    res.setHeader('Content-Type', 'text/html');
    res.send(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DevSecOps Lab Application - Secure Calculator</title>
    <style>
        :root {
            --bg-color: #0f172a;
            --card-bg: #1e293b;
            --accent-color: #38bdf8;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --success-color: #22c55e;
            --border-color: #334155;
        }
        body {
            margin: 0;
            padding: 0;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-main);
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }
        .container {
            width: 100%;
            max-width: 480px;
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 2rem;
            box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.4);
        }
        .header {
            text-align: center;
            margin-bottom: 1.5rem;
        }
        .header h1 {
            font-size: 1.5rem;
            margin: 0 0 0.5rem 0;
            color: var(--accent-color);
        }
        .badge {
            display: inline-block;
            font-size: 0.75rem;
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            background: ${SECURITY_GATE_ENABLED ? 'rgba(34, 197, 94, 0.2)' : 'rgba(239, 68, 68, 0.2)'};
            color: ${SECURITY_GATE_ENABLED ? '#4ade80' : '#f87171'};
            border: 1px solid ${SECURITY_GATE_ENABLED ? '#22c55e' : '#ef4444'};
            font-weight: 600;
        }
        .form-group {
            margin-bottom: 1rem;
        }
        label {
            display: block;
            margin-bottom: 0.5rem;
            font-size: 0.875rem;
            color: var(--text-muted);
        }
        input, select {
            width: 100%;
            padding: 0.75rem;
            border-radius: 6px;
            border: 1px solid var(--border-color);
            background: #0f172a;
            color: var(--text-main);
            box-sizing: border-box;
            font-size: 1rem;
        }
        button {
            width: 100%;
            padding: 0.85rem;
            border-radius: 6px;
            border: none;
            background: var(--accent-color);
            color: #0f172a;
            font-weight: 700;
            font-size: 1rem;
            cursor: pointer;
            transition: opacity 0.2s;
            margin-top: 0.5rem;
        }
        button:hover {
            opacity: 0.9;
        }
        .result-box {
            margin-top: 1.5rem;
            padding: 1rem;
            border-radius: 6px;
            background: #0f172a;
            border: 1px solid var(--border-color);
            text-align: center;
            font-size: 1.1rem;
            min-height: 24px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>DevSecOps Calculator</h1>
            <span class="badge">Security Gate: ${SECURITY_GATE_ENABLED ? 'ENFORCED (SECURE)' : 'BYPASS (DAST DETECT)'}</span>
        </div>
        <form id="calc-form">
            <div class="form-group">
                <label for="numA">Operand A</label>
                <input type="number" step="any" id="numA" required value="42">
            </div>
            <div class="form-group">
                <label for="operation">Operation</label>
                <select id="operation">
                    <option value="add">Add (+)</option>
                    <option value="subtract">Subtract (-)</option>
                    <option value="multiply">Multiply (×)</option>
                    <option value="divide">Divide (÷)</option>
                </select>
            </div>
            <div class="form-group">
                <label for="numB">Operand B</label>
                <input type="number" step="any" id="numB" required value="7">
            </div>
            <button type="submit">Calculate</button>
        </form>
        <div class="result-box" id="result-display">Result: 49</div>
    </div>
    <script>
        document.getElementById('calc-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            const a = document.getElementById('numA').value;
            const b = document.getElementById('numB').value;
            const op = document.getElementById('operation').value;
            const display = document.getElementById('result-display');
            
            try {
                const res = await fetch('/api/calculate', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ a, b, op })
                });
                const data = await res.json();
                if (data.success) {
                    display.innerText = 'Result: ' + data.result;
                    display.style.color = '#38bdf8';
                } else {
                    display.innerText = 'Error: ' + data.error;
                    display.style.color = '#ef4444';
                }
            } catch (err) {
                display.innerText = 'Network Error';
                display.style.color = '#ef4444';
            }
        });
    </script>
</body>
</html>`);
});

if (require.main === module) {
    app.listen(PORT, () => {
        console.log(`🚀 DevSecOps Application running at http://localhost:${PORT}`);
        console.log(`🛡️  Security Gate Status: ${SECURITY_GATE_ENABLED ? 'ENABLED (Hardened)' : 'DISABLED (Baseline Mode)'}`);
    });
}

module.exports = app;
