const test = require('node:test');
const assert = require('node:assert');
const serverApp = require('../src/server');

test('Server API & Security Headers Test Suite', async (t) => {
    let server;
    const port = 3099;

    await t.test('Start ephemeral server', async () => {
        await new Promise((resolve) => {
            server = serverApp.listen(port, resolve);
        });
    });

    await t.test('Health endpoint returns 200 UP', async () => {
        const res = await fetch(`http://localhost:${port}/health`);
        assert.strictEqual(res.status, 200);
        const data = await res.json();
        assert.strictEqual(data.status, 'UP');
        assert.strictEqual(data.service, 'devsecops-calculator-service');
    });

    await t.test('API calculate endpoint handles addition', async () => {
        const res = await fetch(`http://localhost:${port}/api/calculate`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ op: 'add', a: 15, b: 27 })
        });
        assert.strictEqual(res.status, 200);
        const data = await res.json();
        assert.strictEqual(data.result, 42);
    });

    await t.test('Security Gate Headers Enforcement Verification', async () => {
        const res = await fetch(`http://localhost:${port}/`);
        
        // When Security Gate is enabled (Helmet active):
        const csp = res.headers.get('content-security-policy');
        const frameOptions = res.headers.get('x-frame-options');
        const contentTypeOptions = res.headers.get('x-content-type-options');
        const poweredBy = res.headers.get('x-powered-by');

        assert.ok(csp !== null, 'Content-Security-Policy must be enforced by Security Gate');
        assert.strictEqual(frameOptions, 'DENY', 'X-Frame-Options must be DENY');
        assert.strictEqual(contentTypeOptions, 'nosniff', 'X-Content-Type-Options must be nosniff');
        assert.strictEqual(poweredBy, null, 'X-Powered-By header must be masked to prevent server leakage');
    });

    await t.test('Shutdown server', async () => {
        await new Promise((resolve) => {
            server.close(resolve);
        });
    });
});
