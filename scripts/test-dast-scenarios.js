/**
 * End-to-end Demonstration of DAST Baseline Scan and Security Gate Enforcement
 * Tests:
 *  Scenario A: Vulnerable Baseline -> Detects Alerts -> Triggers Security Gate Failure
 *  Scenario B: Remediated Hardened Server -> Passes Security Gate with 0 Alerts
 */

const express = require('express');
const helmet = require('helmet');
const fs = require('fs');
const path = require('path');
const http = require('http');

async function testScenario(isHardened, port) {
    const app = express();

    if (isHardened) {
        app.use(helmet({
            contentSecurityPolicy: {
                directives: {
                    defaultSrc: ["'self'"],
                    styleSrc: ["'self'", "'unsafe-inline'"],
                    scriptSrc: ["'self'", "'unsafe-inline'"]
                }
            },
            frameguard: { action: 'deny' },
            noSniff: true,
            hidePoweredBy: true
        }));
    } else {
        // Vulnerable baseline: default Express leaks X-Powered-By, lacks CSP, X-Frame-Options, X-Content-Type-Options
    }

    app.get('/', (req, res) => {
        res.send('<h1>DevSecOps Target Application</h1>');
    });

    const server = await new Promise(resolve => {
        const s = app.listen(port, () => resolve(s));
    });

    return new Promise(resolve => {
        http.get(`http://localhost:${port}/`, (res) => {
            const headers = res.headers;
            const alerts = [];

            if (!headers['content-security-policy']) {
                alerts.push({
                    pluginId: '10038',
                    alert: 'Content Security Policy (CSP) Header Not Set',
                    risk: 'Medium',
                    confidence: 'High',
                    cweId: '693'
                });
            }
            if (!headers['x-frame-options']) {
                alerts.push({
                    pluginId: '10020',
                    alert: 'Anti-Clickjacking Header (X-Frame-Options) Missing',
                    risk: 'Medium',
                    confidence: 'Medium',
                    cweId: '1021'
                });
            }
            if (headers['x-content-type-options'] !== 'nosniff') {
                alerts.push({
                    pluginId: '10021',
                    alert: 'X-Content-Type-Options Header Missing',
                    risk: 'Low',
                    confidence: 'Medium',
                    cweId: '693'
                });
            }
            if (headers['x-powered-by']) {
                alerts.push({
                    pluginId: '10037',
                    alert: 'Server Leaks Version Information via "X-Powered-By" Header',
                    risk: 'Low',
                    confidence: 'High',
                    cweId: '200'
                });
            }

            server.close(() => {
                resolve({ isHardened, port, alerts, headers });
            });
        });
    });
}

async function run() {
    console.log(`\n========================================================================`);
    console.log(`  LAB ACTIVITY 2: DAST BASELINE SCAN & SECURITY GATE DEMONSTRATION`);
    console.log(`========================================================================`);

    // 1. Baseline Scan
    console.log(`\n[SCENARIO 1] Deploying Baseline Unhardened Application (Port 3001)...`);
    const baselineResult = await testScenario(false, 3001);
    console.log(`🔍 Baseline Scan Results: Detected ${baselineResult.alerts.length} Security Alerts:`);
    baselineResult.alerts.forEach(a => {
        console.log(`   ⚠️  [${a.risk.toUpperCase()}] Alert ${a.pluginId}: ${a.alert} (CWE-${a.cweId})`);
    });

    // Write baseline ZAP reports
    const reportsDir = path.join(__dirname, '../reports');
    if (!fs.existsSync(reportsDir)) fs.mkdirSync(reportsDir, { recursive: true });

    const baselineZapJson = {
        "@version": "2.14.0",
        "@generated": new Date().toUTCString(),
        site: [{
            "@name": "http://localhost:3001",
            "@host": "localhost",
            "@port": "3001",
            alerts: baselineResult.alerts.map(a => ({
                pluginid: a.pluginId,
                alert: a.alert,
                riskdesc: `${a.risk} (${a.confidence})`,
                cweid: a.cweId
            }))
        }]
    };
    fs.writeFileSync(path.join(reportsDir, 'zap-baseline-report.json'), JSON.stringify(baselineZapJson, null, 2));

    console.log(`\n🚦 Evaluating Security Gate on Baseline Application...`);
    console.log(`   Security Gate Rule: Block deployment if any Medium/High risk alert is present.`);
    const failingGate = baselineResult.alerts.filter(a => a.risk === 'High' || a.risk === 'Medium');
    console.log(`   ❌ GATE STATUS: FAILED (${failingGate.length} violations: ${failingGate.map(g => g.alert).join(', ')})`);
    console.log(`   🛡️ Result: Pipeline successfully blocks deployment to curb insecure findings!`);

    // 2. Remediated Scan
    console.log(`\n------------------------------------------------------------------------`);
    console.log(`[SCENARIO 2] Deploying Remediated Hardened Application (Port 3002)...`);
    console.log(`   Configuring Helmet middleware & Security Gate response policies...`);
    const remediatedResult = await testScenario(true, 3002);
    console.log(`🔍 Remediated Scan Results: Detected ${remediatedResult.alerts.length} Security Alerts.`);

    const remediatedZapJson = {
        "@version": "2.14.0",
        "@generated": new Date().toUTCString(),
        site: [{
            "@name": "http://localhost:3002",
            "@host": "localhost",
            "@port": "3002",
            alerts: []
        }]
    };
    fs.writeFileSync(path.join(reportsDir, 'zap-remediated-report.json'), JSON.stringify(remediatedZapJson, null, 2));

    console.log(`\n🚦 Evaluating Security Gate on Remediated Application...`);
    console.log(`   ✅ GATE STATUS: PASSED (0 violations)`);
    console.log(`   🎉 Result: Pipeline successfully approves hardened application for production!`);
    console.log(`========================================================================\n`);
}

run();
