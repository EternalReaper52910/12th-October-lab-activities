/**
 * OWASP ZAP Baseline DAST Scanner & Security Gate Validator
 * DevSecOps Lab Activity 2
 */

const fs = require('fs');
const path = require('path');
const http = require('http');

const TARGET_URL = process.env.TARGET_URL || 'http://localhost:3000';
const ENFORCE_SECURITY_GATE = process.env.ENFORCE_SECURITY_GATE === 'true';

async function scanEndpoint(url) {
    console.log(`\n========================================================================`);
    console.log(`  OWASP ZAP BASELINE DAST SCANNER`);
    console.log(`  Target: ${url}`);
    console.log(`  Security Gate Mode: ${ENFORCE_SECURITY_GATE ? 'ACTIVE ENFORCEMENT' : 'BASELINE AUDIT'}`);
    console.log(`========================================================================\n`);

    return new Promise((resolve, reject) => {
        http.get(url, (res) => {
            const headers = res.headers;
            let rawData = '';
            res.on('data', chunk => rawData += chunk);
            res.on('end', () => {
                const alerts = [];

                // Alert 10038: Content Security Policy (CSP) Header Not Set
                if (!headers['content-security-policy']) {
                    alerts.push({
                        pluginId: '10038',
                        alert: 'Content Security Policy (CSP) Header Not Set',
                        risk: 'Medium',
                        confidence: 'High',
                        cweId: '693',
                        wascId: '15',
                        description: 'Content Security Policy (CSP) is an added layer of security that helps detect and mitigate attacks such as Cross-Site Scripting (XSS) and data injection.',
                        solution: 'Ensure that your web server, application server, load balancer, etc. is configured to set Content Security Policy.',
                        evidence: headers['content-security-policy'] || 'Header missing',
                        gateAction: 'FAIL'
                    });
                }

                // Alert 10020: Anti-CSRF / Anti-Clickjacking Header (X-Frame-Options)
                const xFrame = headers['x-frame-options'];
                if (!xFrame || (xFrame.toUpperCase() !== 'DENY' && xFrame.toUpperCase() !== 'SAMEORIGIN')) {
                    alerts.push({
                        pluginId: '10020',
                        alert: 'Anti-Clickjacking Header (X-Frame-Options) Missing or Insecure',
                        risk: 'Medium',
                        confidence: 'Medium',
                        cweId: '1021',
                        wascId: '15',
                        description: 'The response does not include an X-Frame-Options header or CSP frame-ancestors directive to protect against Clickjacking attacks.',
                        solution: 'Configure the X-Frame-Options HTTP response header to DENY or SAMEORIGIN.',
                        evidence: xFrame || 'Header missing',
                        gateAction: 'FAIL'
                    });
                }

                // Alert 10021: X-Content-Type-Options Header Missing
                if (headers['x-content-type-options'] !== 'nosniff') {
                    alerts.push({
                        pluginId: '10021',
                        alert: 'X-Content-Type-Options Header Missing',
                        risk: 'Low',
                        confidence: 'Medium',
                        cweId: '693',
                        wascId: '12',
                        description: 'The Anti-MIME-Sniffing header X-Content-Type-Options was not set to "nosniff".',
                        solution: 'Ensure that the application/web server sets the X-Content-Type-Options header to "nosniff" on all responses.',
                        evidence: headers['x-content-type-options'] || 'Header missing',
                        gateAction: 'FAIL'
                    });
                }

                // Alert 10037: Server Leaks Information via "Server" / "X-Powered-By" HTTP response headers
                if (headers['x-powered-by'] || (headers['server'] && headers['server'].toLowerCase().includes('express'))) {
                    alerts.push({
                        pluginId: '10037',
                        alert: 'Server Leaks Version Information via "X-Powered-By" Header',
                        risk: 'Low',
                        confidence: 'High',
                        cweId: '200',
                        wascId: '13',
                        description: 'The web/application server discloses version or framework details via headers like X-Powered-By or Server.',
                        solution: 'Disable the X-Powered-By header (e.g. app.disable("x-powered-by") or helmet.hidePoweredBy()).',
                        evidence: headers['x-powered-by'] || headers['server'],
                        gateAction: 'FAIL'
                    });
                }

                // Alert 10096: Timestamp Disclosure - Unix (Informational)
                alerts.push({
                    pluginId: '10096',
                    alert: 'Timestamp Disclosure - HTTP Date Header',
                    risk: 'Informational',
                    confidence: 'Low',
                    cweId: '200',
                    wascId: '13',
                    description: 'A timestamp was disclosed in HTTP response headers.',
                    solution: 'Manually confirm whether timestamp disclosure poses an environment risk.',
                    evidence: headers['date'] || 'N/A',
                    gateAction: 'INFO'
                });

                resolve({ statusCode: res.statusCode, headers, alerts });
            });
        }).on('error', reject);
    });
}

function generateReports(scanResult, outputDir) {
    if (!fs.existsSync(outputDir)) {
        fs.mkdirSync(outputDir, { recursive: true });
    }

    const { alerts } = scanResult;

    // 1. Generate JSON Report matching OWASP ZAP Schema
    const zapJsonReport = {
        "@version": "2.14.0",
        "@generated": new Date().toUTCString(),
        site: [
            {
                "@name": TARGET_URL,
                "@host": "localhost",
                "@port": "3000",
                "@ssl": "false",
                alerts: alerts.map(a => ({
                    pluginid: a.pluginId,
                    alertRef: a.pluginId,
                    alert: a.alert,
                    name: a.alert,
                    riskcode: a.risk === 'High' ? '3' : a.risk === 'Medium' ? '2' : a.risk === 'Low' ? '1' : '0',
                    confidence: a.confidence,
                    riskdesc: `${a.risk} (${a.confidence})`,
                    desc: `<p>${a.description}</p>`,
                    instances: [{ uri: TARGET_URL, method: 'GET', evidence: a.evidence }],
                    solution: `<p>${a.solution}</p>`,
                    cweid: a.cweId,
                    wascid: a.wascId
                }))
            }
        ]
    };

    fs.writeFileSync(path.join(outputDir, 'zap-baseline-report.json'), JSON.stringify(zapJsonReport, null, 2));

    // 2. Generate Rich HTML Report
    const htmlReport = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>ZAP Scanning Report - Baseline Security Scan</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif; margin: 0; padding: 24px; background: #0f172a; color: #f1f5f9; }
        .container { max-width: 900px; margin: auto; background: #1e293b; border-radius: 8px; padding: 28px; border: 1px solid #334155; }
        h1 { color: #38bdf8; border-bottom: 2px solid #38bdf8; padding-bottom: 8px; margin-top: 0; }
        .meta { display: grid; grid-template-columns: repeat(2, 1fr); gap: 12px; margin-bottom: 24px; background: #0f172a; padding: 14px; border-radius: 6px; }
        .alert-card { border: 1px solid #475569; border-radius: 6px; padding: 16px; margin-bottom: 16px; background: #1e293b; }
        .risk-Medium { border-left: 6px solid #f59e0b; }
        .risk-Low { border-left: 6px solid #3b82f6; }
        .risk-Informational { border-left: 6px solid #64748b; }
        .risk-High { border-left: 6px solid #ef4444; }
        .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-weight: bold; font-size: 12px; }
        .badge-Medium { background: #f59e0b; color: #000; }
        .badge-Low { background: #3b82f6; color: #fff; }
        .badge-Informational { background: #64748b; color: #fff; }
        .evidence { background: #0f172a; padding: 8px; font-family: monospace; border-radius: 4px; word-break: break-all; }
        .gate-fail { color: #f87171; font-weight: bold; }
        .gate-pass { color: #4ade80; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <h1>OWASP ZAP Baseline Security Scan Report</h1>
        <div class="meta">
            <div><strong>Target:</strong> ${TARGET_URL}</div>
            <div><strong>Generated:</strong> ${new Date().toUTCString()}</div>
            <div><strong>Total Alerts:</strong> ${alerts.length}</div>
            <div><strong>Security Gate Status:</strong> ${alerts.filter(a => a.gateAction === 'FAIL').length > 0 ? '<span class="gate-fail">FAILED (Gate Triggered)</span>' : '<span class="gate-pass">PASSED</span>'}</div>
        </div>
        <h2>Identified Security Alerts (${alerts.length})</h2>
        ${alerts.map(a => `
        <div class="alert-card risk-${a.risk}">
            <div style="display:flex; justify-content:space-between; align-items:center;">
                <h3 style="margin:0 0 8px 0;">[Plugin ${a.pluginId}] ${a.alert}</h3>
                <span class="badge badge-${a.risk}">${a.risk} Risk</span>
            </div>
            <p><strong>CWE ID:</strong> ${a.cweId} | <strong>Confidence:</strong> ${a.confidence} | <strong>Security Gate Policy:</strong> ${a.gateAction === 'FAIL' ? '<span class="gate-fail">FAIL BUILD</span>' : 'INFO'}</p>
            <p><strong>Description:</strong> ${a.description}</p>
            <p><strong>Remediation / Solution:</strong> ${a.solution}</p>
            <p><strong>Evidence:</strong></p>
            <div class="evidence">${a.evidence}</div>
        </div>
        `).join('')}
    </div>
</body>
</html>`;

    fs.writeFileSync(path.join(outputDir, 'zap-baseline-report.html'), htmlReport);
    console.log(`✅ Reports generated successfully in ${outputDir}/:`);
    console.log(`   - zap-baseline-report.json`);
    console.log(`   - zap-baseline-report.html`);
}

async function run() {
    try {
        const scanResult = await scanEndpoint(TARGET_URL);
        const outputDir = path.join(__dirname, '../reports');
        generateReports(scanResult, outputDir);

        const failingAlerts = scanResult.alerts.filter(a => a.gateAction === 'FAIL');

        console.log(`\n========================================================================`);
        console.log(`  SECURITY GATE EVALUATION SUMMARY`);
        console.log(`========================================================================`);
        console.log(`Total Security Alerts Detected:    ${scanResult.alerts.length}`);
        console.log(`Security Gate Failing Violations:  ${failingAlerts.length}`);

        scanResult.alerts.forEach(a => {
            console.log(`  [${a.risk.toUpperCase()}] Plugin ${a.pluginId}: ${a.alert} -> Gate: ${a.gateAction}`);
        });

        if (ENFORCE_SECURITY_GATE && failingAlerts.length > 0) {
            console.error(`\n❌ SECURITY GATE FAILURE: ${failingAlerts.length} security alert(s) violate baseline gate policy!`);
            console.error(`Build pipeline blocked to curb future vulnerable deployments.\n`);
            process.exit(1);
        } else if (failingAlerts.length === 0) {
            console.log(`\n✅ SECURITY GATE PASSED: All baseline security checks satisfied!\n`);
            process.exit(0);
        } else {
            console.log(`\n⚠️  BASELINE SCAN COMPLETE: Security alerts identified. Security Gate ready for enforcement.\n`);
            process.exit(0);
        }
    } catch (err) {
        console.error('Scan failed to connect to target:', err.message);
        process.exit(2);
    }
}

run();
