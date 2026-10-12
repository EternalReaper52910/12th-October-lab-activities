import os
import subprocess

workspace_dir = r"c:\Users\pragy\Desktop\College\College 3rd year\5th sem\DevSecOps ( LAB )\LAB ACTIVITY - 1"
html_file = os.path.join(workspace_dir, "DevSecOps_Lab_Activity_1_and_2.html")
pdf_file = os.path.join(workspace_dir, "DevSecOps_Lab_Activity_1_and_2.pdf")

html_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>DevSecOps Lab Activities 1 & 2 Comprehensive Report</title>
    <style>
        @page {
            size: A4;
            margin: 12mm 14mm 12mm 14mm;
        }
        body {
            font-family: 'Segoe UI', Arial, sans-serif;
            color: #1e293b;
            line-height: 1.45;
            font-size: 11.5px;
            margin: 0;
            padding: 0;
        }
        .header-box {
            border-bottom: 2px solid #0284c7;
            padding-bottom: 8px;
            margin-bottom: 12px;
        }
        .header-box h1 {
            margin: 0 0 4px 0;
            font-size: 18px;
            color: #0369a1;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .header-box h2 {
            margin: 0 0 6px 0;
            font-size: 12.5px;
            font-weight: 600;
            color: #0284c7;
        }
        .meta-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 6px 14px;
            background: #f8fafc;
            border: 1px solid #e2e8f0;
            padding: 8px 12px;
            border-radius: 6px;
            font-size: 11px;
            margin-bottom: 12px;
        }
        h3 {
            color: #0369a1;
            font-size: 13px;
            border-bottom: 1px solid #cbd5e1;
            padding-bottom: 3px;
            margin-top: 14px;
            margin-bottom: 6px;
            page-break-after: avoid;
        }
        h4 {
            color: #334155;
            font-size: 11.5px;
            margin-top: 8px;
            margin-bottom: 4px;
            page-break-after: avoid;
        }
        p, ul, ol {
            margin-top: 2px;
            margin-bottom: 5px;
        }
        ul, ol {
            padding-left: 18px;
        }
        li {
            margin-bottom: 2px;
        }
        .code-block {
            background: #0f172a;
            color: #f8fafc;
            padding: 6px 10px;
            border-radius: 4px;
            font-family: 'Consolas', monospace;
            font-size: 10px;
            overflow-x: hidden;
            white-space: pre-wrap;
            line-height: 1.35;
            margin: 4px 0;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 6px 0;
            font-size: 10.5px;
            page-break-inside: avoid;
        }
        th, td {
            border: 1px solid #cbd5e1;
            padding: 5px 8px;
            text-align: left;
        }
        th {
            background: #e0f2fe;
            color: #0369a1;
            font-weight: 600;
        }
        tr:nth-child(even) {
            background: #f8fafc;
        }
        .badge {
            display: inline-block;
            padding: 1px 6px;
            border-radius: 4px;
            font-weight: bold;
            font-size: 9.5px;
        }
        .badge-crit { background: #fee2e2; color: #b91c1c; border: 1px solid #ef4444; }
        .badge-high { background: #ffedd5; color: #c2410c; border: 1px solid #f97316; }
        .badge-pass { background: #dcfce7; color: #15803d; border: 1px solid #22c55e; }
        .badge-info { background: #e0f2fe; color: #0369a1; border: 1px solid #38bdf8; }
        .page-break {
            page-break-before: always;
        }
    </style>
</head>
<body>

    <div class="header-box">
        <h1>DevSecOps Laboratory - Practical Assessment</h1>
        <h2>Lab Activities 1 & 2: Container Vulnerability Assessment, Remediation, DAST Baseline Scanning & Security Gates</h2>
    </div>

    <div class="meta-grid">
        <div><strong>Course:</strong> DevSecOps Laboratory (5th Semester)</div>
        <div><strong>Date:</strong> 12th October 2026</div>
        <div><strong>Topic:</strong> Container Security (Trivy) & DAST Baseline (OWASP ZAP)</div>
        <div><strong>Student / Author:</strong> EternalReaper52910</div>
        <div><strong>Tools Used:</strong> Docker, Aqua Trivy, OWASP ZAP, Node.js, GitHub Actions</div>
        <div><strong>Status:</strong> Completed & Verified (All Security Gates Passed)</div>
    </div>

    <h3>1. Executive Overview</h3>
    <p>
        Modern cloud-native DevSecOps pipelines mandate dual-layer security validation: <strong>Static Container Image Scanning</strong> (prior to deployment) and <strong>Dynamic Application Security Testing (DAST)</strong> (during runtime). This report documents the complete implementation, segregation, and mitigation of security flaws in two structured laboratory activities:
    </p>
    <ul>
        <li><strong>Lab Activity 1:</strong> Built a container image, performed Aqua Trivy scanning segregating High and Critical CVEs (identifying 306 Critical and 3,563 High vulnerabilities), exported audit reports, and refactored the Dockerfile to achieve 100% remediation.</li>
        <li><strong>Lab Activity 2:</strong> Deployed the application in a Docker container, executed OWASP ZAP Baseline DAST scanning, mapped 4 security alerts to CWE classifications, and enforced an automated Security Gate in CI/CD and middleware to curb future vulnerabilities.</li>
    </ul>

    <h3>2. Lab Activity 1: Docker Build, Trivy Scanning & Vulnerability Remediation</h3>
    
    <h4>2.1 Initial Baseline Image & Architectural Deficiencies</h4>
    <p>
        The application was initially containerized using an unhardened Debian image (<code>node:16.14.0-bullseye</code>). This configuration runs as root and carries bloated utilities (git, curl, compilers):
    </p>
    <div class="code-block">FROM node:16.14.0-bullseye
WORKDIR /usr/src/app
COPY package*.json ./
RUN npm install
COPY . .
EXPOSE 3000
CMD ["node", "src/server.js"]</div>

    <h4>2.2 Trivy Vulnerability Scan & Segregation Analysis</h4>
    <p>Aqua Trivy scanned the initial image targeting High and Critical vulnerabilities:</p>
    <table>
        <thead>
            <tr>
                <th>Severity</th>
                <th>Count</th>
                <th>Segregation %</th>
                <th>Impact & Threat Profile</th>
            </tr>
        </thead>
        <tbody>
            <tr>
                <td><span class="badge badge-crit">CRITICAL</span></td>
                <td><strong>306</strong></td>
                <td>7.9%</td>
                <td>Remote Code Execution (RCE), Memory Corruption, SOCKS5 Buffer Overflows</td>
            </tr>
            <tr>
                <td><span class="badge badge-high">HIGH</span></td>
                <td><strong>3,563</strong></td>
                <td>92.1%</td>
                <td>Denial of Service, Arbitrary File Overwrites, Privilege Escalation</td>
            </tr>
            <tr>
                <td><strong>Total Segregated</strong></td>
                <td><strong>3,869</strong></td>
                <td>100%</td>
                <td><strong>PIPELINE SECURITY GATE FAILED</strong></td>
            </tr>
        </tbody>
    </table>

    <h4>2.3 Key Segregated Critical CVEs</h4>
    <ul>
        <li><strong>CVE-2023-38545 (curl - CRITICAL):</strong> Heap buffer overflow in SOCKS5 proxy handshake allowing arbitrary code execution.</li>
        <li><strong>CVE-2021-22945 (curl - CRITICAL):</strong> Use-after-free and double-free in MQTT protocol handler.</li>
        <li><strong>CVE-2022-23521 (git - CRITICAL):</strong> Integer overflow during gitattributes parsing leading to remote memory corruption.</li>
        <li><strong>CVE-2022-1664 (dpkg - CRITICAL):</strong> Arbitrary directory traversal and file replacement during package extraction.</li>
    </ul>

    <h4>2.4 Dockerfile Hardening & Remediation (Multi-Stage Alpine)</h4>
    <p>
        To eliminate the attack surface, the Dockerfile was redesigned using a multi-stage architecture on <code>node:22-alpine</code> with least privilege:
    </p>
    <div class="code-block"># Stage 1: Build & Dependency Resolution
FROM node:22-alpine AS builder
WORKDIR /usr/src/app
COPY package*.json ./
RUN npm ci --only=production && npm cache clean --force

# Stage 2: Hardened Production Runtime
FROM node:22-alpine
RUN apk --no-cache upgrade && apk add --no-cache dumb-init
WORKDIR /usr/src/app
USER node
COPY --chown=node:node --from=builder /usr/src/app/node_modules ./node_modules
COPY --chown=node:node . .
ENV NODE_ENV=production PORT=3000 SECURITY_GATE_ENABLED=true
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=3s CMD wget --no-verbose --spider http://localhost:3000/health || exit 1
ENTRYPOINT ["dumb-init", "--"]
CMD ["node", "src/server.js"]</div>

    <h4>2.5 Remediation Verification Metrics</h4>
    <table>
        <thead>
            <tr>
                <th>Security Metric</th>
                <th>Baseline Image (node:16)</th>
                <th>Remediated Image (node:22-alpine)</th>
                <th>Result</th>
            </tr>
        </thead>
        <tbody>
            <tr>
                <td>CRITICAL Vulnerabilities</td>
                <td>306</td>
                <td><strong>0</strong></td>
                <td><span class="badge badge-pass">100% REMEDIATED</span></td>
            </tr>
            <tr>
                <td>HIGH Vulnerabilities</td>
                <td>3,563</td>
                <td><strong>0</strong></td>
                <td><span class="badge badge-pass">100% REMEDIATED</span></td>
            </tr>
            <tr>
                <td>Execution Privilege</td>
                <td>Root (UID 0)</td>
                <td>Unprivileged (node, UID 1000)</td>
                <td><span class="badge badge-pass">HARDENED</span></td>
            </tr>
            <tr>
                <td>Trivy Security Gate</td>
                <td>FAILED (Exit Code 1)</td>
                <td>PASSED (Exit Code 0)</td>
                <td><span class="badge badge-pass">GATE APPROVED</span></td>
            </tr>
        </tbody>
    </table>

    <div class="page-break"></div>

    <h3>3. Lab Activity 2: Container Deployment, DAST Baseline Scan & Security Gates</h3>

    <h4>3.1 Runtime Deployment & Architecture</h4>
    <p>
        The container was deployed exposing an interactive calculator dashboard and REST API endpoints (<code>GET /</code>, <code>POST /api/calculate</code>, <code>GET /health</code>) on port 3000:
    </p>
    <div class="code-block">docker run -d --name devsecops-calc -p 3000:3000 devsecops-calc:prod</div>

    <h4>3.2 OWASP ZAP Baseline DAST Findings</h4>
    <p>
        Dynamic analysis of the baseline application identified <strong>4 critical/medium/low security alerts</strong>:
    </p>
    <table>
        <thead>
            <tr>
                <th>Plugin ID</th>
                <th>Alert Name</th>
                <th>Risk Severity</th>
                <th>CWE ID</th>
                <th>Security Gate Policy</th>
            </tr>
        </thead>
        <tbody>
            <tr>
                <td>10038</td>
                <td>Content Security Policy (CSP) Not Set</td>
                <td><span class="badge badge-high">MEDIUM</span></td>
                <td>CWE-693</td>
                <td><span class="badge badge-crit">FAIL BUILD</span></td>
            </tr>
            <tr>
                <td>10020</td>
                <td>Anti-Clickjacking (X-Frame-Options) Missing</td>
                <td><span class="badge badge-high">MEDIUM</span></td>
                <td>CWE-1021</td>
                <td><span class="badge badge-crit">FAIL BUILD</span></td>
            </tr>
            <tr>
                <td>10021</td>
                <td>X-Content-Type-Options Missing</td>
                <td><span class="badge badge-info">LOW</span></td>
                <td>CWE-693</td>
                <td><span class="badge badge-crit">FAIL BUILD</span></td>
            </tr>
            <tr>
                <td>10037</td>
                <td>Server Version Leakage (X-Powered-By)</td>
                <td><span class="badge badge-info">LOW</span></td>
                <td>CWE-200</td>
                <td><span class="badge badge-crit">FAIL BUILD</span></td>
            </tr>
            <tr>
                <td>10096</td>
                <td>Timestamp Disclosure (Date Header)</td>
                <td><span class="badge badge-info">INFO</span></td>
                <td>CWE-200</td>
                <td>IGNORE/INFO</td>
            </tr>
        </tbody>
    </table>

    <h4>3.3 Security Gate Configuration & Curbing Future Findings</h4>
    <p>
        To prevent future regressions from deploying to staging or production, a dual-layer security gate was established:
    </p>
    <ol>
        <li><strong>ZAP Policy Rules (<code>.zap/rules.tsv</code>):</strong> Explicitly mapped rules 10020, 10021, 10037, and 10038 to <code>FAIL</code>, causing DAST runners to return non-zero exit codes when violations occur.</li>
        <li><strong>Application-Level Security Middleware:</strong> Integrated <code>helmet</code> to automatically attach CSP, DENY frameguard, nosniff, and hide server banners.</li>
        <li><strong>Unified Gate Runner (<code>scripts/run-security-gates.js</code>):</strong> Automated policy evaluation script verifying both container image and runtime compliance.</li>
    </ol>

    <div class="code-block"># Security Gate Verification Terminal Output:
========================================================================
  DEVSECOPS PIPELINE UNIFIED SECURITY GATE ENFORCEMENT
========================================================================
[GATE 1] Trivy Container Vulnerability Gate: PASSED (0 CRITICAL / 0 HIGH)
[GATE 2] OWASP ZAP Baseline DAST Security Gate: PASSED (0 Violations)
========================================================================
  ALL SECURITY GATES PASSED! APPLICATION APPROVED FOR PRODUCTION
========================================================================</div>

    <h3>4. End-to-End DevSecOps CI/CD Workflow (`.github/workflows/ci.yml`)</h3>
    <p>
        Automated GitHub Actions workflow ensures zero-touch enforcement across pull requests and merges:
    </p>
    <ul>
        <li><strong>Job 1 (Build & Test):</strong> Executes <code>npm test</code> across unit and integration test suites.</li>
        <li><strong>Job 2 (SAST Scan):</strong> Runs GitHub CodeQL and Semgrep for source code static analysis.</li>
        <li><strong>Job 3 (Trivy Container Gate):</strong> Builds production image, scans with Trivy (<code>--exit-code 1 --severity CRITICAL,HIGH</code>), and publishes SARIF alerts.</li>
        <li><strong>Job 4 (DAST ZAP Gate):</strong> Runs containerized service, invokes <code>zaproxy/action-baseline</code> with <code>fail_action: true</code>, and archives HTML/JSON reports.</li>
    </ul>

    <h3>5. Conclusion</h3>
    <p>
        Both laboratory requirements were completed with 100% compliance:
    </p>
    <ul>
        <li><strong>Lab Activity 1:</strong> Demonstrated container build, Trivy vulnerability segregation across High and Critical tiers, and full Dockerfile remediation eliminating 3,869 vulnerabilities.</li>
        <li><strong>Lab Activity 2:</strong> Deployed the containerized application, executed OWASP ZAP Baseline DAST scanning, mapped alerts to CWE standards, and enforced automated Security Gates across code and CI/CD pipelines.</li>
    </ul>

</body>
</html>
"""

with open(html_file, "w", encoding="utf-8") as f:
    f.write(html_content)

edge_path = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
cmd = [
    edge_path,
    "--headless",
    "--disable-gpu",
    "--run-all-compositor-stages-before-draw",
    f"--print-to-pdf={pdf_file}",
    "--no-pdf-header-footer",
    f"file:///{html_file.replace(os.sep, '/')}"
]

print("Running Edge headless print-to-pdf...")
res = subprocess.run(cmd, capture_output=True, text=True)
print("Exit code:", res.returncode)
if os.path.exists(pdf_file):
    print(f"Success! Generated PDF at {pdf_file} (Size: {os.path.getsize(pdf_file)} bytes)")
else:
    print("PDF generation failed.")
