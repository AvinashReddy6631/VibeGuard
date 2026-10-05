# 🛡️ VibeGuard

**Lightweight security baseline and automated security auditing for AI-generated and vibe-coded applications.**

VibeGuard helps developers identify common security risks before deployment using automated security checks, a simple CLI, security scoring, and JSON reports.

> VibeGuard is a security baseline and auditing tool. It does not guarantee that an application is completely secure.

---

## 🚀 Why VibeGuard?

AI coding tools such as ChatGPT, Claude, Cursor, Gemini, Copilot, and other AI development tools make it possible to build applications extremely quickly.

But AI-generated code can also introduce security risks.

VibeGuard provides a quick security baseline before you deploy your application.

```bash
npx @avireddy2005/vibeguard scan .


🔍 Security Checks
VibeGuard currently provides 22 security checks:
1. Secret Exposure
2. Environment File Exposure
3. Dependency Vulnerabilities
4. CORS Configuration
5. Security Headers
6. Authentication Indicators
7. Authorization Indicators
8. Dangerous Code Execution
9. Cross-Site Scripting (XSS)
10. SQL Injection
11. Command Injection
12. Path Traversal
13. SSRF
14. Sensitive Configuration
15. Unsafe User Input
16. Error Information Exposure
17. Supply Chain Security
18. Open Redirect
19. Insecure Transport
20. Cookie Security
21. JWT Security
22. Security Logging


📦 Installation
Run directly with npx
npx @avireddy2005/vibeguard scan .

Install globally
npm install -g @avireddy2005/vibeguard

Then run:
vibeguard scan .



💻 Usage

Scan the current project:

npx @avireddy2005/vibeguard scan .

Scan another project:

npx @avireddy2005/vibeguard scan ./my-project

Show version:

npx @avireddy2005/vibeguard --version

Show help:

npx @avireddy2005/vibeguard --help

After global installation:
vibeguard --version

vibeguard scan .




📊 Example Output
🛡️ Starting VibeGuard...

Target: ./my-project
Files discovered: 42

==================================================
                 VIBEGUARD
           SECURITY AUDIT REPORT
==================================================

SUMMARY

Critical : 0
High     : 2
Medium   : 1
Low      : 1
Info     : 1

SECURITY SCORE

74 / 100

VibeGuard status: FAILED

Example finding:
[VG-SQL-001]
Potential SQL injection

File: server.js
Line: 25

Recommendation:
Use parameterized queries or prepared statements.

A clean project can produce:
Critical : 0
High     : 0
Medium   : 0
Low      : 1
Info     : 1

Score: 98 / 100

VibeGuard status: PASSED





📄 JSON Security Report
VibeGuard automatically generates:
vibeguard-report.json

The report contains:
- Project information
- Scan timestamp
- Files scanned
- Severity summary
- Security score
- Finding IDs
- Affected files
- Line numbers
- Descriptions
- Recommendations
Example:
{
  "tool": "VibeGuard",
  "version": "0.1.0",
  "summary": {
    "CRITICAL": 0,
    "HIGH": 3,
    "MEDIUM": 0,
    "LOW": 1,
    "INFO": 1
  },
  "score": 62
}

The generated report is ignored by Git by default.


⚙️ Configuration
Projects can provide a:
security.config.json

This allows configuration of:
- Enabled security checks
- Ignored directories
- Ignored files
- Severity thresholds
Example:
{
  "checks": {
    "secrets": true,
    "dependencies": true,
    "xss": true,
    "sqlInjection": true
  },
  "thresholds": {
    "maximumCritical": 0,
    "maximumHigh": 0,
    "maximumMedium": 5
  }
}




🔄 CI/CD
VibeGuard can be integrated into CI/CD pipelines.
Example GitHub Actions step:
- name: Run VibeGuard
  run: node security-check.js .

VibeGuard also includes automated regression tests and GitHub Actions workflows.




🧪 Development
Clone the repository:
git clone https://github.com/AvinashReddy6631/VibeGuard.git

Enter the project:
cd VibeGuard

Run automated tests:
node tests/run-tests.js

Run VibeGuard locally:
node security-check.js .

Run the CLI locally:
node bin/vibeguard.js --help




🏗️ Project Status
Current version: VibeGuard v0.1.0
Current capabilities:
- 22 security checks
- CLI interface
- Security scoring
- JSON security reports
- Public npm package
- Automated regression tests
- GitHub Actions integration
- Configurable security thresholds
npm Package
@avireddy2005/vibeguard






Install:
npm install -g @avireddy2005/vibeguard

Or use directly:
npx @avireddy2005/vibeguard scan .







⚠️ Security Disclaimer
VibeGuard is designed to provide a lightweight automated security baseline.
Automated scanning cannot identify every possible security vulnerability.
VibeGuard should not replace:
- Professional security testing
- Penetration testing
- Manual code review
- Threat modeling
- Secure development practices
- Dependency management
- Application-specific security assessments
Security findings should be reviewed before making deployment decisions.
📜 License
MIT License
Copyright (c) 2026 Avinash Reddy
```