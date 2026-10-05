# 🛡️ VibeGuard

VibeGuard is a lightweight security baseline and automated
security auditing toolkit for AI-generated and vibe-coded
web applications.

## Why VibeGuard?

AI coding tools allow developers to build applications very
quickly.

However, generated applications may contain security risks
such as:

- exposed secrets
- environment files
- permissive CORS
- missing security headers
- vulnerable dependencies
- authentication risks
- authorization risks

VibeGuard helps developers identify potential security issues
before deployment.

---

## Current Checks

VibeGuard currently checks for:

- Secret exposure
- Environment files
- Dependency vulnerabilities
- Permissive CORS
- Security headers
- Authentication indicators
- Authorization-sensitive code

---

## Usage

Place the VibeGuard files inside your project.

Run:

```bash
node security-check.js