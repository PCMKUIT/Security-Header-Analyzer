# Security Header Analyzer

Automated tool to check HTTP security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, cookie flags, etc.) for a list of target URLs.

## Features

- **Comprehensive Security Header Analysis**: Checks 10+ critical security headers
- **Baseline Comparison**: Compares against security best practices
- **Automated Reporting**: Generates detailed Markdown reports
- **CI/CD Integration**: GitHub Actions workflow for automated scanning
- **Cookie Security Analysis**: Validates HttpOnly, Secure, and SameSite flags


## Quick start


1. Create a virtual environment and install dependencies:


```bash
python -m venv .venv
source .venv/bin/activate # or .venv\Scripts\activate on Windows
pip install -r requirements.txt
