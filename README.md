# Security Header Analyzer

A comprehensive, automated tool for analyzing HTTP security headers compliance against security best practices. Provides detailed scanning, reporting, and trend analysis for web application security.

## 🚀 Features

- **Comprehensive Security Header Analysis**: Checks 10+ critical security headers including CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
- **Intelligent Baseline Comparison**: Configurable security baseline with severity-based scoring
- **Cookie Security Validation**: Analyzes HttpOnly, Secure, and SameSite flags
- **Automated Reporting**: Generates detailed Markdown reports with visual indicators
- **Trend Analysis**: Compare scans over time to track security posture improvements
- **CI/CD Ready**: GitHub Actions workflow for automated scanning
- **Customizable Baseline**: Adjust security requirements to match your organization's policies

## 📋 Supported Security Headers

| Header | Importance | Checks Performed |
|--------|------------|------------------|
| `Strict-Transport-Security` | Critical | Max-age, includeSubDomains, preload |
| `X-Frame-Options` | Critical | DENY, SAMEORIGIN values |
| `X-Content-Type-Options` | Critical | nosniff validation |
| `Referrer-Policy` | Critical | Allowed referrer policies |
| `Content-Security-Policy` | Recommended | Presence and configuration |
| `Permissions-Policy` | Recommended | Feature restrictions |
| `X-XSS-Protection` | Optional | Legacy XSS protection |
| `Set-Cookie` | Critical | HttpOnly, Secure, SameSite flags |

## 🛠️ Quick Start

### 1. Create a virtual environment and install dependencies:

```bash

# Create virtual environment
python -m venv .venv

# Activate virtual environment
# On Linux/Mac:
source .venv/bin/activate
# On Windows:
.venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
