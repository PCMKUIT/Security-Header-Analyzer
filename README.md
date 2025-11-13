# Security Header Analyzer


Automated tool to check HTTP security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, cookie flags, etc.) for a list of target URLs.


This repo provides:
- `header_checker.py` — Python script that requests URLs, compares headers against a baseline, and writes `report/header_audit.md`.
- `tools/baseline_headers.json` — baseline rules used to evaluate headers.
- GitHub Action workflow to run scans on push / pull_request.
- PR template to enforce security checklist for fixes.


## Quick start


1. Create a virtual environment and install dependencies:


```bash
python -m venv .venv
source .venv/bin/activate # or .venv\Scripts\activate on Windows
pip install -r requirements.txt
