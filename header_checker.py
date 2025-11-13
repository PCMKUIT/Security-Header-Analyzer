#!/usr/bin/env python3
"""
header_checker.py


Simple security header analyzer.
- Reads targets from a file or accepts single URL
- Requests each target (GET)
- Compares response headers to baseline in tools/baseline_headers.json
- Writes a Markdown report to report/header_audit.md


Usage:
python header_checker.py --targets targets.txt --output report/header_audit.md


"""
import argparse
import json
import os
import re
from urllib.parse import urlparse


import requests




BASELINE_PATH = os.path.join("tools", "baseline_headers.json")




def load_baseline(path=BASELINE_PATH):
with open(path, "r", encoding="utf-8") as f:
return json.load(f)




def normalize_header_name(name):
return "-".join([p.capitalize() for p in name.split("-")])




def check_hsts(value, rule):
# Example: 'max-age=31536000; includeSubDomains; preload'
try:
max_age = 0
include_sub = False
parts = [p.strip() for p in value.split(";")]
for p in parts:
if p.startswith("max-age"):
m = re.search(r"max-age=(\d+)", p)
if m:
max_age = int(m.group(1))
if p.lower() == "includesubdomains":
include_sub = True
return max_age >= rule.get("min_max_age", 0) and ((not rule.get("require_include_subdomains")) or include_sub)
except Exception:
return False




def check_allowed(value, rule):
allowed = rule.get("allowed_values")
return any(value.strip().startswith(a) for a in allowed) if allowed else True




def check_set_cookie(headers, rule):
ok, data, status = fetch_header
