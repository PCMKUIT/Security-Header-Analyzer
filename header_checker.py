#!/usr/bin/env python3
"""
Security Header Analyzer

A comprehensive tool to analyze HTTP security headers against security best practices.
Checks headers like CSP, HSTS, X-Frame-Options, and validates cookie security flags.

Usage:
  python header_checker.py --targets targets.txt --output report/header_audit.md
  python header_checker.py --url https://example.com --output single_scan.md
"""

import argparse
import json
import os
import re
import sys
import time
from urllib.parse import urlparse
from datetime import datetime

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class SecurityHeaderAnalyzer:
    def __init__(self, baseline_path=None, timeout=10, max_retries=3):
        self.baseline_path = baseline_path or os.path.join("tools", "baseline_headers.json")
        self.timeout = timeout
        self.max_retries = max_retries
        self.baseline = self.load_baseline()
        
        # Setup session with retry strategy
        self.session = requests.Session()
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Set a common user agent
        self.session.headers.update({
            'User-Agent': 'Security-Header-Analyzer/1.0'
        })

    def load_baseline(self):
        """Load security header baseline from JSON file"""
        try:
            with open(self.baseline_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"Error: Baseline file not found at {self.baseline_path}")
            sys.exit(1)
        except json.JSONDecodeError as e:
            print(f"Error: Invalid JSON in baseline file: {e}")
            sys.exit(1)

    def normalize_header_name(self, name):
        """Normalize header name to standard capitalization"""
        return "-".join([part.capitalize() for part in name.split("-")])

    def check_hsts(self, value, rule):
        """Validate HSTS header according to baseline rules"""
        if not value:
            return False, "HSTS header is missing"
        
        try:
            max_age = 0
            include_subdomains = False
            preload = False
            
            parts = [part.strip().lower() for part in value.split(";")]
            
            for part in parts:
                if part.startswith("max-age="):
                    match = re.search(r"max-age=(\d+)", part)
                    if match:
                        max_age = int(match.group(1))
                elif part == "includesubdomains":
                    include_subdomains = True
                elif part == "preload":
                    preload = True
            
            issues = []
            min_max_age = rule.get("min_max_age", 31536000)
            
            if max_age < min_max_age:
                issues.append(f"max-age too short: {max_age} (min: {min_max_age})")
            
            if rule.get("require_include_subdomains") and not include_subdomains:
                issues.append("includeSubDomains directive missing")
            
            return len(issues) == 0, "; ".join(issues) if issues else "OK"
            
        except Exception as e:
            return False, f"Error parsing HSTS: {str(e)}"

    def check_allowed_values(self, value, rule):
        """Check if header value matches allowed values"""
        allowed_values = rule.get("allowed_values", [])
        if not allowed_values:
            return True, "No specific value requirements"
        
        if value in allowed_values:
            return True, "Value allowed"
        else:
            return False, f"Value '{value}' not in allowed values: {allowed_values}"

    def check_cookie_security(self, headers, rule):
        """Analyze Set-Cookie headers for security flags"""
        set_cookie_headers = headers.get("Set-Cookie")
        if not set_cookie_headers:
            return True, "No cookies set"  # No cookies is technically secure
        
        # Handle both single header and multiple headers
        if isinstance(set_cookie_headers, str):
            cookie_strings = [set_cookie_headers]
        else:
            cookie_strings = set_cookie_headers
        
        all_issues = []
        required_flags = rule.get("required_flags", [])
        require_samesite = rule.get("require_samesite", False)
        allowed_samesite = rule.get("allowed_samesite", ["Strict", "Lax"])
        
        for i, cookie_str in enumerate(cookie_strings):
            cookie_issues = []
            cookie_lower = cookie_str.lower()
            
            # Check required flags
            for flag in required_flags:
                if flag.lower() not in cookie_lower:
                    cookie_issues.append(f"Missing {flag}")
            
            # Check SameSite
            if require_samesite:
                samesite_match = re.search(r'samesite=([^;]+)', cookie_str, re.IGNORECASE)
                if not samesite_match:
                    cookie_issues.append("Missing SameSite attribute")
                else:
                    samesite_value = samesite_match.group(1)
                    if samesite_value not in allowed_samesite:
                        cookie_issues.append(f"SameSite value '{samesite_value}' not in allowed values: {allowed_samesite}")
            
            if cookie_issues:
                cookie_name = cookie_str.split(';')[0].split('=')[0]
                all_issues.append(f"Cookie '{cookie_name}': {', '.join(cookie_issues)}")
        
        return len(all_issues) == 0, "; ".join(all_issues) if all_issues else "All cookies secure"

    def evaluate_headers(self, response_headers):
        """Evaluate all headers against baseline rules"""
        findings = []
        headers_dict = {self.normalize_header_name(k): v for k, v in response_headers.items()}
        
        for header_name, rule in self.baseline.items():
            normalized_name = self.normalize_header_name(header_name)
            header_value = headers_dict.get(normalized_name)
            
            # Skip cookie analysis if no cookies
            if header_name == "Set-Cookie" and not header_value:
                continue
                
            if rule.get("required") and not header_value:
                findings.append({
                    "type": "missing",
                    "header": header_name,
                    "message": f"Required header is missing",
                    "severity": "high"
                })
                continue
            
            if header_value:
                if header_name == "Strict-Transport-Security":
                    is_secure, message = self.check_hsts(header_value, rule)
                    if not is_secure:
                        findings.append({
                            "type": "weak",
                            "header": header_name,
                            "message": f"HSTS configuration issue: {message}",
                            "severity": "high"
                        })
                
                elif header_name in ["X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy", "X-XSS-Protection"]:
                    is_allowed, message = self.check_allowed_values(header_value, rule)
                    if not is_allowed:
                        findings.append({
                            "type": "invalid",
                            "header": header_name,
                            "message": message,
                            "severity": "medium"
                        })
                
                elif header_name == "Set-Cookie":
                    is_secure, message = self.check_cookie_security(response_headers, rule)
                    if not is_secure:
                        findings.append({
                            "type": "weak",
                            "header": header_name,
                            "message": f"Cookie security issues: {message}",
                            "severity": "high"
                        })
            
            # Check recommended headers
            elif rule.get("recommended") and not rule.get("required"):
                findings.append({
                    "type": "missing",
                    "header": header_name,
                    "message": "Recommended header is missing",
                    "severity": "low"
                })
        
        return findings

    def fetch_headers(self, url):
        """Fetch headers from URL with error handling"""
        try:
            start_time = time.time()
            response = self.session.get(
                url, 
                timeout=self.timeout, 
                allow_redirects=True,
                verify=True
            )
            response_time = round((time.time() - start_time) * 1000, 2)
            
            headers = dict(response.headers)
            return {
                "success": True,
                "url": url,
                "final_url": response.url,
                "status_code": response.status_code,
                "headers": headers,
                "response_time_ms": response_time,
                "error": None
            }
            
        except requests.exceptions.SSLError as e:
            return {
                "success": False,
                "url": url,
                "final_url": url,
                "status_code": None,
                "headers": {},
                "response_time_ms": None,
                "error": f"SSL Error: {str(e)}"
            }
        except requests.exceptions.Timeout:
            return {
                "success": False,
                "url": url,
                "final_url": url,
                "status_code": None,
                "headers": {},
                "response_time_ms": None,
                "error": f"Request timeout after {self.timeout}s"
            }
        except requests.exceptions.ConnectionError:
            return {
                "success": False,
                "url": url,
                "final_url": url,
                "status_code": None,
                "headers": {},
                "response_time_ms": None,
                "error": "Connection error - host may be unreachable"
            }
        except Exception as e:
            return {
                "success": False,
                "url": url,
                "final_url": url,
                "status_code": None,
                "headers": {},
                "response_time_ms": None,
                "error": f"Unexpected error: {str(e)}"
            }

    def scan_url(self, url):
        """Perform complete security header scan for a single URL"""
        print(f"Scanning: {url}")
        result = self.fetch_headers(url)
        
        if result["success"]:
            findings = self.evaluate_headers(result["headers"])
            result["findings"] = findings
            result["headers_count"] = len(result["headers"])
        else:
            result["findings"] = []
            result["headers_count"] = 0
            
        return result

    def aggregate_summary(self, results):
        """Aggregate scan results into summary statistics"""
        summary = {
            "total": len(results),
            "successful": 0,
            "errors": 0,
            "high_issues": 0,
            "medium_issues": 0,
            "low_issues": 0
        }
        
        for result in results:
            if result["success"]:
                summary["successful"] += 1
                for finding in result["findings"]:
                    if finding["severity"] == "high":
                        summary["high_issues"] += 1
                    elif finding["severity"] == "medium":
                        summary["medium_issues"] += 1
                    elif finding["severity"] == "low":
                        summary["low_issues"] += 1
            else:
                summary["errors"] += 1
                
        return summary

    def calculate_security_score(self, summary):
        """Calculate overall security score (0-100)"""
        if summary["successful"] == 0:
            return 0
            
        # Penalty points for issues
        penalty = (
            summary["high_issues"] * 10 +
            summary["medium_issues"] * 5 +
            summary["low_issues"] * 2
        )
        
        # Base score (perfect would be 100)
        base_score = 100
        
        # Apply penalties but don't go below 0
        final_score = max(0, base_score - penalty)
        
        return final_score

    def generate_report(self, results, output_path):
        """Generate comprehensive Markdown report"""
        os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else ".", exist_ok=True)
        
        summary = self.aggregate_summary(results)
        
        with open(output_path, "w", encoding="utf-8") as f:
            # Header
            f.write("# Security Header Audit Report\n\n")
            f.write(f"**Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"**Targets Scanned**: {summary['total']}\n")
            f.write(f"**Baseline Used**: {os.path.basename(self.baseline_path)}\n\n")
            
            # Executive Summary
            f.write("## 📊 Executive Summary\n\n")
            f.write(f"- **Total URLs Scanned**: {summary['total']}\n")
            f.write(f"- **✅ Successfully Scanned**: {summary['successful']}\n")
            f.write(f"- **❌ Scan Errors**: {summary['errors']}\n")
            f.write(f"- **🔴 High Severity Issues**: {summary['high_issues']}\n")
            f.write(f"- **🟡 Medium Severity Issues**: {summary['medium_issues']}\n")
            f.write(f"- **🔵 Low Severity Issues**: {summary['low_issues']}\n\n")
            
            # Security Score với visual indicator
            security_score = self.calculate_security_score(summary)
            score_emoji = "🔴" if security_score < 50 else "🟡" if security_score < 80 else "✅"
            f.write(f"## 🎯 Overall Security Score: {score_emoji} {security_score}/100\n\n")
            
            # Score Interpretation
            if security_score >= 90:
                f.write("**Status**: ✅ Excellent - Strong security headers implementation\n\n")
            elif security_score >= 70:
                f.write("**Status**: 🟡 Good - Moderate security, some improvements needed\n\n")
            elif security_score >= 50:
                f.write("**Status**: 🟠 Fair - Basic security, significant improvements needed\n\n")
            else:
                f.write("**Status**: 🔴 Poor - Critical security issues require immediate attention\n\n")
            
            # Quick Stats
            f.write("### 📈 Quick Statistics\n\n")
            f.write(f"- **Success Rate**: {(summary['successful']/summary['total']*100):.1f}%\n")
            if summary['successful'] > 0:
                avg_issues_per_site = (summary['high_issues'] + summary['medium_issues'] + summary['low_issues']) / summary['successful']
                f.write(f"- **Average Issues per Site**: {avg_issues_per_site:.1f}\n")
            f.write("\n")
            
            # Detailed Findings
            f.write("## 🔍 Detailed Findings\n\n")
            
            for i, result in enumerate(results, 1):
                f.write(f"---\n\n")
                f.write(f"### 🌐 {i}. {result['url']}\n\n")
                
                if not result["success"]:
                    f.write(f"**❌ Scan Failed**: {result['error']}\n\n")
                    continue
                
                # URL Info Box
                f.write(f"**Status Code**: `{result['status_code']}` | ")
                f.write(f"**Response Time**: `{result['response_time_ms']} ms` | ")
                f.write(f"**Headers Found**: `{result['headers_count']}`\n\n")
                f.write(f"**Final URL**: {result['final_url']}\n\n")
                
                # Findings Summary với visual
                if not result["findings"]:
                    f.write("### ✅ **Excellent! No security issues found**\n\n")
                    f.write("All required and recommended security headers are properly configured.\n\n")
                else:
                    high_findings = [f for f in result["findings"] if f["severity"] == "high"]
                    medium_findings = [f for f in result["findings"] if f["severity"] == "medium"]
                    low_findings = [f for f in result["findings"] if f["severity"] == "low"]
                    
                    # Site-specific score
                    site_penalty = (
                        len(high_findings) * 10 +
                        len(medium_findings) * 5 +
                        len(low_findings) * 2
                    )
                    site_score = max(0, 100 - site_penalty)
                    site_emoji = "🔴" if site_score < 50 else "🟡" if site_score < 80 else "✅"
                    
                    f.write(f"### {site_emoji} Site Security Score: {site_score}/100\n\n")
                    
                    if high_findings:
                        f.write(f"**🔴 Critical Issues ({len(high_findings)})** - Immediate attention required\n")
                    if medium_findings:
                        f.write(f"**🟡 Important Issues ({len(medium_findings)})** - Should be addressed soon\n")
                    if low_findings:
                        f.write(f"**🔵 Recommendations ({len(low_findings)})** - Security enhancements\n")
                    f.write("\n")
                    
                    # Detailed Findings Table với description
                    f.write("#### 📋 Security Issues Details\n\n")
                    f.write("| Severity | Header | Issue | Description |\n")
                    f.write("|----------|--------|-------|-------------|\n")
                    for finding in result["findings"]:
                        severity_icon = {
                            "high": "🔴",
                            "medium": "🟡", 
                            "low": "🔵"
                        }.get(finding["severity"], "⚪")
                        
                        # Get description from baseline
                        header_desc = self.baseline.get(finding["header"], {}).get("description", "Security header")
                        
                        f.write(f"| {severity_icon} **{finding['severity'].title()}** | `{finding['header']}` | {finding['message']} | {header_desc} |\n")
                    f.write("\n")
                
                # Headers Snapshot
                f.write("<details>\n")
                f.write("<summary>📨 View Raw Response Headers</summary>\n\n")
                f.write("```http\n")
                for header, value in result["headers"].items():
                    f.write(f"{header}: {value}\n")
                f.write("```\n")
                f.write("</details>\n\n")
            
            # Remediation Guide
            f.write("---\n\n")
            f.write("## 🛠️ Remediation Guide\n\n")
            f.write("### Quick Fixes for Common Issues:\n\n")
            
            remediation_guides = {
                "Strict-Transport-Security": "**Fix**: Add `Strict-Transport-Security: max-age=31536000; includeSubDomains`",
                "X-Frame-Options": "**Fix**: Add `X-Frame-Options: DENY` or `X-Frame-Options: SAMEORIGIN`",
                "X-Content-Type-Options": "**Fix**: Add `X-Content-Type-Options: nosniff`",
                "Referrer-Policy": "**Fix**: Add `Referrer-Policy: strict-origin-when-cross-origin`",
                "Content-Security-Policy": "**Recommend**: Implement CSP based on your application needs",
                "Permissions-Policy": "**Recommend**: Add `Permissions-Policy` to restrict browser features",
                "Set-Cookie": "**Fix**: Ensure cookies have `HttpOnly`, `Secure`, and `SameSite` flags"
            }
            
            for header, guide in remediation_guides.items():
                f.write(f"- **{header}**: {guide}\n")
            
            f.write("\n### 📚 Additional Resources:\n")
            f.write("- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)\n")
            f.write("- [Mozilla Security Headers Guide](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers)\n")
            f.write("- [SecurityHeaders.com Scanner](https://securityheaders.com/)\n\n")
            
            # Report Footer
            f.write("---\n\n")
            f.write("**Report Generated by**: Security Header Analyzer v1.0  \n")
            f.write("**Next Scan Recommendation**: Run weekly to monitor security header compliance\n")
        
        print(f"Report generated: {output_path}")


def parse_targets(file_path):
    """Parse targets from file, handling various formats"""
    targets = []
    
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                
                # Skip empty lines and comments
                if not line or line.startswith("#"):
                    continue
                
                # Validate and normalize URL
                if not urlparse(line).scheme:
                    line = "https://" + line
                
                try:
                    parsed = urlparse(line)
                    if parsed.scheme not in ["http", "https"]:
                        print(f"Warning: Invalid scheme in line {line_num}: {line}")
                        continue
                    targets.append(line)
                except Exception:
                    print(f"Warning: Invalid URL in line {line_num}: {line}")
                    
    except FileNotFoundError:
        print(f"Error: Targets file not found: {file_path}")
        sys.exit(1)
        
    return targets


def main():
    parser = argparse.ArgumentParser(
        description="Security Header Analyzer - Comprehensive HTTP security header scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --targets targets.txt --output report/audit.md
  %(prog)s --url https://example.com --output single_scan.md
  %(prog)s --targets urls.txt --baseline custom_baseline.json --timeout 15
        """
    )
    
    parser.add_argument(
        "--targets", 
        help="File containing list of URLs to scan (one per line)"
    )
    
    parser.add_argument(
        "--url", 
        help="Single URL to scan"
    )
    
    parser.add_argument(
        "--output", 
        default="report/header_audit.md",
        help="Output report file path (default: report/header_audit.md)"
    )
    
    parser.add_argument(
        "--baseline",
        help="Custom baseline JSON file (default: tools/baseline_headers.json)"
    )
    
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Request timeout in seconds (default: 10)"
    )
    
    parser.add_argument(
        "--retries",
        type=int,
        default=3,
        help="Max retries for failed requests (default: 3)"
    )
    
    args = parser.parse_args()
    
    # Validate arguments
    if not args.targets and not args.url:
        parser.error("Either --targets or --url must be provided")
    
    if args.targets and args.url:
        parser.error("Use either --targets or --url, not both")
    
    # Get targets
    if args.url:
        targets = [args.url]
    else:
        targets = parse_targets(args.targets)
    
    if not targets:
        print("Error: No valid targets found")
        sys.exit(1)
    
    print(f"Starting security header scan for {len(targets)} target(s)...")
    
    # Initialize analyzer
    analyzer = SecurityHeaderAnalyzer(
        baseline_path=args.baseline,
        timeout=args.timeout,
        max_retries=args.retries
    )
    
    # Scan all targets
    results = []
    for target in targets:
        result = analyzer.scan_url(target)
        results.append(result)
    
    # Generate report
    analyzer.generate_report(results, args.output)
    
    # Print quick summary
    summary = analyzer.aggregate_summary(results)
    score = analyzer.calculate_security_score(summary)
    
    print(f"\nScan completed!")
    print(f"Targets: {summary['total']}, Successful: {summary['successful']}, Errors: {summary['errors']}")
    print(f"Issues: High({summary['high_issues']}) Medium({summary['medium_issues']}) Low({summary['low_issues']})")
    print(f"Security Score: {score}/100")
    print(f"Report: {args.output}")


if __name__ == "__main__":
    main()
