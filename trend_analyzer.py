#!/usr/bin/env python3
"""
Trend Analyzer for Security Header Scanner

Compares current scan results with previous scans to track improvements/regressions.
Usage:
  python trend_analyzer.py --current report/header_audit.md --previous previous_scan.md --output trend_report.md
"""

import argparse
import json
import os
import re
from datetime import datetime
from pathlib import Path


class SecurityHeaderTrendAnalyzer:
    def __init__(self):
        self.supported_headers = [
            "Strict-Transport-Security",
            "X-Frame-Options", 
            "X-Content-Type-Options",
            "Referrer-Policy",
            "Content-Security-Policy",
            "Permissions-Policy",
            "X-XSS-Protection",
            "Set-Cookie"
        ]

    def parse_security_report(self, report_path):
        """Parse security report and extract structured data"""
        if not os.path.exists(report_path):
            raise FileNotFoundError(f"Report file not found: {report_path}")
        
        with open(report_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Extract report metadata
        metadata = self._extract_metadata(content)
        
        # Extract findings for each URL
        url_findings = self._extract_url_findings(content)
        
        return {
            'metadata': metadata,
            'url_findings': url_findings,
            'summary': self._extract_summary(content)
        }

    def _extract_metadata(self, content):
        """Extract report metadata"""
        metadata = {}
        
        # Extract generation date
        date_match = re.search(r"\*\*Generated\*\*: (.+?)\n", content)
        if date_match:
            metadata['generated'] = date_match.group(1).strip()
        
        # Extract targets scanned
        targets_match = re.search(r"\*\*Targets Scanned\*\*: (\d+)", content)
        if targets_match:
            metadata['targets_scanned'] = int(targets_match.group(1))
        
        # Extract baseline used
        baseline_match = re.search(r"\*\*Baseline Used\*\*: (.+?)\n", content)
        if baseline_match:
            metadata['baseline_used'] = baseline_match.group(1).strip()
        
        return metadata

    def _extract_summary(self, content):
        """Extract executive summary"""
        summary = {}
        
        # Extract security score
        score_match = re.search(r"Overall Security Score:.*?(\d+)/100", content)
        if score_match:
            summary['security_score'] = int(score_match.group(1))
        
        # Extract issue counts
        high_match = re.search(r"High Severity Issues.*?: (\d+)", content)
        medium_match = re.search(r"Medium Severity Issues.*?: (\d+)", content)
        low_match = re.search(r"Low Severity Issues.*?: (\d+)", content)
        
        if high_match:
            summary['high_issues'] = int(high_match.group(1))
        if medium_match:
            summary['medium_issues'] = int(medium_match.group(1))
        if low_match:
            summary['low_issues'] = int(low_match.group(1))
        
        return summary

    def _extract_url_findings(self, content):
        """Extract findings for each URL"""
        # Split by URL sections - handle both formats
        url_sections = re.split(r'---\n\n### \d+\. ', content)
        if len(url_sections) == 1:
            url_sections = re.split(r'---\n\n### ', content)
        
        url_findings = {}
        
        for section in url_sections[1:]:  # Skip first section (header)
            # Extract URL
            url_match = re.match(r'(https?://[^\n]+)', section)
            if not url_match:
                continue
                
            url = url_match.group(1).strip()
            url_findings[url] = {
                'findings': [],
                'site_score': None,
                'status_code': None,
                'headers_count': None
            }
            
            # Extract site score
            score_match = re.search(r"Site Security Score: (\d+)/100", section)
            if score_match:
                url_findings[url]['site_score'] = int(score_match.group(1))
            
            # Extract status code and headers count
            status_match = re.search(r"Status Code.*?`(\d+)`", section)
            headers_match = re.search(r"Headers Found.*?`(\d+)`", section)
            
            if status_match:
                url_findings[url]['status_code'] = int(status_match.group(1))
            if headers_match:
                url_findings[url]['headers_count'] = int(headers_match.group(1))
            
            # Extract findings table
            findings_section = re.search(r"\| Severity \| Header \| Issue.*?\n\n", section, re.DOTALL)
            if findings_section:
                findings_table = findings_section.group(0)
                url_findings[url]['findings'] = self._parse_findings_table(findings_table)
        
        return url_findings

    def _parse_findings_table(self, table_content):
        """Parse the findings table into structured data"""
        findings = []
        lines = table_content.strip().split('\n')
        
        # Skip header and separator lines
        for line in lines[2:]:
            if line.startswith('|') and 'Severity' not in line:
                cells = [cell.strip() for cell in line.split('|')[1:-1]]  # Remove empty first/last cells
                if len(cells) >= 3:  # At least severity, header, issue
                    # Clean severity from emojis and formatting
                    severity = re.sub(r'[🔴🟡🔵⚪\*\ ]', '', cells[0]).strip()
                    header = cells[1].replace('`', '').strip()
                    issue = cells[2].strip()
                    
                    # Handle optional description column
                    description = cells[3] if len(cells) > 3 else ""
                    
                    findings.append({
                        'severity': severity.lower(),
                        'header': header,
                        'issue': issue,
                        'description': description
                    })
        
        return findings

    def compare_reports(self, current_report, previous_report):
        """Compare two reports and generate trend analysis"""
        comparison = {
            'overall_trend': {},
            'url_comparisons': {},
            'improvements': [],
            'regressions': [],
            'unchanged': []
        }
        
        # Overall comparison
        current_score = current_report['summary'].get('security_score', 0)
        previous_score = previous_report['summary'].get('security_score', 0)
        
        comparison['overall_trend'] = {
            'current_score': current_score,
            'previous_score': previous_score,
            'score_change': current_score - previous_score,
            'score_trend': 'improved' if current_score > previous_score else 'regressed' if current_score < previous_score else 'unchanged'
        }
        
        # Compare issues by severity
        for severity in ['high_issues', 'medium_issues', 'low_issues']:
            current_count = current_report['summary'].get(severity, 0)
            previous_count = previous_report['summary'].get(severity, 0)
            comparison['overall_trend'][f'{severity}_change'] = current_count - previous_count
        
        # Compare individual URLs
        for url in current_report['url_findings']:
            if url in previous_report['url_findings']:
                url_comp = self._compare_url_findings(
                    current_report['url_findings'][url],
                    previous_report['url_findings'][url],
                    url
                )
                comparison['url_comparisons'][url] = url_comp
                
                # Categorize changes
                if url_comp['score_change'] > 0:
                    comparison['improvements'].append(url)
                elif url_comp['score_change'] < 0:
                    comparison['regressions'].append(url)
                else:
                    comparison['unchanged'].append(url)
        
        return comparison

    def _compare_url_findings(self, current, previous, url):
        """Compare findings for a specific URL"""
        comparison = {
            'url': url,
            'current_score': current.get('site_score', 0),
            'previous_score': previous.get('site_score', 0),
            'score_change': current.get('site_score', 0) - previous.get('site_score', 0),
            'resolved_issues': [],
            'new_issues': [],
            'unchanged_issues': []
        }
        
        # Convert findings to sets for comparison
        current_issues = set()
        previous_issues = set()
        
        for finding in current.get('findings', []):
            current_issues.add(f"{finding['header']}: {finding['issue']}")
        
        for finding in previous.get('findings', []):
            previous_issues.add(f"{finding['header']}: {finding['issue']}")
        
        # Find resolved issues (in previous but not in current)
        comparison['resolved_issues'] = list(previous_issues - current_issues)
        
        # Find new issues (in current but not in previous)
        comparison['new_issues'] = list(current_issues - previous_issues)
        
        # Find unchanged issues
        comparison['unchanged_issues'] = list(current_issues & previous_issues)
        
        return comparison

    def generate_trend_report(self, comparison, output_path):
        """Generate comprehensive trend analysis report"""
        os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else '.', exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write("# Security Header Trend Analysis Report\n\n")
            f.write(f"**Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"**Comparison Type**: Historical Analysis\n\n")
            
            # Executive Summary
            f.write("## Executive Summary\n\n")
            
            trend_symbol = {
                'improved': '↑',
                'regressed': '↓', 
                'unchanged': '→'
            }.get(comparison['overall_trend']['score_trend'], '→')
            
            f.write(f"### Overall Security Trend: {trend_symbol} ")
            f.write(f"**{comparison['overall_trend']['score_trend'].upper()}** ")
            f.write(f"({comparison['overall_trend']['score_change']:+d} points)\n\n")
            
            f.write(f"- **Current Score**: {comparison['overall_trend']['current_score']}/100\n")
            f.write(f"- **Previous Score**: {comparison['overall_trend']['previous_score']}/100\n")
            f.write(f"- **Net Change**: {comparison['overall_trend']['score_change']:+d} points\n\n")
            
            # Issue Changes Summary
            f.write("### Issue Changes Summary\n\n")
            
            for severity, label in [('high_issues', 'High'), ('medium_issues', 'Medium'), ('low_issues', 'Low')]:
                change = comparison['overall_trend'].get(f'{severity}_change', 0)
                if change != 0:
                    trend = "improved" if change < 0 else "worsened"
                    symbol = "+" if change < 0 else "-"
                    f.write(f"- {symbol} **{label} Issues**: {trend} ({change:+d})\n")
                else:
                    f.write(f"- → **{label} Issues**: unchanged\n")
            
            f.write("\n")
            
            # URL-level Analysis
            f.write("## URL-Level Analysis\n\n")
            
            for category, urls, symbol in [
                ('Improvements', comparison['improvements'], '+'),
                ('Regressions', comparison['regressions'], '-'), 
                ('Unchanged', comparison['unchanged'], '→')
            ]:
                if urls:
                    f.write(f"### {symbol} {category} ({len(urls)} URLs)\n\n")
                    
                    for url in urls:
                        url_comp = comparison['url_comparisons'][url]
                        f.write(f"#### {url}\n")
                        f.write(f"- **Score Change**: {url_comp['score_change']:+d} points ")
                        f.write(f"({url_comp['previous_score']} → {url_comp['current_score']})\n")
                        
                        if url_comp['resolved_issues']:
                            f.write(f"- **Resolved Issues**: {len(url_comp['resolved_issues'])}\n")
                        if url_comp['new_issues']:
                            f.write(f"- **New Issues**: {len(url_comp['new_issues'])}\n")
                        if url_comp['unchanged_issues']:
                            f.write(f"- **Unchanged Issues**: {len(url_comp['unchanged_issues'])}\n")
                        
                        f.write("\n")
            
            # Detailed Changes
            f.write("## Detailed Changes Breakdown\n\n")
            
            for url, url_comp in comparison['url_comparisons'].items():
                f.write(f"### {url}\n\n")
                
                if url_comp['resolved_issues']:
                    f.write("#### Resolved Issues:\n")
                    for issue in url_comp['resolved_issues']:
                        f.write(f"- {issue}\n")
                    f.write("\n")
                
                if url_comp['new_issues']:
                    f.write("#### New Issues:\n")
                    for issue in url_comp['new_issues']:
                        f.write(f"- {issue}\n")
                    f.write("\n")
            
            # Recommendations
            f.write("## Trend Recommendations\n\n")
            
            if comparison['overall_trend']['score_change'] > 0:
                f.write("### Excellent Progress!\n\n")
                f.write("Your security header implementation is improving. Keep up the good work!\n\n")
            elif comparison['overall_trend']['score_change'] < 0:
                f.write("### Attention Needed\n\n")
                f.write("Security header compliance has regressed. Please review the new issues.\n\n")
            else:
                f.write("### Stable Performance\n\n")
                f.write("No significant changes detected. Consider addressing remaining issues.\n\n")
            
            # Footer
            f.write("---\n\n")
            f.write("**Report Generated by**: Security Header Trend Analyzer  \n")
            f.write("**Recommendation**: Run trend analysis after each security scan  \n")
            f.write("**Note**: This analysis helps track security posture over time\n")
        
        print(f"Trend report generated: {output_path}")

    def save_comparison_data(self, comparison, output_path):
        """Save comparison data as JSON for programmatic use"""
        os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else '.', exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(comparison, f, indent=2, ensure_ascii=False)
        
        print(f"Comparison data saved: {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Security Header Trend Analyzer - Compare current and previous scan results",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python trend_analyzer.py --current report/header_audit.md --previous previous_scan.md --output trend_report.md
  python trend_analyzer.py --current scan1.md --previous scan2.md --output trends/ --json
        """
    )
    
    parser.add_argument(
        "--current",
        required=True,
        help="Current security scan report file"
    )
    
    parser.add_argument(
        "--previous", 
        required=True,
        help="Previous security scan report file for comparison"
    )
    
    parser.add_argument(
        "--output",
        default="trend_analysis.md",
        help="Output trend report file (default: trend_analysis.md)"
    )
    
    parser.add_argument(
        "--json",
        action="store_true",
        help="Also save comparison data as JSON"
    )
    
    args = parser.parse_args()
    
    print("Starting security header trend analysis...")
    
    analyzer = SecurityHeaderTrendAnalyzer()
    
    try:
        # Parse reports
        print("Parsing current report...")
        current_report = analyzer.parse_security_report(args.current)
        
        print("Parsing previous report...")
        previous_report = analyzer.parse_security_report(args.previous)
        
        # Compare reports
        print("Comparing reports...")
        comparison = analyzer.compare_reports(current_report, previous_report)
        
        # Generate trend report
        print("Generating trend report...")
        analyzer.generate_trend_report(comparison, args.output)
        
        # Save JSON data if requested
        if args.json:
            json_path = args.output.replace('.md', '.json')
            analyzer.save_comparison_data(comparison, json_path)
        
        # Print quick summary
        print(f"\nTrend Analysis Complete!")
        print(f"Overall Trend: {comparison['overall_trend']['score_trend']}")
        print(f"Score Change: {comparison['overall_trend']['score_change']:+d} points")
        print(f"Improvements: {len(comparison['improvements'])} URLs")
        print(f"Regressions: {len(comparison['regressions'])} URLs")
        print(f"Unchanged: {len(comparison['unchanged'])} URLs")
        print(f"Report: {args.output}")
        
    except FileNotFoundError as e:
        print(f"Error: {e}")
        return 1
    except Exception as e:
        print(f"Error during trend analysis: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())
