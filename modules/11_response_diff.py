#!/usr/bin/env python3
import urllib3; urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
"""
============================================================================
MODULE 11: RESPONSE DIFF ANALYSIS
============================================================================
Detects vulnerabilities by comparing response differences:
- Normal request vs malicious request
- Different parameter values
- Timing differences
============================================================================
"""

import json
import os
import re
import sys
import time
import difflib
from dataclasses import dataclass, asdict
from typing import Dict, List, Tuple, Optional
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
except ImportError:
    print("Error: requests library required")
    sys.exit(1)

try:
    from rich.console import Console
    from rich.table import Table
    console = Console()
except ImportError:
    class Console:
        def print(self, *args, **kwargs): print(*args)
        def log(self, *args, **kwargs): print(*args)
    console = Console()


# ============================================================================
# DATA CLASSES
# ============================================================================
@dataclass
class DiffResult:
    url: str
    param: str
    vuln_type: str
    confidence: float
    normal_response: str
    malicious_response: str
    diff_ratio: float
    evidence: str
    payload_used: str


# ============================================================================
# PAYLOADS FOR DIFF TESTING
# ============================================================================
class PayloadSets:
    """Payload sets for different vulnerability types."""
    
    SQLI = {
        'error_based': [
            ("1", "'"),
            ("1", "1'"),
            ("1", "1\""),
            ("1", "1' OR '1'='1"),
            ("1", "1' AND '1'='2"),
            ("1", "1'-- -"),
        ],
        'boolean_based': [
            ("1", "1 AND 1=1"),
            ("1", "1 AND 1=2"),
        ],
    }
    
    XSS = {
        'reflection': [
            ("test", "<script>alert(1)</script>"),
            ("test", "'\"><img src=x>"),
            ("test", "javascript:alert(1)"),
        ],
    }
    
    SSTI = {
        'detection': [
            ("test", "{{7*7}}"),
            ("test", "${7*7}"),
            ("test", "<%= 7*7 %>"),
            ("test", "#{7*7}"),
        ],
    }
    
    PATH_TRAVERSAL = {
        'detection': [
            ("file.txt", "../../../etc/passwd"),
            ("file.txt", "....//....//etc/passwd"),
        ],
    }


# ============================================================================
# RESPONSE DIFF ANALYZER
# ============================================================================
class ResponseDiffAnalyzer:
    """Analyzes response differences to detect vulnerabilities."""
    
    # Error patterns that indicate vulnerability
    SQLI_ERROR_PATTERNS = [
        r"sql syntax",
        r"mysql_fetch",
        r"ORA-\d{5}",
        r"PostgreSQL.*ERROR",
        r"SQLite.*error",
        r"ODBC.*Driver",
        r"syntax error",
        r"unclosed quotation",
        r"unterminated string",
    ]
    
    SSTI_PATTERNS = [
        r"\b49\b",  # Result of 7*7
        r"{{.*}}",  # Template syntax in output
    ]
    
    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.session = self._create_session()
        self.results: List[DiffResult] = []
    
    def _create_session(self) -> requests.Session:
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        })
        session.verify = False
        return session
    
    def load_urls(self) -> List[str]:
        """Load URLs with parameters to test."""
        urls = []
        param_dir = self.output_dir / 'params'
        
        # Load from parameter mining
        files_to_check = [
            'urls_with_params.txt',
            'gf_sqli.txt',
            'gf_xss.txt',
            'gf_ssti.txt',
        ]
        
        for filename in files_to_check:
            filepath = param_dir / filename
            if filepath.exists():
                with open(filepath, 'r') as f:
                    urls.extend([line.strip() for line in f if line.strip()])
        
        return list(set(urls))[:200]  # Limit for performance
    
    def make_request(self, url: str, timeout: int = 10) -> Tuple[str, float, int]:
        """Make HTTP request and return response details."""
        try:
            start = time.time()
            resp = self.session.get(url, timeout=timeout)
            elapsed = time.time() - start
            return resp.text, elapsed, resp.status_code
        except Exception as e:
            return "", 0, 0
    
    def calculate_diff_ratio(self, text1: str, text2: str) -> float:
        """Calculate similarity ratio between two texts."""
        if not text1 or not text2:
            return 0.0
        return difflib.SequenceMatcher(None, text1, text2).ratio()
    
    def analyze_sqli(self, url: str) -> Optional[DiffResult]:
        """Analyze URL for SQL injection using response diff."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            return None
        
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        for param in params:
            original_value = params[param][0] if params[param] else ""
            
            # Test error-based first
            for normal_val, malicious_val in PayloadSets.SQLI['error_based']:
                # Normal request
                test_params = {k: v[0] for k, v in params.items()}
                test_params[param] = normal_val
                normal_url = f"{base_url}?{urlencode(test_params)}"
                normal_resp, normal_time, normal_status = self.make_request(normal_url)
                
                # Malicious request
                test_params[param] = malicious_val
                mal_url = f"{base_url}?{urlencode(test_params)}"
                mal_resp, mal_time, mal_status = self.make_request(mal_url)
                
                if not normal_resp or not mal_resp:
                    continue
                
                # Check for SQL error patterns
                for pattern in self.SQLI_ERROR_PATTERNS:
                    if re.search(pattern, mal_resp, re.IGNORECASE) and not re.search(pattern, normal_resp, re.IGNORECASE):
                        return DiffResult(
                            url=url,
                            param=param,
                            vuln_type="SQLi (Error-based)",
                            confidence=0.9,
                            normal_response=normal_resp[:500],
                            malicious_response=mal_resp[:500],
                            diff_ratio=self.calculate_diff_ratio(normal_resp, mal_resp),
                            evidence=f"SQL error pattern detected: {pattern}",
                            payload_used=malicious_val,
                        )
                
                # Check for significant difference in response
                diff_ratio = self.calculate_diff_ratio(normal_resp, mal_resp)
                if diff_ratio < 0.8 and normal_status != mal_status:
                    return DiffResult(
                        url=url,
                        param=param,
                        vuln_type="SQLi (Behavioral)",
                        confidence=0.7,
                        normal_response=normal_resp[:500],
                        malicious_response=mal_resp[:500],
                        diff_ratio=diff_ratio,
                        evidence=f"Status code changed: {normal_status} → {mal_status}, diff ratio: {diff_ratio:.2f}",
                        payload_used=malicious_val,
                    )
            
            # Test boolean-based
            for true_val, false_val in PayloadSets.SQLI['boolean_based']:
                test_params = {k: v[0] for k, v in params.items()}
                
                test_params[param] = original_value + " AND 1=1"
                true_url = f"{base_url}?{urlencode(test_params)}"
                true_resp, _, _ = self.make_request(true_url)
                
                test_params[param] = original_value + " AND 1=2"
                false_url = f"{base_url}?{urlencode(test_params)}"
                false_resp, _, _ = self.make_request(false_url)
                
                if true_resp and false_resp:
                    diff_ratio = self.calculate_diff_ratio(true_resp, false_resp)
                    if diff_ratio < 0.9 and len(true_resp) != len(false_resp):
                        return DiffResult(
                            url=url,
                            param=param,
                            vuln_type="SQLi (Boolean-based)",
                            confidence=0.75,
                            normal_response=true_resp[:500],
                            malicious_response=false_resp[:500],
                            diff_ratio=diff_ratio,
                            evidence=f"Boolean condition affects response, diff ratio: {diff_ratio:.2f}",
                            payload_used="AND 1=1 vs AND 1=2",
                        )
        
        return None
    
    def analyze_ssti(self, url: str) -> Optional[DiffResult]:
        """Analyze URL for SSTI using response diff."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            return None
        
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        for param in params:
            # Get baseline response first to compare against
            test_params = {k: v[0] for k, v in params.items()}
            baseline_url = f"{base_url}?{urlencode(test_params)}"
            baseline_resp, _, _ = self.make_request(baseline_url)
            
            for normal_val, malicious_val in PayloadSets.SSTI['detection']:
                test_params = {k: v[0] for k, v in params.items()}
                test_params[param] = malicious_val
                test_url = f"{base_url}?{urlencode(test_params)}"
                
                resp, _, status = self.make_request(test_url)
                
                if resp:
                    # Check if 7*7 was evaluated to 49
                    # Additional checks to reduce false positives:
                    # 1. "49" should NOT already be in baseline (e.g., page number, ID)
                    # 2. The payload syntax should NOT be in response (means it was processed)
                    # 3. "49" should appear as a distinct value (word boundary)
                    baseline_has_49 = re.search(r'\b49\b', baseline_resp) is not None if baseline_resp else False
                    payload_reflected = malicious_val in resp
                    has_49 = re.search(r'\b49\b', resp) is not None
                    
                    # Only flag as SSTI if:
                    # - 49 appears in response
                    # - 49 was NOT in baseline (new value)
                    # - The payload template syntax is NOT reflected (was executed)
                    if has_49 and not baseline_has_49 and not payload_reflected:
                        return DiffResult(
                            url=url,
                            param=param,
                            vuln_type="SSTI",
                            confidence=0.85,
                            normal_response=baseline_resp[:500] if baseline_resp else "",
                            malicious_response=resp[:500],
                            diff_ratio=0,
                            evidence=f"Template expression {malicious_val} evaluated to 49 (not in baseline)",
                            payload_used=malicious_val,
                        )
        
        return None

    
    def analyze_url(self, url: str) -> List[DiffResult]:
        """Analyze a URL for multiple vulnerability types."""
        results = []
        
        # Try SQLi
        sqli_result = self.analyze_sqli(url)
        if sqli_result:
            results.append(sqli_result)
        
        # Try SSTI
        ssti_result = self.analyze_ssti(url)
        if ssti_result:
            results.append(ssti_result)
        
        return results
    
    def analyze_all(self, urls: List[str], max_workers: int = 10):
        """Analyze all URLs."""
        console.log(f"[cyan]Analyzing {len(urls)} URLs for response differences...[/cyan]")
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(self.analyze_url, url): url for url in urls}
            
            for future in as_completed(futures):
                try:
                    results = future.result()
                    for result in results:
                        self.results.append(result)
                        console.log(f"[red]🎯 {result.vuln_type} found: {result.url[:50]}...[/red]")
                except Exception:
                    pass
        
        console.log(f"[green]Analysis complete. Found {len(self.results)} potential vulnerabilities.[/green]")
    
    def save_results(self):
        """Save analysis results."""
        intel_dir = self.output_dir / 'intel'
        intel_dir.mkdir(exist_ok=True)
        
        if self.results:
            with open(intel_dir / 'response_diff_results.json', 'w') as f:
                json.dump([asdict(r) for r in self.results], f, indent=2)
            
            # Also save to vulns directory
            vuln_dir = self.output_dir / 'vulns'
            vuln_dir.mkdir(exist_ok=True)
            with open(vuln_dir / 'diff_analysis_findings.json', 'w') as f:
                json.dump([asdict(r) for r in self.results], f, indent=2)
    
    def print_summary(self):
        """Print analysis summary."""
        if not self.results:
            console.log("[yellow]No vulnerabilities found via response diff analysis[/yellow]")
            return
        
        table = Table(title="Response Diff Analysis Results")
        table.add_column("Type", style="cyan")
        table.add_column("Param", style="green")
        table.add_column("Confidence", style="yellow")
        table.add_column("URL", style="white")
        
        for r in self.results:
            table.add_row(
                r.vuln_type,
                r.param,
                f"{r.confidence:.0%}",
                r.url[:50] + "..."
            )
        
        console.print(table)


# ============================================================================
# MAIN
# ============================================================================
def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='HybridRecon X - Response Diff Analysis')
    parser.add_argument('--output', '-o', required=True, help='Output directory')
    parser.add_argument('--threads', '-t', type=int, default=10, help='Analysis threads')
    args = parser.parse_args()
    
    console.log("\n[bold magenta]═══ RESPONSE DIFF ANALYSIS ═══[/bold magenta]\n")
    
    analyzer = ResponseDiffAnalyzer(args.output)
    
    urls = analyzer.load_urls()
    if not urls:
        console.log("[yellow]No URLs with parameters found to analyze[/yellow]")
        return
    
    analyzer.analyze_all(urls, max_workers=args.threads)
    analyzer.save_results()
    analyzer.print_summary()
    
    console.log("\n[bold green]Response diff analysis complete![/bold green]\n")


if __name__ == '__main__':
    main()
