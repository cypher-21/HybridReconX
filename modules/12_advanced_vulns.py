#!/usr/bin/env python3
"""
============================================================================
MODULE 13: ADVANCED VULNERABILITIES
============================================================================
Handles vulnerability classes not covered by specific tools:
- CORS Misconfiguration (Corsy)
- CRLF Injection (crlfuzz)
- HTTP Request Smuggling (smuggler)
- Prototype Pollution (ppmap)
- SSL/TLS Issues (testssl)
- 4xx Bypass (nomore403)
- LFI/RFI with payloads (lfimap + custom)
- SSRF Deep Testing (SSRFmap + custom payloads)
- Open Redirect (Oralyzer + payloads)
============================================================================
"""

import argparse
import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from urllib.parse import urlparse

# Add lib to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'lib'))

# Import shared utilities (console, signal handling, ScanConfig, run_command)
from scan_utils import console, is_interrupted, ScanConfig, run_command as shared_run_command

# Import our libraries
try:
    from payload_manager import PayloadManager, SSRFPayloads, LFIPayloads
    from tool_registry import ToolRegistry
except ImportError:
    # Fallback if libraries not available
    PayloadManager = None
    ToolRegistry = None


@dataclass 
class ScanResult:
    """Result of a vulnerability scan."""
    vuln_type: str
    tool: str
    target: str
    severity: str
    details: str
    output_file: Optional[str] = None


class AdvancedVulnScanner:
    """
    Advanced vulnerability scanner for miscellaneous vulnerability classes.
    """
    
    def __init__(self, config: ScanConfig):
        self.config = config
        self.output_dir = Path(config.output_dir)
        self.vuln_dir = self.output_dir / 'vulns' / 'advanced'
        self.vuln_dir.mkdir(parents=True, exist_ok=True)
        self.results: List[ScanResult] = []
        
        # Initialize payload manager
        if PayloadManager:
            PayloadManager.set_base_dir(str(Path(__file__).parent.parent))
    
    def run_command(self, cmd: List[str], output_file: Optional[str] = None,
                    timeout: int = 300) -> Tuple[bool, str, int]:
        """Run a command and capture output. Delegates to shared run_command()."""
        return shared_run_command(cmd, output_file=output_file, timeout=timeout)
    
    # =========================================================================
    # CORS MISCONFIGURATION SCANNING
    # =========================================================================
    def scan_cors(self, targets: List[str]) -> bool:
        """
        Scan for CORS misconfigurations using Corsy or manual testing.
        """
        if not targets:
            console.log("[yellow]No targets for CORS scanning[/yellow]")
            return False
        
        console.log(f"[green]Scanning {len(targets)} targets for CORS misconfigurations[/green]")
        
        cors_dir = self.vuln_dir / 'cors'
        cors_dir.mkdir(exist_ok=True)
        
        # Check if Corsy is available
        if ToolRegistry and ToolRegistry.is_available('corsy'):
            return self._run_corsy(targets, cors_dir)
        else:
            return self._cors_manual_test(targets, cors_dir)
    
    def _run_corsy(self, targets: List[str], output_dir: Path) -> bool:
        """Run Corsy CORS scanner."""
        # Write targets to file
        targets_file = output_dir / 'targets.txt'
        with open(targets_file, 'w') as f:
            f.write('\n'.join(targets[:self.config.max_targets]))
        
        output_file = output_dir / 'corsy_results.json'
        
        cmd = [
            'python3', '-m', 'corsy',
            '-i', str(targets_file),
            '-o', str(output_file),
            '-t', str(self.config.threads),
        ]
        
        success, output, _ = self.run_command(cmd, timeout=600)
        
        if success and output_file.exists():
            self._parse_cors_results(output_file)
        
        return success
    
    def _cors_manual_test(self, targets: List[str], output_dir: Path) -> bool:
        """Manual CORS testing with curl."""
        results_file = output_dir / 'cors_results.txt'
        findings = []
        
        test_origins = [
            'https://evil.com',
            'null',
            'https://target.com.evil.com',
        ]
        
        for target in targets[:50]:
            for origin in test_origins:
                try:
                    result = subprocess.run(
                        ['curl', '-s', '-I', '-H', f'Origin: {origin}', 
                         '--max-time', '10', target],
                        capture_output=True,
                        text=True,
                        timeout=15
                    )
                    
                    headers = result.stdout.lower()
                    
                    # Check for CORS misconfigurations
                    if 'access-control-allow-origin' in headers:
                        if origin.lower() in headers or '*' in headers:
                            finding = {
                                'url': target,
                                'origin': origin,
                                'type': 'cors_misconfiguration',
                                'severity': 'high' if 'credentials' in headers else 'medium'
                            }
                            findings.append(finding)
                            console.log(f"[red]CORS Issue: {target} reflects {origin}[/red]")
                            
                            self.results.append(ScanResult(
                                vuln_type='CORS',
                                tool='curl',
                                target=target,
                                severity=finding['severity'],
                                details=f"Reflects origin: {origin}"
                            ))
                
                except Exception as e:
                    continue
        
        if findings:
            with open(results_file, 'w') as f:
                json.dump(findings, f, indent=2)
        
        return True
    
    def _parse_cors_results(self, results_file: Path):
        """Parse Corsy results and add to findings."""
        try:
            with open(results_file) as f:
                data = json.load(f)
            
            for item in data:
                if item.get('vulnerable'):
                    self.results.append(ScanResult(
                        vuln_type='CORS',
                        tool='corsy',
                        target=item.get('url', ''),
                        severity='high',
                        details=item.get('type', 'CORS misconfiguration'),
                        output_file=str(results_file)
                    ))
        except Exception as e:
            console.log(f"[yellow]Could not parse Corsy results: {e}[/yellow]")
    
    # =========================================================================
    # CRLF INJECTION SCANNING
    # =========================================================================
    def scan_crlf(self, targets: List[str]) -> bool:
        """
        Scan for CRLF injection vulnerabilities.
        """
        if not targets:
            console.log("[yellow]No targets for CRLF scanning[/yellow]")
            return False
        
        console.log(f"[green]Scanning {len(targets)} targets for CRLF injection[/green]")
        
        crlf_dir = self.vuln_dir / 'crlf'
        crlf_dir.mkdir(exist_ok=True)
        
        # Check if crlfuzz is available
        if ToolRegistry and ToolRegistry.is_available('crlfuzz'):
            return self._run_crlfuzz(targets, crlf_dir)
        else:
            return self._crlf_manual_test(targets, crlf_dir)
    
    def _run_crlfuzz(self, targets: List[str], output_dir: Path) -> bool:
        """Run crlfuzz scanner."""
        targets_file = output_dir / 'targets.txt'
        with open(targets_file, 'w') as f:
            f.write('\n'.join(targets[:self.config.max_targets]))
        
        output_file = output_dir / 'crlfuzz_results.txt'
        
        cmd = [
            'crlfuzz',
            '-l', str(targets_file),
            '-o', str(output_file),
            '-c', str(self.config.threads),
            '-s',  # Silent
        ]
        
        success, output, _ = self.run_command(cmd, timeout=600)
        
        # Parse results
        if output_file.exists():
            with open(output_file) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        console.log(f"[red]CRLF Found: {line}[/red]")
                        self.results.append(ScanResult(
                            vuln_type='CRLF',
                            tool='crlfuzz',
                            target=line,
                            severity='medium',
                            details='CRLF injection vulnerable',
                            output_file=str(output_file)
                        ))
        
        return success
    
    def _crlf_manual_test(self, targets: List[str], output_dir: Path) -> bool:
        """Manual CRLF testing."""
        payloads = [
            '%0d%0aX-Injected: true',
            '%0aX-Injected: true',
            '%0d%0aSet-Cookie: crlftest=true',
            '%E5%98%8A%E5%98%8DX-Injected: true',
        ]
        
        results_file = output_dir / 'crlf_results.txt'
        findings = []
        
        for target in targets[:30]:
            for payload in payloads:
                test_url = f"{target}{payload}"
                try:
                    result = subprocess.run(
                        ['curl', '-s', '-I', '--max-time', '10', test_url],
                        capture_output=True,
                        text=True,
                        timeout=15
                    )
                    
                    if 'X-Injected' in result.stdout or 'crlftest' in result.stdout:
                        findings.append(target)
                        console.log(f"[red]CRLF Found: {target}[/red]")
                        self.results.append(ScanResult(
                            vuln_type='CRLF',
                            tool='curl',
                            target=target,
                            severity='medium',
                            details=f'Payload: {payload}'
                        ))
                        break
                
                except Exception:
                    continue
        
        if findings:
            with open(results_file, 'w') as f:
                f.write('\n'.join(findings))
        
        return True
    
    # =========================================================================
    # HTTP REQUEST SMUGGLING
    # =========================================================================
    def scan_smuggling(self, targets: List[str]) -> bool:
        """
        Scan for HTTP request smuggling vulnerabilities.
        """
        if not targets:
            console.log("[yellow]No targets for request smuggling scan[/yellow]")
            return False
        
        console.log(f"[green]Scanning {len(targets)} targets for request smuggling[/green]")
        
        smuggle_dir = self.vuln_dir / 'smuggling'
        smuggle_dir.mkdir(exist_ok=True)
        
        # Check if smuggler is available
        smuggler_path = None
        if ToolRegistry:
            smuggler_path = ToolRegistry.find_tool('smuggler')
        
        if not smuggler_path:
            smuggler_paths = [
                '/opt/tools/smuggler/smuggler.py',
                os.path.expanduser('~/tools/smuggler/smuggler.py'),
            ]
            for path in smuggler_paths:
                if os.path.exists(path):
                    smuggler_path = path
                    break
        
        if smuggler_path:
            return self._run_smuggler(targets, smuggle_dir, smuggler_path)
        else:
            console.log("[yellow]Smuggler not available, skipping request smuggling tests[/yellow]")
            return False
    
    def _run_smuggler(self, targets: List[str], output_dir: Path, smuggler_path: str) -> bool:
        """Run smuggler tool."""
        results_file = output_dir / 'smuggler_results.txt'
        
        for target in targets[:20]:  # Limit due to time
            console.log(f"[cyan]Testing smuggling: {target}[/cyan]")
            
            cmd = ['python3', smuggler_path, '-u', target, '-q']
            
            success, output, _ = self.run_command(
                cmd, 
                str(output_dir / f"smuggler_{urlparse(target).netloc}.txt"),
                timeout=120
            )
            
            if 'VULNERABLE' in output.upper():
                console.log(f"[red]Request Smuggling Found: {target}[/red]")
                self.results.append(ScanResult(
                    vuln_type='Request Smuggling',
                    tool='smuggler',
                    target=target,
                    severity='critical',
                    details=output[:200]
                ))
        
        return True
    
    # =========================================================================
    # SSL/TLS TESTING
    # =========================================================================
    def scan_ssl(self, targets: List[str]) -> bool:
        """
        Scan for SSL/TLS misconfigurations using testssl.
        """
        if not targets:
            console.log("[yellow]No targets for SSL/TLS scanning[/yellow]")
            return False
        
        if self.config.fast_mode:
            console.log("[yellow]Skipping SSL tests in fast mode[/yellow]")
            return False
        
        console.log(f"[green]Scanning {len(targets)} targets for SSL/TLS issues[/green]")
        
        ssl_dir = self.vuln_dir / 'ssl'
        ssl_dir.mkdir(exist_ok=True)
        
        # Check if testssl is available
        testssl_path = None
        possible_paths = [
            'testssl',
            '/opt/tools/testssl.sh/testssl.sh',
            '/usr/local/bin/testssl',
        ]
        
        for path in possible_paths:
            try:
                subprocess.run([path, '--version'], capture_output=True, timeout=5)
                testssl_path = path
                break
            except Exception:
                continue
        
        if not testssl_path:
            console.log("[yellow]testssl not available, skipping SSL tests[/yellow]")
            return False
        
        # Test each target (limited due to slow speed)
        for target in targets[:10]:
            # Extract host from URL
            parsed = urlparse(target)
            host = parsed.netloc or parsed.path
            
            if ':' in host:
                test_target = host
            else:
                test_target = f"{host}:443"
            
            console.log(f"[cyan]Testing SSL: {test_target}[/cyan]")
            
            output_file = ssl_dir / f"ssl_{host.replace(':', '_')}.json"
            
            cmd = [
                testssl_path,
                '--jsonfile', str(output_file),
                '--severity', 'MEDIUM',
                '--sneaky',  # Don't trigger WAF
                '--fast',
                test_target
            ]
            
            success, output, _ = self.run_command(cmd, timeout=180)
            
            if output_file.exists():
                self._parse_ssl_results(output_file, target)
        
        return True
    
    def _parse_ssl_results(self, results_file: Path, target: str):
        """Parse testssl JSON results."""
        try:
            with open(results_file) as f:
                data = json.load(f)
            
            for item in data:
                if item.get('severity') in ['CRITICAL', 'HIGH', 'MEDIUM']:
                    self.results.append(ScanResult(
                        vuln_type='SSL/TLS',
                        tool='testssl',
                        target=target,
                        severity=item.get('severity', '').lower(),
                        details=f"{item.get('id')}: {item.get('finding')}",
                        output_file=str(results_file)
                    ))
        except Exception as e:
            console.log(f"[yellow]Could not parse testssl results: {e}[/yellow]")
    
    # =========================================================================
    # 4XX BYPASS TESTING
    # =========================================================================
    def scan_4xx_bypass(self, targets: List[str]) -> bool:
        """
        Attempt to bypass 403/401 responses using nomore403.
        """
        if not targets:
            console.log("[yellow]No targets for 4xx bypass testing[/yellow]")
            return False
        
        console.log(f"[green]Testing {len(targets)} targets for 4xx bypass[/green]")
        
        bypass_dir = self.vuln_dir / '4xx_bypass'
        bypass_dir.mkdir(exist_ok=True)
        
        # Check if nomore403 is available
        if not (ToolRegistry and ToolRegistry.is_available('nomore403')):
            console.log("[yellow]nomore403 not available, using manual bypass techniques[/yellow]")
            return self._4xx_manual_bypass(targets, bypass_dir)
        
        results_file = bypass_dir / 'bypass_results.txt'
        
        for target in targets[:30]:
            cmd = ['nomore403', '-u', target]
            
            success, output, _ = self.run_command(cmd, timeout=60)
            
            if 'BYPASS' in output.upper() or '200' in output:
                console.log(f"[red]4xx Bypass Found: {target}[/red]")
                with open(results_file, 'a') as f:
                    f.write(f"{target}\n")
                    f.write(f"{output}\n\n")
                
                self.results.append(ScanResult(
                    vuln_type='4xx Bypass',
                    tool='nomore403',
                    target=target,
                    severity='medium',
                    details='Access control bypass possible'
                ))
        
        return True
    
    def _4xx_manual_bypass(self, targets: List[str], output_dir: Path) -> bool:
        """Manual 4xx bypass testing."""
        bypass_techniques = [
            ('X-Original-URL', '/'),
            ('X-Rewrite-URL', '/'),
            ('X-Forwarded-For', '127.0.0.1'),
            ('X-Custom-IP-Authorization', '127.0.0.1'),
        ]
        
        path_bypasses = [
            '/',
            '/.//',
            '/../',
            '%2e/',
            '.json',
            '?',
            '#',
            '/*',
            '..;/',
        ]
        
        findings = []
        
        for target in targets[:20]:
            # Test header bypasses
            for header, value in bypass_techniques:
                try:
                    result = subprocess.run(
                        ['curl', '-s', '-o', '/dev/null', '-w', '%{http_code}',
                         '-H', f'{header}: {value}', '--max-time', '10', target],
                        capture_output=True,
                        text=True,
                        timeout=15
                    )
                    
                    if result.stdout.strip() in ['200', '301', '302']:
                        console.log(f"[red]Bypass with {header}: {target}[/red]")
                        findings.append(f"{target} - {header}: {value}")
                        self.results.append(ScanResult(
                            vuln_type='4xx Bypass',
                            tool='curl',
                            target=target,
                            severity='medium',
                            details=f'Bypass with header {header}'
                        ))
                        break
                
                except Exception:
                    continue
        
        if findings:
            with open(output_dir / 'bypass_results.txt', 'w') as f:
                f.write('\n'.join(findings))
        
        return True
    
    # =========================================================================
    # SSRF DEEP TESTING
    # =========================================================================
    def scan_ssrf(self, targets_file: str, callback_url: Optional[str] = None) -> bool:
        """
        Deep SSRF testing with payloads and optional OOB callback.
        """
        if not os.path.exists(targets_file):
            console.log("[yellow]No SSRF candidates file found[/yellow]")
            return False
        
        console.log(f"[green]Running deep SSRF testing[/green]")
        
        ssrf_dir = self.vuln_dir / 'ssrf'
        ssrf_dir.mkdir(exist_ok=True)
        
        # Load payloads
        if PayloadManager:
            payloads = PayloadManager.get_payloads('ssrf', max_payloads=100)
        else:
            payloads = SSRFPayloads.get_cloud_metadata_urls() + SSRFPayloads.get_localhost_bypasses()
        
        # Add callback-based payloads if provided
        if callback_url:
            payloads.extend(SSRFPayloads.generate_with_callback(callback_url))
        
        # Load targets
        with open(targets_file) as f:
            targets = [line.strip() for line in f if line.strip()][:50]
        
        console.log(f"[cyan]Testing {len(targets)} targets with {len(payloads)} payloads[/cyan]")
        
        findings = []
        
        for target in targets:
            for payload in payloads[:20]:  # Limit payloads per target
                try:
                    # Replace parameter value with payload
                    if '=' in target:
                        test_url = target.rsplit('=', 1)[0] + '=' + payload
                    else:
                        test_url = f"{target}?url={payload}"
                    
                    result = subprocess.run(
                        ['curl', '-s', '-k', '-L', '--max-time', '10', test_url],
                        capture_output=True,
                        text=True,
                        timeout=15
                    )
                    
                    response = result.stdout.lower()
                    
                    # Check for SSRF indicators
                    indicators = [
                        'ami-id', 'instance-id', 'meta-data',
                        'computemetadata', 'root:x:', 'openss',
                        'localhost', '127.0.0.1', callback_url or ''
                    ]
                    
                    for indicator in indicators:
                        if indicator and indicator.lower() in response:
                            console.log(f"[red]SSRF Found: {target} -> {payload[:50]}[/red]")
                            findings.append({
                                'target': target,
                                'payload': payload,
                                'indicator': indicator
                            })
                            self.results.append(ScanResult(
                                vuln_type='SSRF',
                                tool='curl',
                                target=target,
                                severity='critical',
                                details=f'Payload: {payload[:50]}, Indicator: {indicator}'
                            ))
                            break
                
                except Exception:
                    continue
        
        if findings:
            with open(ssrf_dir / 'ssrf_results.json', 'w') as f:
                json.dump(findings, f, indent=2)
        
        return True
    
    # =========================================================================
    # LFI DEEP TESTING
    # =========================================================================
    def scan_lfi(self, targets_file: str) -> bool:
        """
        Deep LFI testing with payload integration.
        """
        if not os.path.exists(targets_file):
            console.log("[yellow]No LFI candidates file found[/yellow]")
            return False
        
        console.log(f"[green]Running deep LFI testing[/green]")
        
        lfi_dir = self.vuln_dir / 'lfi'
        lfi_dir.mkdir(exist_ok=True)
        
        # Check if lfimap is available
        if ToolRegistry and ToolRegistry.is_available('lfimap'):
            return self._run_lfimap(targets_file, lfi_dir)
        
        # Fall back to custom testing
        return self._lfi_custom_test(targets_file, lfi_dir)
    
    def _run_lfimap(self, targets_file: str, output_dir: Path) -> bool:
        """Run lfimap tool."""
        output_file = output_dir / 'lfimap_results.txt'
        
        cmd = [
            'lfimap',
            '-L', targets_file,
            '-o', str(output_file),
        ]
        
        success, output, _ = self.run_command(cmd, timeout=600)
        
        if 'VULN' in output.upper() or 'FOUND' in output.upper():
            console.log("[red]LFI vulnerabilities found![/red]")
        
        return success
    
    def _lfi_custom_test(self, targets_file: str, output_dir: Path) -> bool:
        """Custom LFI testing with payloads."""
        # Load payloads
        if PayloadManager:
            payloads = PayloadManager.get_payloads('lfi', max_payloads=50)
        else:
            payloads = LFIPayloads.get_traversal_depths('/etc/passwd', 8)
        
        with open(targets_file) as f:
            targets = [line.strip() for line in f if line.strip()][:30]
        
        findings = []
        
        for target in targets:
            for payload in payloads[:15]:
                try:
                    if '=' in target:
                        test_url = target.rsplit('=', 1)[0] + '=' + payload
                    else:
                        test_url = f"{target}?file={payload}"
                    
                    result = subprocess.run(
                        ['curl', '-s', '-k', '--max-time', '10', test_url],
                        capture_output=True,
                        text=True,
                        timeout=15
                    )
                    
                    # Check for LFI success indicators
                    if any(ind in result.stdout for ind in ['root:x:', 'root:*:', '[extensions]', 'daemon:']):
                        console.log(f"[red]LFI Found: {target}[/red]")
                        findings.append({'target': target, 'payload': payload})
                        self.results.append(ScanResult(
                            vuln_type='LFI',
                            tool='curl',
                            target=target,
                            severity='critical',
                            details=f'Payload: {payload}'
                        ))
                        break
                
                except Exception:
                    continue
        
        if findings:
            with open(output_dir / 'lfi_results.json', 'w') as f:
                json.dump(findings, f, indent=2)
        
        return True
    
    # =========================================================================
    # OPEN REDIRECT TESTING
    # =========================================================================
    def scan_open_redirect(self, targets_file: str) -> bool:
        """
        Open redirect testing with Oralyzer or custom payloads.
        """
        if not os.path.exists(targets_file):
            console.log("[yellow]No redirect candidates file found[/yellow]")
            return False
        
        console.log(f"[green]Running open redirect testing[/green]")
        
        redirect_dir = self.vuln_dir / 'redirect'
        redirect_dir.mkdir(exist_ok=True)
        
        # Check if oralyzer is available
        if ToolRegistry and ToolRegistry.is_available('oralyzer'):
            return self._run_oralyzer(targets_file, redirect_dir)
        
        return self._redirect_custom_test(targets_file, redirect_dir)
    
    def _run_oralyzer(self, targets_file: str, output_dir: Path) -> bool:
        """Run Oralyzer tool."""
        with open(targets_file) as f:
            targets = [line.strip() for line in f if line.strip()][:50]
        
        findings = []
        
        for target in targets:
            cmd = ['oralyzer', '-u', target]
            success, output, _ = self.run_command(cmd, timeout=30)
            
            if 'VULNERABLE' in output.upper():
                console.log(f"[red]Open Redirect Found: {target}[/red]")
                findings.append(target)
                self.results.append(ScanResult(
                    vuln_type='Open Redirect',
                    tool='oralyzer',
                    target=target,
                    severity='medium',
                    details='Vulnerable to open redirect'
                ))
        
        if findings:
            with open(output_dir / 'redirect_results.txt', 'w') as f:
                f.write('\n'.join(findings))
        
        return True
    
    def _redirect_custom_test(self, targets_file: str, output_dir: Path) -> bool:
        """Custom open redirect testing."""
        payloads = [
            'https://evil.com',
            '//evil.com',
            '/\\evil.com',
            'https://evil.com/%2f%2e%2e',
            '////evil.com',
            'https:evil.com',
        ]
        
        with open(targets_file) as f:
            targets = [line.strip() for line in f if line.strip()][:30]
        
        findings = []
        
        for target in targets:
            for payload in payloads:
                try:
                    if '=' in target:
                        test_url = target.rsplit('=', 1)[0] + '=' + payload
                    else:
                        test_url = f"{target}?url={payload}"
                    
                    result = subprocess.run(
                        ['curl', '-s', '-I', '-L', '--max-time', '10', 
                         '--max-redirs', '5', test_url],
                        capture_output=True,
                        text=True,
                        timeout=20
                    )
                    
                    headers_lower = result.stdout.lower()
                    if 'evil.com' in headers_lower:
                        console.log(f"[red]Open Redirect Found: {target}[/red]")
                        findings.append(target)
                        self.results.append(ScanResult(
                            vuln_type='Open Redirect',
                            tool='curl',
                            target=target,
                            severity='medium',
                            details=f'Payload: {payload}'
                        ))
                        break
                
                except Exception:
                    continue
        
        if findings:
            with open(output_dir / 'redirect_results.txt', 'w') as f:
                f.write('\n'.join(findings))
        
        return True
    
    # =========================================================================
    # MAIN ORCHESTRATION
    # =========================================================================
    def run_all(self):
        """Run all advanced vulnerability scans."""
        console.print("\n[bold cyan]═══════════════════════════════════════════════════════════[/bold cyan]")
        console.print("[bold cyan]  ADVANCED VULNERABILITY SCANNER[/bold cyan]")
        console.print("[bold cyan]═══════════════════════════════════════════════════════════[/bold cyan]\n")
        
        # Load targets from various sources
        probe_dir = self.output_dir / 'probed'
        param_dir = self.output_dir / 'params'
        
        # Get live hosts for general scanning
        live_hosts_file = probe_dir / 'live_hosts.txt'
        live_hosts = []
        if live_hosts_file.exists():
            with open(live_hosts_file) as f:
                live_hosts = [line.strip() for line in f if line.strip()]
        
        # Run scans
        if live_hosts:
            self.scan_cors(live_hosts[:self.config.max_targets])
            self.scan_crlf(live_hosts[:self.config.max_targets])
            self.scan_ssl(live_hosts[:20])  # SSL is slow
            self.scan_smuggling(live_hosts[:20])  # Also slow
        
        # Scan specific candidates
        ssrf_file = param_dir / 'gf_ssrf.txt'
        if ssrf_file.exists():
            self.scan_ssrf(str(ssrf_file))
        
        lfi_file = param_dir / 'gf_lfi.txt'
        if lfi_file.exists():
            self.scan_lfi(str(lfi_file))
        
        redirect_file = param_dir / 'gf_redirect.txt'
        if redirect_file.exists():
            self.scan_open_redirect(str(redirect_file))
        
        # Find 403/401 responses for bypass testing
        status_codes_file = probe_dir / 'status_codes.txt'
        forbidden_urls = []
        if status_codes_file.exists():
            with open(status_codes_file) as f:
                for line in f:
                    if '403' in line or '401' in line:
                        parts = line.strip().split()
                        if parts:
                            forbidden_urls.append(parts[0])
        
        if forbidden_urls:
            self.scan_4xx_bypass(forbidden_urls[:30])
        
        # Generate summary
        self._generate_summary()
    
    def _generate_summary(self):
        """Generate summary of findings."""
        summary_file = self.vuln_dir / 'advanced_summary.json'
        
        summary = {
            'total_findings': len(self.results),
            'by_type': {},
            'by_severity': {},
            'findings': []
        }
        
        for result in self.results:
            # Count by type
            if result.vuln_type not in summary['by_type']:
                summary['by_type'][result.vuln_type] = 0
            summary['by_type'][result.vuln_type] += 1
            
            # Count by severity
            if result.severity not in summary['by_severity']:
                summary['by_severity'][result.severity] = 0
            summary['by_severity'][result.severity] += 1
            
            # Add to findings
            summary['findings'].append({
                'type': result.vuln_type,
                'tool': result.tool,
                'target': result.target,
                'severity': result.severity,
                'details': result.details
            })
        
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2)
        
        # Print summary
        console.print("\n[bold cyan]═══════════════════════════════════════════════════════════[/bold cyan]")
        console.print("[bold cyan]  ADVANCED SCAN SUMMARY[/bold cyan]")
        console.print("[bold cyan]═══════════════════════════════════════════════════════════[/bold cyan]\n")
        
        console.print(f"[green]Total findings: {summary['total_findings']}[/green]")
        
        console.print("\n[yellow]By Type:[/yellow]")
        for vtype, count in summary['by_type'].items():
            console.print(f"  - {vtype}: {count}")
        
        console.print("\n[yellow]By Severity:[/yellow]")
        for severity, count in summary['by_severity'].items():
            color = 'red' if severity == 'critical' else 'yellow' if severity == 'high' else 'cyan'
            console.print(f"  [{color}]- {severity}: {count}[/{color}]")
        
        console.print(f"\n[green]Results saved to: {summary_file}[/green]")


def parse_int_or_default(value, default):
    """Parse int from string, return default if empty or invalid."""
    if value is None or value == '':
        return default
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


def main():
    parser = argparse.ArgumentParser(
        description='HybridRecon X - Advanced Vulnerability Scanner'
    )
    parser.add_argument('--output', '-o', required=True, help='Output directory')
    parser.add_argument('--config', '-c', help='Config file path')
    parser.add_argument('--threads', '-t', default='10', help='Number of threads')
    parser.add_argument('--rate-limit', '-r', default='100', help='Rate limit')
    parser.add_argument('--fast', action='store_true', help='Fast mode - skip slow scans')
    parser.add_argument('--stealth', action='store_true', help='Stealth mode - lower rate')
    parser.add_argument('--max-targets', default='100', help='Max targets per scan')
    
    # Specific scan options
    parser.add_argument('--cors-only', action='store_true', help='Only run CORS scan')
    parser.add_argument('--crlf-only', action='store_true', help='Only run CRLF scan')
    parser.add_argument('--ssl-only', action='store_true', help='Only run SSL scan')
    parser.add_argument('--smuggle-only', action='store_true', help='Only run smuggling scan')
    
    args = parser.parse_args()
    
    config = ScanConfig(
        output_dir=args.output,
        config_file=args.config,
        threads=parse_int_or_default(args.threads, 10),
        rate_limit=parse_int_or_default(args.rate_limit, 100),
        fast_mode=args.fast,
        stealth_mode=args.stealth,
        max_targets=parse_int_or_default(args.max_targets, 100),
    )
    
    scanner = AdvancedVulnScanner(config)
    
    # Run specific scans or all
    if args.cors_only or args.crlf_only or args.ssl_only or args.smuggle_only:
        probe_dir = Path(args.output) / 'probed'
        live_hosts_file = probe_dir / 'live_hosts.txt'
        live_hosts = []
        if live_hosts_file.exists():
            with open(live_hosts_file) as f:
                live_hosts = [line.strip() for line in f if line.strip()]
        
        if args.cors_only:
            scanner.scan_cors(live_hosts)
        if args.crlf_only:
            scanner.scan_crlf(live_hosts)
        if args.ssl_only:
            scanner.scan_ssl(live_hosts)
        if args.smuggle_only:
            scanner.scan_smuggling(live_hosts)
        
        scanner._generate_summary()
    else:
        scanner.run_all()


if __name__ == '__main__':
    main()
