#!/usr/bin/env python3
"""
============================================================================
DATA AGGREGATOR - Normalize All Module Outputs
============================================================================
Parses outputs from all modules, builds a normalized dataset for reporting.
Correlates findings by: host, endpoint, parameter, tool, severity.
============================================================================
"""

import json
import os
import re
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field, asdict
from collections import defaultdict


@dataclass
class Finding:
    """Normalized vulnerability finding."""
    id: str
    host: str
    url: str
    vuln_type: str
    severity: str
    tool: str
    confidence: float = 0.0
    parameter: str = ""
    payload: str = ""
    evidence: str = ""
    poc: str = ""
    validated: bool = False
    timestamp: str = ""


@dataclass
class HostInfo:
    """Information about a discovered host."""
    hostname: str
    ip: str = ""
    ports: List[int] = field(default_factory=list)
    technologies: List[str] = field(default_factory=list)
    status_code: int = 0
    title: str = ""
    content_length: int = 0
    waf_detected: str = ""


@dataclass
class ScanData:
    """Complete aggregated scan data."""
    target: str
    scan_started: str
    scan_completed: str = ""
    duration_seconds: int = 0
    
    # Discovery
    subdomains: List[str] = field(default_factory=list)
    hosts: Dict[str, HostInfo] = field(default_factory=dict)
    urls: List[str] = field(default_factory=list)
    parameters: List[str] = field(default_factory=list)
    js_files: List[str] = field(default_factory=list)
    
    # Intelligence
    js_secrets: List[Dict] = field(default_factory=list)
    js_endpoints: List[str] = field(default_factory=list)
    dom_xss_vectors: List[Dict] = field(default_factory=list)
    
    # Vulnerabilities
    findings: List[Finding] = field(default_factory=list)
    
    # Metadata
    modules_run: List[str] = field(default_factory=list)
    modules_skipped: List[Dict] = field(default_factory=list)
    tools_skipped: List[Dict] = field(default_factory=list)
    tool_errors: List[Dict] = field(default_factory=list)


class DataAggregator:
    """Aggregates data from all module outputs."""
    
    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.data = ScanData(
            target="",
            scan_started=datetime.now().isoformat()
        )
        self.finding_counter = 0
    
    def aggregate_all(self) -> ScanData:
        """Run all aggregation steps."""
        print("[AGGREGATOR] Starting data aggregation...")
        
        self._load_target_info()
        self._load_subdomains()
        self._load_hosts()
        self._load_urls()
        self._load_parameters()
        self._load_js_intel()
        self._load_nuclei_findings()
        self._load_validated_findings()
        self._load_exploit_findings()
        self._load_advanced_findings()
        self._load_response_diff_findings()
        self._load_module_metadata()
        
        self.data.scan_completed = datetime.now().isoformat()
        
        print(f"[AGGREGATOR] Aggregation complete:")
        print(f"  - Subdomains: {len(self.data.subdomains)}")
        print(f"  - Hosts: {len(self.data.hosts)}")
        print(f"  - URLs: {len(self.data.urls)}")
        print(f"  - Findings: {len(self.data.findings)}")
        
        return self.data
    
    def _load_target_info(self):
        """Load target information."""
        # Try to get target from various sources
        target_file = self.output_dir / '.target'
        if target_file.exists():
            self.data.target = target_file.read_text().strip()
        else:
            # Infer from output directory name
            self.data.target = self.output_dir.parent.name
    
    def _load_subdomains(self):
        """Load discovered subdomains."""
        files = [
            self.output_dir / 'recon' / 'clean_subdomains.txt',
            self.output_dir / 'recon' / 'all_subdomains.txt',
        ]
        
        subdomains = set()
        for f in files:
            if f.exists():
                subdomains.update(line.strip() for line in f.read_text().splitlines() if line.strip())
        
        self.data.subdomains = sorted(subdomains)
    
    def _load_hosts(self):
        """Load live host information."""
        # Load from httpx output
        httpx_file = self.output_dir / 'probed' / 'httpx_full.json'
        if httpx_file.exists():
            for line in httpx_file.read_text().splitlines():
                try:
                    data = json.loads(line)
                    host = data.get('host', data.get('url', ''))
                    if host:
                        self.data.hosts[host] = HostInfo(
                            hostname=host,
                            ip=data.get('a', [''])[0] if data.get('a') else '',
                            status_code=data.get('status_code', 0),
                            title=data.get('title', ''),
                            content_length=data.get('content_length', 0),
                            technologies=data.get('tech', []),
                        )
                except json.JSONDecodeError:
                    continue
        
        # Fallback to simple list
        if not self.data.hosts:
            live_file = self.output_dir / 'probed' / 'live_hosts.txt'
            if live_file.exists():
                for line in live_file.read_text().splitlines():
                    host = line.strip()
                    if host:
                        self.data.hosts[host] = HostInfo(hostname=host)
        
        # Load tech fingerprinting
        tech_file = self.output_dir / 'fingerprint' / 'tech_details.json'
        if tech_file.exists():
            try:
                tech_data = json.loads(tech_file.read_text())
                for host, techs in tech_data.items():
                    if host in self.data.hosts:
                        self.data.hosts[host].technologies = techs
            except (json.JSONDecodeError, TypeError):
                pass
        
        # Load WAF detection
        waf_file = self.output_dir / 'fingerprint' / 'waf_results.txt'
        if waf_file.exists():
            for line in waf_file.read_text().splitlines():
                parts = line.strip().split()
                if len(parts) >= 2:
                    host, waf = parts[0], ' '.join(parts[1:])
                    if host in self.data.hosts:
                        self.data.hosts[host].waf_detected = waf
    
    def _load_urls(self):
        """Load discovered URLs."""
        files = [
            self.output_dir / 'content' / 'all_urls.txt',
            self.output_dir / 'content' / 'katana_output.txt',
        ]
        
        urls = set()
        for f in files:
            if f.exists():
                urls.update(line.strip() for line in f.read_text().splitlines() 
                           if line.strip() and line.strip().startswith('http'))
        
        self.data.urls = sorted(urls)[:5000]  # Limit for report size
    
    def _load_parameters(self):
        """Load mined parameters."""
        param_file = self.output_dir / 'params' / 'urls_with_params.txt'
        if param_file.exists():
            self.data.parameters = [
                line.strip() for line in param_file.read_text().splitlines()
                if line.strip()
            ][:1000]
    
    def _load_js_intel(self):
        """Load JavaScript analysis results."""
        intel_dir = self.output_dir / 'intel'
        
        # Secrets
        secrets_file = intel_dir / 'js_secrets.json'
        if secrets_file.exists():
            try:
                self.data.js_secrets = json.loads(secrets_file.read_text())
            except json.JSONDecodeError:
                pass
        
        # Endpoints
        endpoints_file = intel_dir / 'js_endpoints.txt'
        if endpoints_file.exists():
            self.data.js_endpoints = [
                line.strip() for line in endpoints_file.read_text().splitlines()
                if line.strip()
            ]
        
        # DOM XSS
        dom_file = intel_dir / 'dom_xss_vectors.json'
        if dom_file.exists():
            try:
                self.data.dom_xss_vectors = json.loads(dom_file.read_text())
            except json.JSONDecodeError:
                pass
    
    def _safe_read_file(self, filepath: Path) -> str:
        """Safely read a file, returning empty string on any error."""
        try:
            if filepath.exists() and filepath.is_file():
                return filepath.read_text(errors='ignore')
        except Exception as e:
            print(f"[AGGREGATOR] Warning: Could not read {filepath}: {e}")
        return ""
    
    def _safe_read_json(self, filepath: Path) -> Any:
        """Safely read and parse a JSON file."""
        try:
            if filepath.exists() and filepath.is_file():
                content = filepath.read_text(errors='ignore')
                if content.strip():
                    return json.loads(content)
        except (json.JSONDecodeError, Exception) as e:
            print(f"[AGGREGATOR] Warning: Could not parse JSON {filepath}: {e}")
        return None
    
    def _load_nuclei_findings(self):
        """Load Nuclei scan results."""
        vuln_dir = self.output_dir / 'vulns'
        
        if not vuln_dir.exists():
            print(f"[AGGREGATOR] No vulns directory found")
            return
        
        nuclei_files = list(vuln_dir.glob('nuclei*.txt')) + list(vuln_dir.glob('nuclei*.json'))
        
        if not nuclei_files:
            print(f"[AGGREGATOR] No Nuclei result files found")
            return
        
        print(f"[AGGREGATOR] Loading {len(nuclei_files)} Nuclei result files")
        
        for f in nuclei_files:
            content = self._safe_read_file(f)
            if not content:
                continue
            
            # Try parsing as full JSON array first (nuclei -je outputs JSON array)
            try:
                full_data = json.loads(content)
                if isinstance(full_data, list):
                    for item in full_data:
                        if isinstance(item, dict):
                            self._add_nuclei_finding(item)
                    continue
                elif isinstance(full_data, dict):
                    self._add_nuclei_finding(full_data)
                    continue
            except json.JSONDecodeError:
                pass
            
            # Fall back to JSONL format (one JSON object per line)
            for line in content.splitlines():
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                    if isinstance(data, dict):
                        self._add_nuclei_finding(data)
                    elif isinstance(data, list):
                        for item in data:
                            if isinstance(item, dict):
                                self._add_nuclei_finding(item)
                except json.JSONDecodeError:
                    # Parse text format: [severity] [template] [protocol] url
                    match = re.search(r'\[(critical|high|medium|low|info)\]\s*\[([^\]]+)\].*?(https?://\S+)', line, re.I)
                    if match:
                        self._add_finding(
                            host=match.group(3).split('/')[2] if '/' in match.group(3) else match.group(3),
                            url=match.group(3),
                            vuln_type=match.group(2),
                            severity=match.group(1).lower(),
                            tool='nuclei',
                        )
    
    def _add_nuclei_finding(self, data: dict):
        """Add a single Nuclei finding from parsed JSON data."""
        if not isinstance(data, dict):
            return
        info = data.get('info', {})
        if not isinstance(info, dict):
            info = {}
        self._add_finding(
            host=data.get('host', ''),
            url=data.get('matched-at', data.get('host', '')),
            vuln_type=data.get('template-id', 'unknown'),
            severity=info.get('severity', 'medium'),
            tool='nuclei',
            evidence=data.get('matched-line', ''),
        )
    
    def _load_validated_findings(self):
        """Load validated vulnerability findings."""
        vuln_dir = self.output_dir / 'vulns'
        
        for confidence_level in ['high', 'medium']:
            file_path = vuln_dir / f'validated_{confidence_level}.json'
            if file_path.exists():
                try:
                    findings = json.loads(file_path.read_text())
                    for f in findings:
                        self._add_finding(
                            host=self._extract_host(f.get('url', '')),
                            url=f.get('url', ''),
                            vuln_type=f.get('vuln_type', 'unknown'),
                            severity=f.get('severity', 'medium'),
                            tool=f.get('source', 'validator'),
                            confidence=f.get('confidence_score', 0.5),
                            payload=f.get('payload', ''),
                            evidence=f.get('evidence', ''),
                            poc=f.get('poc', ''),
                            validated=True,
                        )
                except json.JSONDecodeError:
                    pass
    
    def _load_exploit_findings(self):
        """Load findings from exploit tools."""
        exploit_dir = self.output_dir / 'exploits'
        
        if not exploit_dir.exists():
            return
        
        # SQLMap
        for log_file in exploit_dir.glob('sqlmap/**/*.log'):
            content = self._safe_read_file(log_file)
            if 'injectable' in content.lower() or 'vulnerable' in content.lower():
                # Extract URL from log
                url_match = re.search(r'https?://\S+', content)
                if url_match:
                    self._add_finding(
                        host=self._extract_host(url_match.group()),
                        url=url_match.group(),
                        vuln_type='SQL Injection',
                        severity='high',
                        tool='sqlmap',
                    )
        
        # XSStrike
        for result_file in exploit_dir.glob('xsstrike/*.txt'):
            content = self._safe_read_file(result_file)
            if 'vulnerable' in content.lower():
                url_match = re.search(r'https?://\S+', content)
                if url_match:
                    self._add_finding(
                        host=self._extract_host(url_match.group()),
                        url=url_match.group(),
                        vuln_type='XSS',
                        severity='high',
                        tool='xsstrike',
                    )
        
        # LFI results
        lfi_file = exploit_dir / 'lfi_results.txt'
        if lfi_file.exists():
            for line in self._safe_read_file(lfi_file).splitlines():
                if line.strip():
                    self._add_finding(
                        host=self._extract_host(line),
                        url=line.strip(),
                        vuln_type='LFI',
                        severity='high',
                        tool='custom',
                    )
        
        # SSRF results
        ssrf_file = exploit_dir / 'ssrf_results.txt'
        if ssrf_file.exists():
            for line in self._safe_read_file(ssrf_file).splitlines():
                if line.strip():
                    self._add_finding(
                        host=self._extract_host(line),
                        url=line.strip(),
                        vuln_type='SSRF',
                        severity='critical',
                        tool='custom',
                    )
    
    def _load_advanced_findings(self):
        """Load findings from advanced vulnerability module."""
        advanced_dir = self.output_dir / 'vulns' / 'advanced'
        
        if not advanced_dir.exists():
            return
        
        # Summary file
        summary_file = advanced_dir / 'advanced_summary.json'
        if summary_file.exists():
            try:
                summary = json.loads(summary_file.read_text())
                for finding in summary.get('findings', []):
                    self._add_finding(
                        host=self._extract_host(finding.get('target', '')),
                        url=finding.get('target', ''),
                        vuln_type=finding.get('type', 'unknown'),
                        severity=finding.get('severity', 'medium'),
                        tool=finding.get('tool', 'advanced'),
                        evidence=finding.get('details', ''),
                    )
            except json.JSONDecodeError:
                pass
    
    def _load_response_diff_findings(self):
        """Load response diff analysis findings."""
        diff_file = self.output_dir / 'intel' / 'response_diff_results.json'
        
        if diff_file.exists():
            try:
                findings = json.loads(diff_file.read_text())
                for f in findings:
                    self._add_finding(
                        host=self._extract_host(f.get('url', '')),
                        url=f.get('url', ''),
                        vuln_type=f.get('vuln_type', 'unknown'),
                        severity='high' if f.get('confidence', 0) > 0.8 else 'medium',
                        tool='response_diff',
                        confidence=f.get('confidence', 0),
                        parameter=f.get('param', ''),
                        payload=f.get('payload_used', ''),
                        evidence=f.get('evidence', ''),
                    )
            except json.JSONDecodeError:
                pass
    
    def _load_module_metadata(self):
        """Load metadata about module execution."""
        logs_dir = self.output_dir / 'logs'
        
        # Skipped modules
        skipped_file = logs_dir / 'skipped_modules.json'
        if skipped_file.exists():
            try:
                self.data.modules_skipped = json.loads(skipped_file.read_text())
            except json.JSONDecodeError:
                pass
        
        # Skipped tools
        tools_file = logs_dir / 'skipped_tools.txt'
        if tools_file.exists():
            for line in tools_file.read_text().splitlines():
                parts = line.split('|')
                if len(parts) >= 3:
                    self.data.tools_skipped.append({
                        'timestamp': parts[0].strip(),
                        'tool': parts[1].strip(),
                        'reason': parts[2].strip(),
                    })
    
    def _add_finding(self, host: str, url: str, vuln_type: str, severity: str, tool: str,
                     confidence: float = 0.0, parameter: str = "", payload: str = "",
                     evidence: str = "", poc: str = "", validated: bool = False):
        """Add a normalized finding."""
        self.finding_counter += 1
        
        finding = Finding(
            id=f"FINDING-{self.finding_counter:04d}",
            host=host,
            url=url,
            vuln_type=vuln_type,
            severity=severity.lower(),
            tool=tool,
            confidence=confidence,
            parameter=parameter,
            payload=payload,
            evidence=evidence,
            poc=poc,
            validated=validated,
            timestamp=datetime.now().isoformat(),
        )
        
        self.data.findings.append(finding)
    
    def _extract_host(self, url: str) -> str:
        """Extract host from URL."""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            return parsed.netloc or parsed.path.split('/')[0]
        except:
            return url.split('/')[2] if url.count('/') >= 2 else url
    
    def save(self, output_path: Optional[str] = None) -> str:
        """Save aggregated data to JSON."""
        if output_path is None:
            output_path = str(self.output_dir / 'reports' / 'aggregated_data.json')
        
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        
        # Convert to serializable format
        data_dict = {
            'target': self.data.target,
            'scan_started': self.data.scan_started,
            'scan_completed': self.data.scan_completed,
            'stats': {
                'subdomains': len(self.data.subdomains),
                'hosts': len(self.data.hosts),
                'urls': len(self.data.urls),
                'parameters': len(self.data.parameters),
                'findings': len(self.data.findings),
                'js_secrets': len(self.data.js_secrets),
                'js_endpoints': len(self.data.js_endpoints),
            },
            'subdomains': self.data.subdomains[:100],  # Limit for file size
            'hosts': {k: asdict(v) for k, v in list(self.data.hosts.items())[:100]},
            'findings': [asdict(f) for f in self.data.findings],
            'js_secrets': self.data.js_secrets,
            'js_endpoints': self.data.js_endpoints[:100],
            'dom_xss_vectors': self.data.dom_xss_vectors,
            'modules_skipped': self.data.modules_skipped,
            'tools_skipped': self.data.tools_skipped,
        }
        
        with open(output_path, 'w') as f:
            json.dump(data_dict, f, indent=2, default=str)
        
        print(f"[AGGREGATOR] Data saved to: {output_path}")
        return output_path


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Aggregate HybridRecon X scan data')
    parser.add_argument('--output', '-o', required=True, help='Output directory')
    args = parser.parse_args()
    
    aggregator = DataAggregator(args.output)
    aggregator.aggregate_all()
    aggregator.save()


if __name__ == '__main__':
    main()
