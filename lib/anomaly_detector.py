#!/usr/bin/env python3
"""
============================================================================
LIB: ANOMALY DETECTOR
============================================================================
Detects statistical outliers in HTTP responses that often indicate 
vulnerabilities. Flags unusual response sizes, times, status codes, and
content patterns.
============================================================================
"""

import json
import statistics
import re
import sys
import hashlib
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple
from collections import defaultdict
from urllib.parse import urlparse

try:
    import requests
except ImportError:
    print("Error: requests library required")
    sys.exit(1)


# ============================================================================
# 64-BIT SIMHASH UTILITIES
# ============================================================================
def compute_simhash(text: str) -> int:
    """
    Computes a 64-bit SimHash for text and structural tokens.
    Hamming distance <= 3 indicates near-duplicate page/template.
    """
    if not text:
        return 0
    
    # Normalize and extract tokens, stripping dynamic variable numbers/hashes
    cleaned = re.sub(r'[0-9a-fA-F]{8,}', ' HASH ', text.lower())
    cleaned = re.sub(r'\d+', ' NUM ', cleaned)
    tokens = re.findall(r'\b[a-zA-Z_]{3,}\b', cleaned)
    
    if not tokens:
        tokens = [text[i:i+3] for i in range(max(1, len(text) - 2))]
        
    v = [0] * 64
    for token in tokens:
        h = int(hashlib.md5(token.encode('utf-8')).hexdigest()[:16], 16)
        for i in range(64):
            bit = (h >> i) & 1
            if bit == 1:
                v[i] += 1
            else:
                v[i] -= 1
                
    simhash = 0
    for i in range(64):
        if v[i] > 0:
            simhash |= (1 << i)
            
    return simhash


def hamming_distance(h1: int, h2: int) -> int:
    """Calculate hamming distance (number of differing bits) between two 64-bit hashes."""
    return bin(h1 ^ h2).count('1')


@dataclass
class ResponseData:
    """Captured response data for analysis."""
    url: str
    status_code: int
    content_length: int
    response_time: float
    content_type: str
    headers: Dict[str, str]
    title: str = ""
    has_error_page: bool = False
    words: int = 0
    lines: int = 0
    webserver: str = ""
    simhash: int = 0


@dataclass
class ResponseCluster:
    """A cluster of structurally similar HTTP responses."""
    cluster_id: int
    representative_url: str
    status_code: int
    content_length: int
    title: str
    member_count: int
    urls: List[str]
    is_outlier: bool = False


@dataclass
class Anomaly:
    """Detected anomaly."""
    url: str
    anomaly_type: str
    severity: str  # critical, high, medium, low
    description: str
    value: str
    expected: str
    deviation: float  # How far from normal (sigma)
    

class AnomalyDetector:
    """Detects anomalies in HTTP responses."""
    
    # Error patterns that indicate backend issues (potential vulns)
    ERROR_PATTERNS = [
        (r'(sql|mysql|oracle|postgresql|sqlite).*error', 'sql_error'),
        (r'(exception|traceback|stack.?trace)', 'exception'),
        (r'(debug|development).?mode', 'debug_mode'),
        (r'(undefined|null|nil).*(variable|method|function)', 'code_error'),
        (r'(warning|notice|fatal|error).*\bon line\b', 'php_error'),
        (r'<pre>.*File\s+\".*\",\s+line\s+\d+', 'python_error'),
        (r'(java\.(lang|io|sql)|javax\.)', 'java_error'),
        (r'(asp\.net|\.aspx|iis)\b.*error', 'aspnet_error'),
        (r'server.?error|internal.?error|500', 'server_error'),
    ]
    
    # Response time thresholds (seconds)
    SLOW_RESPONSE_THRESHOLD = 5.0  # Baseline for "slow"
    VERY_SLOW_THRESHOLD = 10.0     # Potentially exploitable delay
    
    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.responses: List[ResponseData] = []
        self.anomalies: List[Anomaly] = []
        self.baseline_stats: Dict[str, Dict] = {}
        self.clusters: List[ResponseCluster] = []
        self.session = self._create_session()
        
    def _create_session(self) -> requests.Session:
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        })
        session.verify = False
        return session
    
    def load_responses_from_httpx(self) -> int:
        """Load response data from HTTPX JSON output."""
        httpx_file = self.output_dir / 'probed' / 'httpx_output.json'
        
        if not httpx_file.exists():
            print(f"[!] HTTPX output not found: {httpx_file}")
            return 0
        
        count = 0
        with open(httpx_file, 'r') as f:
            for line in f:
                try:
                    data = json.loads(line.strip())
                    resp = ResponseData(
                        url=data.get('url', ''),
                        status_code=data.get('status_code', 0),
                        content_length=data.get('content_length', 0),
                        response_time=data.get('time', '0s').replace('s', ''),
                        content_type=data.get('content_type', ''),
                        headers={},
                        title=data.get('title', ''),
                        words=data.get('words', 0),
                        lines=data.get('lines', 0),
                        webserver=data.get('webserver', ''),
                    )
                    # Parse response time
                    try:
                        resp.response_time = float(resp.response_time)
                    except:
                        resp.response_time = 0.0
                    
                    # Compute SimHash from body if available, or structural response features
                    body = data.get('body', '')
                    if body:
                        simhash_text = f"{resp.title} {body}"
                    else:
                        tech_list = ','.join(data.get('tech', [])) if isinstance(data.get('tech'), list) else ''
                        simhash_text = f"status_{resp.status_code} len_{resp.content_length} w_{resp.words} l_{resp.lines} srv_{resp.webserver} title_{resp.title} tech_{tech_list}"
                    
                    resp.simhash = compute_simhash(simhash_text)
                    self.responses.append(resp)
                    count += 1
                except:
                    continue
        
        print(f"[+] Loaded {count} responses from HTTPX")
        return count
    
    def calculate_baseline_stats(self):
        """Calculate baseline statistics for anomaly detection."""
        if len(self.responses) < 5:
            print("[!] Not enough responses for statistical analysis")
            return
        
        # Group by domain
        by_domain: Dict[str, List[ResponseData]] = defaultdict(list)
        for r in self.responses:
            domain = urlparse(r.url).netloc
            by_domain[domain].append(r)
        
        for domain, resps in by_domain.items():
            sizes = [r.content_length for r in resps if r.content_length > 0]
            times = [r.response_time for r in resps if r.response_time > 0]
            
            if len(sizes) >= 3:
                self.baseline_stats[domain] = {
                    'size_mean': statistics.mean(sizes),
                    'size_stdev': statistics.stdev(sizes) if len(sizes) > 1 else 0,
                    'time_mean': statistics.mean(times) if times else 0,
                    'time_stdev': statistics.stdev(times) if len(times) > 1 else 0,
                    'count': len(resps),
                }
        
        print(f"[+] Calculated baseline for {len(self.baseline_stats)} domains")
    
    def detect_size_anomalies(self):
        """Detect unusual response sizes."""
        for r in self.responses:
            domain = urlparse(r.url).netloc
            stats = self.baseline_stats.get(domain)
            
            if not stats or stats['size_stdev'] == 0:
                continue
            
            # Calculate z-score
            z_score = (r.content_length - stats['size_mean']) / stats['size_stdev']
            
            # Flag significant deviations
            if abs(z_score) >= 3:  # 3 sigma = very unusual
                severity = 'high' if abs(z_score) >= 4 else 'medium'
                direction = 'larger' if z_score > 0 else 'smaller'
                
                self.anomalies.append(Anomaly(
                    url=r.url,
                    anomaly_type='response_size',
                    severity=severity,
                    description=f"Response size is significantly {direction} than normal",
                    value=str(r.content_length),
                    expected=f"{stats['size_mean']:.0f} ± {stats['size_stdev']:.0f}",
                    deviation=abs(z_score),
                ))
    
    def detect_time_anomalies(self):
        """Detect unusual response times (potential injection)."""
        for r in self.responses:
            domain = urlparse(r.url).netloc
            stats = self.baseline_stats.get(domain)
            
            # Absolute slow check
            if r.response_time >= self.VERY_SLOW_THRESHOLD:
                self.anomalies.append(Anomaly(
                    url=r.url,
                    anomaly_type='response_time',
                    severity='high',
                    description=f"Very slow response - potential time-based injection",
                    value=f"{r.response_time:.2f}s",
                    expected=f"<{self.SLOW_RESPONSE_THRESHOLD}s",
                    deviation=r.response_time / self.SLOW_RESPONSE_THRESHOLD,
                ))
                continue
            
            # Statistical slow check
            if stats and stats['time_stdev'] > 0:
                z_score = (r.response_time - stats['time_mean']) / stats['time_stdev']
                
                if z_score >= 3 and r.response_time >= self.SLOW_RESPONSE_THRESHOLD:
                    self.anomalies.append(Anomaly(
                        url=r.url,
                        anomaly_type='response_time',
                        severity='medium',
                        description="Response significantly slower than baseline",
                        value=f"{r.response_time:.2f}s",
                        expected=f"{stats['time_mean']:.2f}s ± {stats['time_stdev']:.2f}s",
                        deviation=z_score,
                    ))
    
    def detect_status_anomalies(self):
        """Detect unusual status code patterns."""
        # Group by path pattern
        path_status: Dict[str, Dict[int, int]] = defaultdict(lambda: defaultdict(int))
        
        for r in self.responses:
            # Normalize path (remove IDs)
            path = urlparse(r.url).path
            normalized = re.sub(r'/\d+', '/{id}', path)
            path_status[normalized][r.status_code] += 1
        
        for r in self.responses:
            path = urlparse(r.url).path
            normalized = re.sub(r'/\d+', '/{id}', path)
            status_dist = path_status[normalized]
            
            total = sum(status_dist.values())
            if total < 3:
                continue
            
            # Current status code frequency
            freq = status_dist[r.status_code] / total
            
            # Flag rare status codes
            if freq < 0.1 and r.status_code >= 400:
                self.anomalies.append(Anomaly(
                    url=r.url,
                    anomaly_type='status_code',
                    severity='medium' if r.status_code >= 500 else 'low',
                    description=f"Unusual status code {r.status_code} for this path pattern",
                    value=str(r.status_code),
                    expected=f"Common: {max(status_dist, key=status_dist.get)}",
                    deviation=1 / freq if freq > 0 else 10,
                ))
    
    def detect_content_type_mismatch(self):
        """Detect content-type mismatches (often error pages)."""
        for r in self.responses:
            url_lower = r.url.lower()
            content_type = r.content_type.lower()
            
            mismatches = []
            
            # JSON endpoint returning HTML (often error page)
            if '/api/' in url_lower or url_lower.endswith('.json'):
                if 'html' in content_type and 'json' not in content_type:
                    mismatches.append(('expected JSON', 'got HTML'))
            
            # Static file returning HTML
            if any(url_lower.endswith(ext) for ext in ['.js', '.css', '.xml']):
                if 'html' in content_type:
                    mismatches.append(('expected static file', 'got HTML'))
            
            for expected, got in mismatches:
                self.anomalies.append(Anomaly(
                    url=r.url,
                    anomaly_type='content_type_mismatch',
                    severity='medium',
                    description=f"Content-type mismatch: {expected}, {got}",
                    value=r.content_type,
                    expected=expected,
                    deviation=1.0,
                ))
    
    def detect_error_disclosure(self, fetch_content: bool = False):
        """Detect error messages that disclose sensitive info."""
        # This works better with actual response content
        # For now, flag based on title patterns
        for r in self.responses:
            title_lower = r.title.lower() if r.title else ''
            
            error_indicators = [
                ('exception', 'high', 'Exception in title'),
                ('error', 'medium', 'Error in title'),
                ('debug', 'high', 'Debug mode indicator'),
                ('traceback', 'critical', 'Stack trace in title'),
                ('warning', 'low', 'Warning in title'),
            ]
            
            for keyword, severity, desc in error_indicators:
                if keyword in title_lower:
                    self.anomalies.append(Anomaly(
                        url=r.url,
                        anomaly_type='error_disclosure',
                        severity=severity,
                        description=desc,
                        value=r.title[:100],
                        expected='Normal page title',
                        deviation=1.0,
                    ))
                    break
    
    def cluster_responses(self, max_hamming_distance: int = 3):
        """
        Cluster responses into distinct architectural archetypes using 64-bit SimHash.
        Identifies outlier archetypes and eliminates redundant fuzzing of identical parked pages.
        """
        if not self.responses:
            return
            
        cluster_list: List[ResponseCluster] = []
        cluster_simhashes: List[int] = []
        
        for r in self.responses:
            if not r.simhash:
                continue
                
            matched_idx = -1
            # Match against existing cluster with same status code class (2xx, 3xx, 4xx, 5xx)
            for idx, c in enumerate(cluster_list):
                if (c.status_code // 100) == (r.status_code // 100):
                    dist = hamming_distance(cluster_simhashes[idx], r.simhash)
                    if dist <= max_hamming_distance:
                        matched_idx = idx
                        break
                        
            if matched_idx >= 0:
                cluster_list[matched_idx].member_count += 1
                cluster_list[matched_idx].urls.append(r.url)
            else:
                new_c = ResponseCluster(
                    cluster_id=len(cluster_list) + 1,
                    representative_url=r.url,
                    status_code=r.status_code,
                    content_length=r.content_length,
                    title=r.title[:60] if r.title else f"HTTP {r.status_code}",
                    member_count=1,
                    urls=[r.url],
                    is_outlier=False,
                )
                cluster_list.append(new_c)
                cluster_simhashes.append(r.simhash)
                
        total_resp = len(self.responses)
        for c in cluster_list:
            # Singleton or tiny cluster (<= 2 hosts) when there are many hosts
            if total_resp >= 5 and c.member_count <= 2:
                c.is_outlier = True
                self.anomalies.append(Anomaly(
                    url=c.representative_url,
                    anomaly_type='structural_outlier',
                    severity='high' if c.status_code in [200, 301, 302] else 'medium',
                    description=f"Unique response structure (Archetype #{c.cluster_id}: '{c.title}', only {c.member_count} host(s) share this archetype)",
                    value=f"Cluster size: {c.member_count}",
                    expected=f"Typical cluster size: > {max(1, total_resp // max(1, len(cluster_list)))}",
                    deviation=float(total_resp / max(1, c.member_count)),
                ))
                
        self.clusters = cluster_list
        print(f"[+] Grouped {len(self.responses)} responses into {len(self.clusters)} unique response archetypes (SimHash dist<={max_hamming_distance})")

    def run_all_detection(self):
        """Run all anomaly detection methods."""
        self.calculate_baseline_stats()
        self.detect_size_anomalies()
        self.detect_time_anomalies()
        self.detect_status_anomalies()
        self.detect_content_type_mismatch()
        self.detect_error_disclosure()
        self.cluster_responses()
        
        # Sort by severity
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        self.anomalies.sort(key=lambda x: severity_order.get(x.severity, 4))
        
        print(f"\n[+] Detected {len(self.anomalies)} anomalies")
    
    def save_results(self):
        """Save anomaly detection results."""
        intel_dir = self.output_dir / 'intel'
        intel_dir.mkdir(exist_ok=True)
        
        # Save full results
        with open(intel_dir / 'anomalies.json', 'w') as f:
            json.dump([asdict(a) for a in self.anomalies], f, indent=2)
        
        # Save by severity
        for severity in ['critical', 'high', 'medium', 'low']:
            filtered = [a for a in self.anomalies if a.severity == severity]
            if filtered:
                with open(intel_dir / f'anomalies_{severity}.txt', 'w') as f:
                    for a in filtered:
                        f.write(f"{a.url}\t{a.anomaly_type}\t{a.description}\n")
        
        # Save URLs worth investigating
        investigate_urls = set()
        for a in self.anomalies:
            if a.severity in ['critical', 'high']:
                investigate_urls.add(a.url)
        
        if investigate_urls:
            with open(intel_dir / 'investigate_anomalies.txt', 'w') as f:
                f.write('\n'.join(sorted(investigate_urls)))
            print(f"[!] {len(investigate_urls)} URLs flagged for investigation")
            
        # Save response archetypes & deduplicated representatives
        if self.clusters:
            with open(intel_dir / 'response_clusters.json', 'w') as f:
                json.dump([asdict(c) for c in self.clusters], f, indent=2)
            with open(intel_dir / 'unique_archetypes.txt', 'w') as f:
                for c in self.clusters:
                    f.write(f"{c.representative_url}\n")
            outliers = sum(1 for c in self.clusters if c.is_outlier)
            print(f"[+] Saved {len(self.clusters)} response archetypes ({outliers} structural outliers) to intel/unique_archetypes.txt")
    
    def print_summary(self):
        """Print anomaly summary."""
        print("\n" + "="*60)
        print("  ANOMALY DETECTION SUMMARY")
        print("="*60)
        
        by_type = defaultdict(int)
        by_severity = defaultdict(int)
        
        for a in self.anomalies:
            by_type[a.anomaly_type] += 1
            by_severity[a.severity] += 1
        
        print("\nBy Severity:")
        for sev in ['critical', 'high', 'medium', 'low']:
            count = by_severity.get(sev, 0)
            if count:
                marker = '🚨' if sev == 'critical' else '⚠️' if sev == 'high' else '•'
                print(f"  {marker} {sev.upper()}: {count}")
        
        print("\nBy Type:")
        for atype, count in sorted(by_type.items(), key=lambda x: x[1], reverse=True):
            print(f"  • {atype}: {count}")
        
        # Show top anomalies
        if self.anomalies:
            print("\nTop Anomalies to Investigate:")
            for a in self.anomalies[:10]:
                print(f"  [{a.severity.upper()}] {a.anomaly_type}")
                print(f"      URL: {a.url[:80]}...")
                print(f"      {a.description}")
                print()

        # Show Archetype clustering breakdown
        if self.clusters:
            print("\n" + "="*60)
            print("  RESPONSE ARCHETYPE CLUSTERING (SimHash)")
            print("="*60)
            print(f"  Total Responses: {len(self.responses)}")
            print(f"  Unique Archetypes: {len(self.clusters)}")
            print(f"  Structural Outliers: {sum(1 for c in self.clusters if c.is_outlier)}")
            print("\nTop Archetypes:")
            for c in sorted(self.clusters, key=lambda x: x.member_count, reverse=True)[:5]:
                label = "OUTLIER" if c.is_outlier else "POPULAR"
                print(f"  [{label}] #{c.cluster_id}: {c.member_count} host(s) | HTTP {c.status_code} | {c.title[:40]}")
                print(f"      Rep: {c.representative_url[:70]}")


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='HybridRecon X - Anomaly Detector')
    parser.add_argument('--output', '-o', required=True, help='Output directory')
    args = parser.parse_args()
    
    print("\n" + "="*60)
    print("  ANOMALY DETECTION ENGINE")
    print("="*60 + "\n")
    
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    detector = AnomalyDetector(args.output)
    
    if detector.load_responses_from_httpx() == 0:
        print("[!] No response data to analyze")
        return
    
    detector.run_all_detection()
    detector.save_results()
    detector.print_summary()
    
    print("\n[+] Anomaly detection complete!")
    print(f"    Results: {detector.output_dir}/intel/anomalies.json\n")


if __name__ == '__main__':
    main()
