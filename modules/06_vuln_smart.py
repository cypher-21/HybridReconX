#!/usr/bin/env python3
"""
============================================================================
MODULE 06: SMART ROUTER - THE BRAIN
============================================================================
Context-Aware Vulnerability Scanner Routing Engine

This is the core intelligence of HybridRecon X. It reads fingerprint data
and makes intelligent decisions about which scanners to run based on the
detected technology stack, WAF presence, and server configuration.

The Smart Router implements:
1. Technology-specific template selection for Nuclei
2. CMS-specific scanner triggering (WPScan, JoomScan, etc.)
3. WAF-aware rate limiting
4. OS-specific payload filtering
5. Parallel execution with resource management
============================================================================
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

# Add lib to path for shared imports
sys.path.insert(0, str(Path(__file__).parent.parent / 'lib'))

try:
    import yaml
    from rich.table import Table
except ImportError:
    yaml = None

# Import shared utilities (console, signal handling, ScanConfig, run_command)
from scan_utils import console, is_interrupted, reset_interrupt, ScanConfig, run_command

# Import centralized tool registry
from tool_registry import ToolRegistry



# ============================================================================
# DATA CLASSES
# ============================================================================
@dataclass
class TargetInfo:
    """Represents a target with its fingerprint data."""
    url: str
    status_code: int = 0
    title: str = ""
    webserver: str = ""
    tech: List[str] = field(default_factory=list)
    whatweb_tech: List[str] = field(default_factory=list)
    versions: Dict[str, str] = field(default_factory=dict)
    waf: List[str] = field(default_factory=list)
    cdn: bool = False
    ip: str = ""
    cname: str = ""
    
    @property
    def all_tech(self) -> List[str]:
        """Combined tech from all sources."""
        return self.tech + self.whatweb_tech + [self.webserver]
    
    @property
    def tech_string(self) -> str:
        """Lowercase string of all tech for matching."""
        return ' '.join([str(t).lower() for t in self.all_tech])
    
    def has_tech(self, *patterns: str) -> bool:
        """Check if any pattern matches the tech stack."""
        tech_lower = self.tech_string
        return any(p.lower() in tech_lower for p in patterns)
    
    def has_waf(self, *waf_names: str) -> bool:
        """Check if specific WAF is detected."""
        waf_lower = [w.lower() for w in self.waf]
        return any(w.lower() in waf_lower for w in waf_names)


# ScanConfig is imported from lib/scan_utils.py


# ============================================================================
# TECHNOLOGY DETECTION RULES
# ============================================================================
class TechDetector:
    """Technology detection and classification."""
    
    TECH_PATTERNS = {
        'wordpress': ['wordpress', 'wp-', 'wp-content', 'wp-includes'],
        'joomla': ['joomla', 'com_'],
        'drupal': ['drupal', 'sites/default', 'sites/all'],
        'magento': ['magento', 'mage'],
        'shopify': ['shopify', 'cdn.shopify'],
        'laravel': ['laravel', 'x-powered-by: laravel'],
        'symfony': ['symfony'],
        'django': ['django', 'csrfmiddlewaretoken'],
        'flask': ['flask', 'werkzeug'],
        'rails': ['ruby on rails', 'rails', 'x-powered-by: phusion'],
        'spring': ['spring', 'springboot', 'x-application-context'],
        'tomcat': ['tomcat', 'apache-coyote', 'catalina'],
        'jetty': ['jetty', 'eclipse jetty'],
        'nginx': ['nginx'],
        'apache': ['apache', 'mod_'],
        'iis': ['iis', 'microsoft-iis', 'asp.net', 'aspnet'],
        'nodejs': ['node.js', 'express', 'nodejs', 'node'],
        'php': ['php', 'x-powered-by: php'],
        'java': ['java', 'jsp', 'jsf', 'servlet'],
        'python': ['python', 'wsgi'],
        'ruby': ['ruby', 'rack'],
        'go': ['golang', 'go-http'],
        'dotnet': ['.net', 'asp.net', 'aspnetcore'],
        'cloudflare': ['cloudflare'],
        'aws': ['amazon', 'aws', 'cloudfront', 'elb'],
        'azure': ['azure', 'microsoft azure'],
        'gcp': ['google cloud', 'gcp', 'google frontend'],
    }
    
    NUCLEI_TAGS = {
        'wordpress': ['wordpress', 'wp-plugin', 'wp-theme', 'wp-core'],
        'joomla': ['joomla', 'joomla-plugin'],
        'drupal': ['drupal', 'drupal-plugin'],
        'magento': ['magento'],
        'laravel': ['laravel', 'php'],
        'symfony': ['symfony', 'php'],
        'django': ['django', 'python'],
        'flask': ['flask', 'python'],
        'spring': ['springboot', 'spring', 'java'],
        'tomcat': ['tomcat', 'apache', 'java'],
        'iis': ['iis', 'microsoft', 'aspnet', 'windows'],
        'nodejs': ['nodejs', 'express', 'javascript'],
        'php': ['php'],
        'java': ['java', 'jsp'],
        'dotnet': ['aspnet', 'dotnet', 'microsoft'],
        'nginx': ['nginx'],
        'apache': ['apache'],
    }
    
    # Paths to exclude based on OS detection
    LINUX_ONLY_PATHS = [
        '/etc/passwd', '/proc/', '/var/log/', '/home/',
        '/root/', '/usr/', '/opt/', '/tmp/', '/dev/'
    ]
    
    WINDOWS_ONLY_PATHS = [
        'C:\\', 'C:/', 'Windows\\', 'inetpub', 'web.config',
        'Program Files', 'Users\\'
    ]
    
    @classmethod
    def detect_technologies(cls, target: TargetInfo) -> Dict[str, bool]:
        """Detect all technologies for a target."""
        detected = {}
        tech_lower = target.tech_string
        
        for tech_name, patterns in cls.TECH_PATTERNS.items():
            detected[tech_name] = any(p.lower() in tech_lower for p in patterns)
        
        return detected
    
    @classmethod
    def get_nuclei_tags(cls, target: TargetInfo) -> List[str]:
        """Get appropriate Nuclei tags for a target."""
        tags = set()
        detected = cls.detect_technologies(target)
        
        for tech_name, is_detected in detected.items():
            if is_detected and tech_name in cls.NUCLEI_TAGS:
                tags.update(cls.NUCLEI_TAGS[tech_name])
        
        return list(tags)
    
    @classmethod
    def is_windows(cls, target: TargetInfo) -> bool:
        """Check if target is likely Windows-based."""
        return target.has_tech('iis', 'asp.net', 'aspnet', 'windows', '.net')
    
    @classmethod
    def is_linux(cls, target: TargetInfo) -> bool:
        """Check if target is likely Linux-based."""
        return not cls.is_windows(target)


# ============================================================================
# WAF HANDLING
# ============================================================================
class WAFHandler:
    """Handle WAF-specific rate limiting and evasion."""
    
    WAF_RATE_LIMITS = {
        'cloudflare': {'rate': 10, 'delay': 1.0},
        'akamai': {'rate': 5, 'delay': 2.0},
        'aws': {'rate': 15, 'delay': 0.5},
        'incapsula': {'rate': 10, 'delay': 1.0},
        'sucuri': {'rate': 10, 'delay': 1.0},
        'f5': {'rate': 15, 'delay': 0.5},
        'default': {'rate': 50, 'delay': 0.1},
    }
    
    @classmethod
    def get_rate_limit(cls, waf_list: List[str]) -> Tuple[int, float]:
        """Get rate limit based on detected WAF."""
        for waf in waf_list:
            waf_lower = waf.lower()
            for waf_name, config in cls.WAF_RATE_LIMITS.items():
                if waf_name in waf_lower:
                    return config['rate'], config['delay']
        
        return cls.WAF_RATE_LIMITS['default']['rate'], cls.WAF_RATE_LIMITS['default']['delay']


# ============================================================================
# SCANNER EXECUTION
# ============================================================================
class ScannerExecutor:
    """Execute security scanners with proper configuration."""
    
    def __init__(self, config: ScanConfig):
        self.config = config
        self.vuln_dir = Path(config.output_dir) / 'vulns'
        self.vuln_dir.mkdir(parents=True, exist_ok=True)
    
    def run_command(self, cmd: List[str], output_file: Optional[str] = None,
                    timeout: int = 3600) -> Tuple[bool, str, int]:
        """Run a command and capture output. Delegates to shared run_command()."""
        return run_command(cmd, output_file=output_file, timeout=timeout)
    
    def run_nuclei(self, targets: List[str], tags: List[str] = None,
                   templates: List[str] = None, output_name: str = "nuclei") -> bool:
        """Run Nuclei scanner with specific tags/templates."""
        if not targets:
            console.log("[yellow]No targets for Nuclei scan[/yellow]")
            return False
        
        # Check if nuclei is available
        if not ToolRegistry.is_available('nuclei'):
            console.log("[red]Nuclei not available, skipping...[/red]")
            return False
        
        console.log(f"[green]Running Nuclei on {len(targets)} targets[/green]")
        
        # Write targets to file - one per line
        targets_file = self.vuln_dir / f"{output_name}_targets.txt"
        try:
            with open(targets_file, 'w') as f:
                for target in targets:
                    if target and target.strip():
                        f.write(target.strip() + '\n')
        except Exception as e:
            console.log(f"[red]Failed to write targets file: {e}[/red]")
            return False
        
        # Verify file was created and has content
        if not targets_file.exists() or targets_file.stat().st_size == 0:
            console.log("[red]Targets file is empty or not created[/red]")
            return False
        
        console.log(f"[cyan]Targets file: {targets_file} ({targets_file.stat().st_size} bytes)[/cyan]")
        
        results_txt = self.vuln_dir / f"{output_name}_results.txt"
        results_json = self.vuln_dir / f"{output_name}_results.json"
        
        cmd = [
            'nuclei',
            '-l', str(targets_file),
            '-s', self.config.nuclei_severity,
            '-c', str(self.config.threads),
            '-rl', str(self.config.rate_limit),
            '-o', str(results_txt),
            '-je', str(results_json),
        ]
        
        if tags:
            cmd.extend(['-tags', ','.join(tags)])
        
        if templates:
            for t in templates:
                cmd.extend(['-t', t])
        
        success, output, ret_code = self.run_command(cmd)
        
        # Verify results were created
        if results_txt.exists():
            line_count = sum(1 for _ in open(results_txt))
            console.log(f"[green]Nuclei found {line_count} results[/green]")
        else:
            console.log("[yellow]No Nuclei text results generated[/yellow]")
        
        return success
    
    def run_nuclei_automatic(self, targets: List[str], output_name: str = "nuclei_auto") -> bool:
        """
        Run Nuclei with -automatic-scan flag.
        
        This uses wappalyzer integration for smart template selection
        based on detected technologies. More efficient and accurate.
        """
        if not targets:
            console.log("[yellow]No targets for Nuclei automatic scan[/yellow]")
            return False
        
        if not ToolRegistry.is_available('nuclei'):
            console.log("[red]Nuclei not available, skipping...[/red]")
            return False
        
        console.log(f"[green]Running Nuclei AUTOMATIC scan on {len(targets)} targets[/green]")
        console.log("[cyan]Using wappalyzer for smart template selection...[/cyan]")
        
        # Write targets to file
        targets_file = self.vuln_dir / f"{output_name}_targets.txt"
        with open(targets_file, 'w') as f:
            for target in targets:
                if target and target.strip():
                    f.write(target.strip() + '\n')
        
        if not targets_file.exists() or targets_file.stat().st_size == 0:
            console.log("[red]Targets file is empty[/red]")
            return False
        
        results_txt = self.vuln_dir / f"{output_name}_results.txt"
        results_json = self.vuln_dir / f"{output_name}_results.json"
        
        cmd = [
            'nuclei',
            '-l', str(targets_file),
            '-automatic-scan',  # Smart template selection
            '-s', self.config.nuclei_severity,
            '-c', str(min(self.config.threads, 25)),  # Lower threads for automatic
            '-rl', str(self.config.rate_limit),
            '-o', str(results_txt),
            '-je', str(results_json),
            '-stats',  # Show progress stats
        ]
        
        success, output, ret_code = self.run_command(cmd, timeout=1800)  # 30 min timeout
        
        if results_txt.exists():
            line_count = sum(1 for _ in open(results_txt))
            console.log(f"[green]Nuclei automatic scan found {line_count} results[/green]")
        
        return success
    
    def _get_wpscan_token(self) -> Optional[str]:
        """Get WPScan API token from config."""
        try:
            if self.config.config_file and os.path.exists(self.config.config_file):
                import yaml
                with open(self.config.config_file, 'r') as f:
                    config_data = yaml.safe_load(f) or {}
                # Try both locations
                token = config_data.get('api_keys', {}).get('wpscan_token', '')
                if not token:
                    token = config_data.get('modules', {}).get('cms', {}).get('wordpress', {}).get('wpscan', {}).get('api_token', '')
                return token if token else None
        except Exception:
            pass
        return None
    
    def run_wpscan(self, targets: List[str]) -> bool:
        """Run WPScan on WordPress targets."""
        if not targets:
            return False
        
        # Check if wpscan is available
        if not ToolRegistry.is_available('wpscan'):
            console.log("[yellow]WPScan not available, skipping...[/yellow]")
            return False
        
        console.log(f"[green]Running WPScan on {len(targets)} WordPress targets[/green]")
        
        results_dir = self.vuln_dir / 'wpscan'
        results_dir.mkdir(exist_ok=True)
        
        # Get API token
        api_token = self._get_wpscan_token()
        if api_token:
            console.log("[cyan]Using WPScan API token[/cyan]")
        
        for target in targets[:20]:  # Limit to 20 targets
            safe_name = urlparse(target).netloc.replace('.', '_').replace(':', '_')
            output_file = results_dir / f"{safe_name}.json"
            
            cmd = [
                'wpscan',
                '--url', target,
                '--enumerate', 'vp,vt,u',
                '--format', 'json',
                '--output', str(output_file),
                '--random-user-agent',
            ]
            
            # Add API token if available
            if api_token:
                cmd.extend(['--api-token', api_token])
            
            if self.config.stealth_mode:
                cmd.extend(['--throttle', '2000'])
            
            self.run_command(cmd, timeout=600)
        
        return True
    
    def run_joomscan(self, targets: List[str]) -> bool:
        """Run JoomScan on Joomla targets."""
        if not targets:
            return False
        
        # Find JoomScan
        joomscan_path = ToolRegistry.find_tool('joomscan')
        if not joomscan_path:
            console.log("[yellow]JoomScan not available, skipping...[/yellow]")
            return False
        
        console.log(f"[green]Running JoomScan on {len(targets)} Joomla targets[/green]")
        
        results_dir = self.vuln_dir / 'joomscan'
        results_dir.mkdir(exist_ok=True)
        
        for target in targets[:10]:
            safe_name = urlparse(target).netloc.replace('.', '_')
            
            # Build command based on path type
            if joomscan_path.endswith('.pl'):
                cmd = ['perl', joomscan_path, '-u', target]
            else:
                cmd = [joomscan_path, '-u', target]
            
            self.run_command(cmd, str(results_dir / f"{safe_name}.txt"), timeout=300)
        
        return True
    
    def run_droopescan(self, targets: List[str], cms: str = 'drupal') -> bool:
        """Run Droopescan on Drupal targets."""
        if not targets:
            return False
        
        # Check if droopescan is available
        if not ToolRegistry.is_available('droopescan'):
            console.log("[yellow]Droopescan not available, skipping...[/yellow]")
            return False
        
        console.log(f"[green]Running Droopescan on {len(targets)} {cms} targets[/green]")
        
        results_dir = self.vuln_dir / 'droopescan'
        results_dir.mkdir(exist_ok=True)
        
        for target in targets[:10]:
            safe_name = urlparse(target).netloc.replace('.', '_')
            
            cmd = [
                'droopescan', 'scan', cms,
                '-u', target,
                '-t', str(min(self.config.threads, 10)),
            ]
            
            self.run_command(cmd, str(results_dir / f"{safe_name}.txt"), timeout=300)
        
        return True
    
    def run_dalfox(self, targets_file: str) -> bool:
        """Run Dalfox XSS scanner."""
        if not os.path.exists(targets_file):
            console.log("[yellow]No XSS candidates file found[/yellow]")
            return False
        
        # Check if dalfox is available
        if not ToolRegistry.is_available('dalfox'):
            console.log("[yellow]Dalfox not available, skipping...[/yellow]")
            return False
        
        with open(targets_file, 'r') as f:
            target_count = len([line for line in f if line.strip()])
        
        if target_count == 0:
            console.log("[yellow]XSS candidates file is empty[/yellow]")
            return False
        
        console.log(f"[green]Running Dalfox on {target_count} XSS candidates[/green]")
        
        cmd = [
            'dalfox', 'file', targets_file,
            '-o', str(self.vuln_dir / 'dalfox_results.txt'),
            '--silence',
            '--skip-bav',
            '-w', str(min(self.config.threads, 20)),
        ]
        
        if self.config.blind_xss_callback:
            cmd.extend(['--blind', self.config.blind_xss_callback])
        
        if self.config.stealth_mode:
            cmd.extend(['--delay', '1000'])
        
        success, _, _ = self.run_command(cmd, timeout=1800)
        return success
    
    def run_ghauri(self, targets_file: str) -> bool:
        """Run Ghauri SQLi scanner."""
        if not os.path.exists(targets_file):
            console.log("[yellow]No SQLi candidates file found[/yellow]")
            return False
        
        # Check if ghauri is available
        if not ToolRegistry.is_available('ghauri'):
            console.log("[yellow]Ghauri not available, skipping...[/yellow]")
            return False
        
        with open(targets_file, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]
        
        if not targets:
            console.log("[yellow]SQLi candidates file is empty[/yellow]")
            return False
        
        console.log(f"[green]Running Ghauri on {len(targets)} SQLi candidates[/green]")
        
        results_dir = self.vuln_dir / 'ghauri'
        results_dir.mkdir(exist_ok=True)
        
        for target in targets[:50]:  # Limit to 50 targets
            safe_name = target.replace('/', '_').replace(':', '_')[:50]
            
            cmd = [
                'ghauri',
                '-u', target,
                '--batch',
                '--level', '1',
                '-o', str(results_dir / f"{safe_name}.txt"),
            ]
            
            self.run_command(cmd, timeout=300)
        
        return True
    
    def run_cvemap(self) -> bool:
        """Run CVEmap for CVE prioritization based on scan findings."""
        # Check if cvemap is available
        cvemap_path = shutil.which('cvemap')
        if not cvemap_path:
            console.log("[yellow]cvemap not available, skipping CVE prioritization...[/yellow]")
            return False
        
        console.log("[green]Running CVEmap for CVE prioritization[/green]")
        
        # Look for nuclei JSON results to extract CVEs
        nuclei_results = list(self.vuln_dir.glob('*_results.json'))
        if not nuclei_results:
            console.log("[yellow]No nuclei results found for CVE mapping[/yellow]")
            return False
        
        cve_list = set()
        
        # Extract CVE IDs from nuclei results
        for result_file in nuclei_results:
            try:
                with open(result_file, 'r') as f:
                    for line in f:
                        if 'CVE-' in line:
                            import re
                            cves = re.findall(r'CVE-\d{4}-\d+', line)
                            cve_list.update(cves)
            except Exception:
                continue
        
        if not cve_list:
            console.log("[yellow]No CVEs found in scan results[/yellow]")
            return False
        
        console.log(f"[green]Found {len(cve_list)} unique CVEs, running priority analysis[/green]")
        
        # Write CVEs to file
        cve_file = self.vuln_dir / 'cve_list.txt'
        with open(cve_file, 'w') as f:
            f.write('\n'.join(sorted(cve_list)))
        
        # Run cvemap for each CVE
        output_file = self.vuln_dir / 'cvemap_results.json'
        
        for cve in list(cve_list)[:20]:  # Limit to 20 CVEs
            cmd = ['cvemap', '-id', cve, '-json']
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                if result.stdout:
                    with open(output_file, 'a') as f:
                        f.write(result.stdout + '\n')
            except Exception:
                continue
        
        console.log(f"[green]CVEmap results saved to {output_file}[/green]")
        return True


# ============================================================================
# SMART ROUTER MAIN CLASS
# ============================================================================
class SmartRouter:
    """Main Smart Router class that orchestrates context-aware scanning."""
    
    def __init__(self, config: ScanConfig):
        self.config = config
        self.output_dir = Path(config.output_dir)
        self.finger_dir = self.output_dir / 'fingerprint'
        self.param_dir = self.output_dir / 'params'
        self.executor = ScannerExecutor(config)
        self.targets: List[TargetInfo] = []
    
    def load_fingerprint_data(self) -> bool:
        """Load fingerprint data from JSON files."""
        consolidated_file = self.finger_dir / 'consolidated.json'
        
        if not consolidated_file.exists():
            console.log("[yellow]No consolidated fingerprint data found[/yellow]")
            # Try httpx output
            httpx_file = self.finger_dir / 'httpx_tech.json'
            if httpx_file.exists():
                return self._load_httpx_data(httpx_file)
            return False
        
        try:
            with open(consolidated_file, 'r') as f:
                data = json.load(f)
            
            for entry in data:
                target = TargetInfo(
                    url=entry.get('url', ''),
                    status_code=entry.get('status_code', 0),
                    title=entry.get('title', ''),
                    webserver=entry.get('webserver', ''),
                    tech=entry.get('tech', []),
                    whatweb_tech=entry.get('whatweb_tech', []),
                    versions=entry.get('versions', {}),
                    waf=entry.get('waf', []),
                    cdn=entry.get('cdn', False),
                    ip=entry.get('ip', ''),
                    cname=entry.get('cname', ''),
                )
                if target.url:
                    self.targets.append(target)
            
            console.log(f"[green]Loaded {len(self.targets)} targets[/green]")
            return True
            
        except Exception as e:
            console.log(f"[red]Error loading fingerprint data: {e}[/red]")
            return False
    
    def _load_httpx_data(self, httpx_file: Path) -> bool:
        """Load data from httpx JSON lines file."""
        try:
            with open(httpx_file, 'r') as f:
                for line in f:
                    try:
                        entry = json.loads(line.strip())
                        target = TargetInfo(
                            url=entry.get('url', ''),
                            status_code=entry.get('status_code', 0),
                            title=entry.get('title', ''),
                            webserver=entry.get('webserver', ''),
                            tech=entry.get('tech', []),
                            cdn=entry.get('cdn', False),
                            ip=entry.get('host', ''),
                        )
                        if target.url:
                            self.targets.append(target)
                    except json.JSONDecodeError:
                        continue
            
            console.log(f"[green]Loaded {len(self.targets)} targets from httpx[/green]")
            return len(self.targets) > 0
            
        except Exception as e:
            console.log(f"[red]Error loading httpx data: {e}[/red]")
            return False
    
    def categorize_targets(self) -> Dict[str, List[str]]:
        """Categorize targets by technology for routing."""
        categories = {
            'wordpress': [],
            'joomla': [],
            'drupal': [],
            'laravel': [],
            'spring': [],
            'tomcat': [],
            'iis': [],
            'nodejs': [],
            'all': [],
            'waf_protected': [],
            'windows': [],
            'linux': [],
        }
        
        for target in self.targets:
            categories['all'].append(target.url)
            
            # CMS detection
            if target.has_tech('wordpress', 'wp-'):
                categories['wordpress'].append(target.url)
            elif target.has_tech('joomla'):
                categories['joomla'].append(target.url)
            elif target.has_tech('drupal'):
                categories['drupal'].append(target.url)
            
            # Framework detection
            if target.has_tech('laravel'):
                categories['laravel'].append(target.url)
            if target.has_tech('spring', 'springboot'):
                categories['spring'].append(target.url)
            if target.has_tech('tomcat'):
                categories['tomcat'].append(target.url)
            if target.has_tech('nodejs', 'express'):
                categories['nodejs'].append(target.url)
            
            # Server detection
            if TechDetector.is_windows(target):
                categories['iis'].append(target.url)
                categories['windows'].append(target.url)
            else:
                categories['linux'].append(target.url)
            
            # WAF detection
            if target.waf:
                categories['waf_protected'].append(target.url)
        
        return categories
    
    def print_summary(self, categories: Dict[str, List[str]]):
        """Print categorization summary."""
        table = Table(title="Target Categorization Summary")
        table.add_column("Category", style="cyan")
        table.add_column("Count", style="green")
        
        for category, targets in categories.items():
            if targets:
                table.add_row(category.upper(), str(len(targets)))
        
        console.print(table)
    
    def save_target_lists(self, categories: Dict[str, List[str]]):
        """Save categorized target lists to files."""
        targets_dir = self.output_dir / 'vulns' / 'targets'
        targets_dir.mkdir(parents=True, exist_ok=True)
        
        for category, targets in categories.items():
            if targets:
                output_file = targets_dir / f"{category}_targets.txt"
                with open(output_file, 'w') as f:
                    f.write('\n'.join(set(targets)))
    
    def adjust_rate_limits(self):
        """Adjust rate limits based on WAF detection."""
        waf_targets = [t for t in self.targets if t.waf]
        
        if waf_targets:
            waf_types = set()
            for t in waf_targets:
                waf_types.update(t.waf)
            
            rate, delay = WAFHandler.get_rate_limit(list(waf_types))
            
            if rate < self.config.rate_limit:
                console.log(f"[yellow]WAF detected! Adjusting rate limit: {self.config.rate_limit} → {rate}[/yellow]")
                self.config.rate_limit = rate
    
    def run_cms_scanners(self, categories: Dict[str, List[str]]):
        """Run CMS-specific scanners."""
        console.log("\n[bold cyan]═══ CMS-SPECIFIC SCANNERS ═══[/bold cyan]")
        
        if categories['wordpress']:
            self.executor.run_wpscan(categories['wordpress'])
            # Also run WordPress-specific Nuclei templates
            self.executor.run_nuclei(
                categories['wordpress'],
                tags=['wordpress', 'wp-plugin', 'wp-theme'],
                output_name='nuclei_wordpress'
            )
        
        if categories['joomla']:
            self.executor.run_joomscan(categories['joomla'])
            self.executor.run_nuclei(
                categories['joomla'],
                tags=['joomla'],
                output_name='nuclei_joomla'
            )
        
        if categories['drupal']:
            self.executor.run_droopescan(categories['drupal'], 'drupal')
            self.executor.run_nuclei(
                categories['drupal'],
                tags=['drupal'],
                output_name='nuclei_drupal'
            )
    
    def run_framework_scanners(self, categories: Dict[str, List[str]]):
        """Run framework-specific Nuclei scans."""
        console.log("\n[bold cyan]═══ FRAMEWORK-SPECIFIC SCANNERS ═══[/bold cyan]")
        
        if categories['laravel']:
            self.executor.run_nuclei(
                categories['laravel'],
                tags=['laravel', 'php'],
                output_name='nuclei_laravel'
            )
        
        if categories['spring']:
            self.executor.run_nuclei(
                categories['spring'],
                tags=['springboot', 'spring', 'java'],
                output_name='nuclei_spring'
            )
        
        if categories['tomcat']:
            self.executor.run_nuclei(
                categories['tomcat'],
                tags=['tomcat', 'apache', 'java'],
                output_name='nuclei_tomcat'
            )
        
        if categories['iis']:
            self.executor.run_nuclei(
                categories['iis'],
                tags=['iis', 'microsoft', 'aspnet', 'windows'],
                output_name='nuclei_iis'
            )
        
        if categories['nodejs']:
            self.executor.run_nuclei(
                categories['nodejs'],
                tags=['nodejs', 'express', 'javascript'],
                output_name='nuclei_nodejs'
            )
    
    def run_general_vuln_scan(self, categories: Dict[str, List[str]]):
        """Run general vulnerability scans on all targets."""
        console.log("\n[bold cyan]═══ GENERAL VULNERABILITY SCAN ═══[/bold cyan]")
        
        all_targets = categories.get('all', [])
        
        if all_targets:
            # Run with critical templates first
            console.log(f"[green]Running Nuclei on {len(all_targets)} targets[/green]")
            
            # Standard templates
            templates = [
                'cves/',
                'vulnerabilities/',
                'exposures/',
                'misconfiguration/',
                'takeovers/',
            ]
            
            # Add custom templates if they exist
            custom_templates_dir = Path('/hybridrecon/.data/nuclei-custom-templates/')
            if custom_templates_dir.exists():
                templates.append(str(custom_templates_dir))
                console.log(f"[cyan]Including custom Nuclei templates[/cyan]")
            
            self.executor.run_nuclei(
                all_targets,
                templates=templates,
                output_name='nuclei_general'
            )
    
    def run_injection_scanners(self):
        """Run lightweight injection detection (deep scanning in Module 07)."""
        console.log("\n[bold cyan]═══ INJECTION DETECTION ═══[/bold cyan]")
        console.log("[cyan]Note: XSS (Dalfox) moved to Module 07 with XSStrike[/cyan]")
        
        # SQLi detection only - deep SQLMap testing in Module 07
        sqli_file = self.param_dir / 'gf_sqli.txt'
        if sqli_file.exists():
            self.executor.run_ghauri(str(sqli_file))
        else:
            console.log("[yellow]No SQLi candidates file found[/yellow]")
    
    def route(self) -> bool:
        """Main routing method - the brain of the operation."""
        console.log("\n[bold magenta]══════════════════════════════════════════════════════════[/bold magenta]")
        console.log("[bold magenta]  SMART ROUTER - CONTEXT-AWARE VULNERABILITY SCANNING[/bold magenta]")
        console.log("[bold magenta]══════════════════════════════════════════════════════════[/bold magenta]\n")
        
        # Load fingerprint data
        if not self.load_fingerprint_data():
            console.log("[red]Failed to load fingerprint data[/red]")
            return False
        
        # Categorize targets
        categories = self.categorize_targets()
        self.print_summary(categories)
        self.save_target_lists(categories)
        
        # Adjust rate limits for WAF
        self.adjust_rate_limits()
        
        # Run scans based on categorization
        if not self.config.fast_mode:
            self.run_cms_scanners(categories)
            self.run_framework_scanners(categories)
        
        # Always run general scan
        self.run_general_vuln_scan(categories)
        
        # Run injection scanners
        self.run_injection_scanners()
        
        console.log("\n[bold green]Smart Router completed successfully![/bold green]")
        return True


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================
def parse_args():
    parser = argparse.ArgumentParser(
        description='HybridRecon X - Smart Router (The Brain)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python3 06_vuln_smart.py --output ./output/target --config config.yaml
  python3 06_vuln_smart.py --output ./output/target --fast
  python3 06_vuln_smart.py --output ./output/target --stealth
        '''
    )
    
    parser.add_argument('--output', '-o', required=True,
                        help='Output directory (same as main scan)')
    parser.add_argument('--config', '-c', default='config.yaml',
                        help='Config file path')
    parser.add_argument('--fast', action='store_true',
                        help='Fast mode - skip slower scans')
    parser.add_argument('--stealth', action='store_true',
                        help='Stealth mode - lower rate limits')
    parser.add_argument('--threads', '-t', type=int, default=25,
                        help='Number of threads')
    parser.add_argument('--rate-limit', '-r', type=int, default=150,
                        help='Rate limit (requests/second)')
    parser.add_argument('--severity', '-s', default='critical,high,medium',
                        help='Nuclei severity filter')
    parser.add_argument('--blind-xss', default='',
                        help='Blind XSS callback URL')
    
    return parser.parse_args()


def load_config_file(config_path: str) -> dict:
    """Load configuration from YAML file."""
    if yaml is None:
        return {}
    
    try:
        with open(config_path, 'r') as f:
            return yaml.safe_load(f) or {}
    except Exception:
        return {}


def main():
    args = parse_args()
    
    # Load config file if exists
    config_data = load_config_file(args.config)
    
    # Merge config file with CLI args
    vuln_config = config_data.get('modules', {}).get('vulnerability', {})
    
    config = ScanConfig(
        output_dir=args.output,
        config_file=args.config,
        fast_mode=args.fast,
        stealth_mode=args.stealth,
        threads=args.threads,
        rate_limit=10 if args.stealth else args.rate_limit,
        nuclei_severity=args.severity,
        blind_xss_callback=args.blind_xss or vuln_config.get('xss', {}).get('dalfox', {}).get('blind_xss_callback', ''),
    )
    
    # Run Smart Router
    router = SmartRouter(config)
    success = router.route()
    
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
