#!/usr/bin/env python3
"""
============================================================================
TOOL REGISTRY - Centralized Tool Discovery & Management
============================================================================
Provides:
1. Dynamic tool path discovery
2. Tool availability checking
3. Tool version detection
4. Recommended arguments for each tool

Used by all modules for consistent tool invocation.
============================================================================
"""

import os
import subprocess
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum


class ToolCategory(Enum):
    """Categories of security tools."""
    RECON = "recon"
    PROBING = "probing"
    FUZZING = "fuzzing"
    VULN_SCAN = "vuln_scan"
    EXPLOITATION = "exploitation"
    CMS = "cms"
    CLOUD = "cloud"
    UTILITY = "utility"


@dataclass
class ToolInfo:
    """Information about a security tool."""
    name: str
    category: ToolCategory
    paths: List[str]  # Possible paths to find the tool
    required: bool = False  # Is this tool required for the framework?
    python_tool: bool = False  # Does it need python3 prefix?
    perl_tool: bool = False  # Does it need perl prefix?
    check_cmd: Optional[str] = None  # Command to check if tool works
    version_cmd: Optional[str] = None  # Command to get version
    description: str = ""


class ToolRegistry:
    """
    Centralized registry for all security tools.
    Handles path discovery, availability checking, and command building.
    """
    
    # Tool definitions
    TOOLS: Dict[str, ToolInfo] = {
        # === RECON TOOLS ===
        'subfinder': ToolInfo(
            name='subfinder',
            category=ToolCategory.RECON,
            paths=['subfinder'],
            required=True,
            description='Passive subdomain enumeration'
        ),
        'amass': ToolInfo(
            name='amass',
            category=ToolCategory.RECON,
            paths=['amass'],
            description='In-depth DNS enumeration'
        ),
        'assetfinder': ToolInfo(
            name='assetfinder',
            category=ToolCategory.RECON,
            paths=['assetfinder'],
            description='Find domains and subdomains'
        ),
        'findomain': ToolInfo(
            name='findomain',
            category=ToolCategory.RECON,
            paths=['findomain', '/usr/local/bin/findomain'],
            description='Fast subdomain scanner'
        ),
        'dnsx': ToolInfo(
            name='dnsx',
            category=ToolCategory.RECON,
            paths=['dnsx'],
            description='DNS toolkit'
        ),
        'puredns': ToolInfo(
            name='puredns',
            category=ToolCategory.RECON,
            paths=['puredns'],
            description='Fast domain resolver'
        ),
        'massdns': ToolInfo(
            name='massdns',
            category=ToolCategory.RECON,
            paths=['massdns', '/opt/tools/massdns'],
            description='High-performance DNS resolver'
        ),
        'gotator': ToolInfo(
            name='gotator',
            category=ToolCategory.RECON,
            paths=['gotator'],
            description='Subdomain permutations'
        ),
        'dnstake': ToolInfo(
            name='dnstake',
            category=ToolCategory.RECON,
            paths=['dnstake'],
            description='Subdomain takeover detection'
        ),
        'tlsx': ToolInfo(
            name='tlsx',
            category=ToolCategory.RECON,
            paths=['tlsx'],
            description='TLS analysis and subdomain detection'
        ),
        
        # === PROBING TOOLS ===
        'httpx': ToolInfo(
            name='httpx',
            category=ToolCategory.PROBING,
            paths=['httpx'],
            required=True,
            description='Fast HTTP toolkit'
        ),
        'whatweb': ToolInfo(
            name='whatweb',
            category=ToolCategory.PROBING,
            paths=['whatweb', '/opt/tools/whatweb/whatweb'],
            description='Web scanner and fingerprinting'
        ),
        'wafw00f': ToolInfo(
            name='wafw00f',
            category=ToolCategory.PROBING,
            paths=['wafw00f'],
            description='WAF detection'
        ),
        
        # === FUZZING TOOLS ===
        'ffuf': ToolInfo(
            name='ffuf',
            category=ToolCategory.FUZZING,
            paths=['ffuf'],
            required=True,
            description='Fast web fuzzer'
        ),
        'feroxbuster': ToolInfo(
            name='feroxbuster',
            category=ToolCategory.FUZZING,
            paths=['feroxbuster'],
            description='Recursive content discovery'
        ),
        'katana': ToolInfo(
            name='katana',
            category=ToolCategory.FUZZING,
            paths=['katana'],
            description='Next-gen web crawler'
        ),
        'hakrawler': ToolInfo(
            name='hakrawler',
            category=ToolCategory.FUZZING,
            paths=['hakrawler'],
            description='Simple web crawler'
        ),
        'gau': ToolInfo(
            name='gau',
            category=ToolCategory.FUZZING,
            paths=['gau'],
            description='Fetch URLs from archives'
        ),
        'waybackurls': ToolInfo(
            name='waybackurls',
            category=ToolCategory.FUZZING,
            paths=['waybackurls'],
            description='Fetch URLs from Wayback Machine'
        ),
        
        # === VULNERABILITY SCANNING ===
        'nuclei': ToolInfo(
            name='nuclei',
            category=ToolCategory.VULN_SCAN,
            paths=['nuclei'],
            required=True,
            description='Template-based vulnerability scanner'
        ),
        'dalfox': ToolInfo(
            name='dalfox',
            category=ToolCategory.VULN_SCAN,
            paths=['dalfox'],
            description='XSS scanner'
        ),
        'ghauri': ToolInfo(
            name='ghauri',
            category=ToolCategory.VULN_SCAN,
            paths=['ghauri', '/opt/tools/ghauri/ghauri.py'],
            python_tool=True,
            description='SQLi detection'
        ),
        'crlfuzz': ToolInfo(
            name='crlfuzz',
            category=ToolCategory.VULN_SCAN,
            paths=['crlfuzz'],
            description='CRLF injection scanner'
        ),
        'corsy': ToolInfo(
            name='corsy',
            category=ToolCategory.VULN_SCAN,
            paths=['corsy', 'python3 -m corsy'],
            description='CORS misconfiguration scanner'
        ),
        'testssl': ToolInfo(
            name='testssl',
            category=ToolCategory.VULN_SCAN,
            paths=['testssl', 'testssl.sh', '/opt/tools/testssl.sh/testssl.sh'],
            description='SSL/TLS testing'
        ),
        'nomore403': ToolInfo(
            name='nomore403',
            category=ToolCategory.VULN_SCAN,
            paths=['nomore403'],
            description='4xx bypass tool'
        ),
        
        # === EXPLOITATION TOOLS ===
        'sqlmap': ToolInfo(
            name='sqlmap',
            category=ToolCategory.EXPLOITATION,
            paths=['sqlmap', '/opt/tools/sqlmap/sqlmap.py', '/usr/share/sqlmap/sqlmap.py'],
            python_tool=True,
            description='SQL injection exploitation'
        ),
        'xsstrike': ToolInfo(
            name='xsstrike',
            category=ToolCategory.EXPLOITATION,
            paths=['xsstrike', '/opt/tools/XSStrike/xsstrike.py'],
            python_tool=True,
            description='Advanced XSS detection'
        ),
        'commix': ToolInfo(
            name='commix',
            category=ToolCategory.EXPLOITATION,
            paths=['commix', '/opt/tools/commix/commix.py', '/usr/share/commix/commix.py'],
            python_tool=True,
            description='Command injection exploitation'
        ),
        'tplmap': ToolInfo(
            name='tplmap',
            category=ToolCategory.EXPLOITATION,
            paths=['tplmap', '/opt/tools/tplmap/tplmap.py'],
            python_tool=True,
            description='SSTI detection'
        ),
        'lfimap': ToolInfo(
            name='lfimap',
            category=ToolCategory.EXPLOITATION,
            paths=['lfimap'],
            description='LFI automation'
        ),
        'ssrfmap': ToolInfo(
            name='ssrfmap',
            category=ToolCategory.EXPLOITATION,
            paths=['ssrfmap', '/opt/tools/SSRFmap/ssrfmap.py'],
            python_tool=True,
            description='SSRF exploitation'
        ),
        'smuggler': ToolInfo(
            name='smuggler',
            category=ToolCategory.EXPLOITATION,
            paths=['smuggler', '/opt/tools/smuggler/smuggler.py'],
            python_tool=True,
            description='HTTP request smuggling'
        ),
        'ppmap': ToolInfo(
            name='ppmap',
            category=ToolCategory.EXPLOITATION,
            paths=['ppmap'],
            description='Prototype pollution scanner'
        ),
        'oralyzer': ToolInfo(
            name='oralyzer',
            category=ToolCategory.EXPLOITATION,
            paths=['oralyzer'],
            description='Open redirect scanner'
        ),
        
        # === CMS TOOLS ===
        'wpscan': ToolInfo(
            name='wpscan',
            category=ToolCategory.CMS,
            paths=['wpscan'],
            description='WordPress scanner'
        ),
        'joomscan': ToolInfo(
            name='joomscan',
            category=ToolCategory.CMS,
            paths=['joomscan', '/opt/tools/joomscan/joomscan.pl'],
            perl_tool=True,
            description='Joomla scanner'
        ),
        'droopescan': ToolInfo(
            name='droopescan',
            category=ToolCategory.CMS,
            paths=['droopescan'],
            description='Drupal/SilverStripe scanner'
        ),
        
        # === CLOUD/SECRETS ===
        'gitleaks': ToolInfo(
            name='gitleaks',
            category=ToolCategory.CLOUD,
            paths=['gitleaks'],
            description='Git secrets scanner'
        ),
        'trufflehog': ToolInfo(
            name='trufflehog',
            category=ToolCategory.CLOUD,
            paths=['trufflehog'],
            description='Secrets scanner'
        ),
        'git-dumper': ToolInfo(
            name='git-dumper',
            category=ToolCategory.CLOUD,
            paths=['git-dumper'],
            description='Git repository dumper'
        ),
        's3scanner': ToolInfo(
            name='s3scanner',
            category=ToolCategory.CLOUD,
            paths=['s3scanner'],
            description='S3 bucket scanner'
        ),
        
        # === JS ANALYSIS ===
        'xnlinkfinder': ToolInfo(
            name='xnlinkfinder',
            category=ToolCategory.FUZZING,
            paths=['xnLinkFinder', 'xnlinkfinder'],
            description='JS endpoint discovery'
        ),
        'jsluice': ToolInfo(
            name='jsluice',
            category=ToolCategory.FUZZING,
            paths=['jsluice'],
            description='JS secret extraction'
        ),
        
        # === UTILITIES ===
        'gf': ToolInfo(
            name='gf',
            category=ToolCategory.UTILITY,
            paths=['gf'],
            description='Grep patterns for bugs'
        ),
        'qsreplace': ToolInfo(
            name='qsreplace',
            category=ToolCategory.UTILITY,
            paths=['qsreplace'],
            description='Query string replacement'
        ),
        'anew': ToolInfo(
            name='anew',
            category=ToolCategory.UTILITY,
            paths=['anew'],
            description='Append without duplicates'
        ),
        'arjun': ToolInfo(
            name='arjun',
            category=ToolCategory.UTILITY,
            paths=['arjun'],
            description='HTTP parameter discovery'
        ),
        'paramspider': ToolInfo(
            name='paramspider',
            category=ToolCategory.UTILITY,
            paths=['paramspider'],
            description='Parameter mining from archives'
        ),
    }
    
    # Cache for discovered paths
    _path_cache: Dict[str, Optional[str]] = {}
    _version_cache: Dict[str, str] = {}
    
    @classmethod
    def find_tool(cls, tool_name: str) -> Optional[str]:
        """
        Find the path to a tool.
        
        Returns:
            Path to the tool executable, or None if not found.
        """
        if tool_name in cls._path_cache:
            return cls._path_cache[tool_name]
        
        tool_info = cls.TOOLS.get(tool_name)
        if not tool_info:
            # Unknown tool - try direct lookup
            path = shutil.which(tool_name)
            cls._path_cache[tool_name] = path
            return path
        
        # Try each possible path
        for path in tool_info.paths:
            # Check if it's in PATH
            found = shutil.which(path.split()[0])
            if found:
                cls._path_cache[tool_name] = path
                return path
            
            # Check if file exists directly
            if os.path.isfile(path):
                cls._path_cache[tool_name] = path
                return path
        
        cls._path_cache[tool_name] = None
        return None
    
    @classmethod
    def is_available(cls, tool_name: str) -> bool:
        """Check if a tool is available."""
        return cls.find_tool(tool_name) is not None
    
    @classmethod
    def get_command(cls, tool_name: str) -> Optional[List[str]]:
        """
        Get the command to run a tool.
        
        Returns:
            List of command parts, or None if tool not found.
        """
        path = cls.find_tool(tool_name)
        if not path:
            return None
        
        tool_info = cls.TOOLS.get(tool_name)
        if not tool_info:
            return [path]
        
        # Handle Python tools
        if tool_info.python_tool and path.endswith('.py'):
            return ['python3', path]
        
        # Handle Perl tools
        if tool_info.perl_tool and path.endswith('.pl'):
            return ['perl', path]
        
        return [path]
    
    @classmethod
    def get_version(cls, tool_name: str) -> Optional[str]:
        """Get the version of a tool."""
        if tool_name in cls._version_cache:
            return cls._version_cache[tool_name]
        
        cmd = cls.get_command(tool_name)
        if not cmd:
            return None
        
        try:
            # Try common version flags
            for flag in ['--version', '-version', '-v', 'version']:
                try:
                    result = subprocess.run(
                        cmd + [flag],
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                    if result.returncode == 0 and result.stdout:
                        version = result.stdout.strip().split('\n')[0]
                        cls._version_cache[tool_name] = version
                        return version
                except Exception:
                    continue
        except Exception:
            pass
        
        return None
    
    @classmethod
    def get_available_tools(cls, category: Optional[ToolCategory] = None) -> List[str]:
        """Get list of all available tools, optionally filtered by category."""
        available = []
        for name, info in cls.TOOLS.items():
            if category and info.category != category:
                continue
            if cls.is_available(name):
                available.append(name)
        return available
    
    @classmethod
    def get_missing_tools(cls, required_only: bool = False) -> List[str]:
        """Get list of missing tools."""
        missing = []
        for name, info in cls.TOOLS.items():
            if required_only and not info.required:
                continue
            if not cls.is_available(name):
                missing.append(name)
        return missing
    
    @classmethod
    def check_all(cls) -> Dict[str, Dict]:
        """Check availability of all tools and return detailed status."""
        status = {}
        for name, info in cls.TOOLS.items():
            path = cls.find_tool(name)
            status[name] = {
                'available': path is not None,
                'path': path,
                'category': info.category.value,
                'required': info.required,
                'description': info.description,
            }
        return status
    
    @classmethod
    def print_status(cls):
        """Print tool availability status to console."""
        print("\n" + "=" * 70)
        print("  TOOL REGISTRY STATUS")
        print("=" * 70)
        
        # Group by category
        by_category: Dict[str, List[Tuple[str, bool, str]]] = {}
        for name, info in cls.TOOLS.items():
            cat = info.category.value
            if cat not in by_category:
                by_category[cat] = []
            available = cls.is_available(name)
            by_category[cat].append((name, available, info.description))
        
        # Print by category
        for category, tools in sorted(by_category.items()):
            print(f"\n[{category.upper()}]")
            for name, available, desc in sorted(tools):
                status = "✓" if available else "✗"
                req = " (REQUIRED)" if cls.TOOLS[name].required else ""
                print(f"  {status} {name:20} - {desc}{req}")
        
        # Summary
        total = len(cls.TOOLS)
        available = len([t for t in cls.TOOLS if cls.is_available(t)])
        missing_required = [t for t, i in cls.TOOLS.items() if i.required and not cls.is_available(t)]
        
        print(f"\n{'=' * 70}")
        print(f"  Total: {available}/{total} tools available")
        if missing_required:
            print(f"  ⚠ Missing REQUIRED tools: {', '.join(missing_required)}")
        print("=" * 70 + "\n")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Tool Registry CLI")
    parser.add_argument("--status", "-s", action="store_true", help="Show tool status")
    parser.add_argument("--check", "-c", help="Check specific tool")
    parser.add_argument("--check-all", action="store_true", help="Check all tools (JSON output)")
    parser.add_argument("--category", help="Filter by category")
    parser.add_argument("--missing", action="store_true", help="Show missing tools")
    parser.add_argument("--required", action="store_true", help="Only show required tools")
    
    args = parser.parse_args()
    
    if args.status:
        ToolRegistry.print_status()
    elif args.check:
        path = ToolRegistry.find_tool(args.check)
        if path:
            print(f"✓ {args.check} found at: {path}")
            version = ToolRegistry.get_version(args.check)
            if version:
                print(f"  Version: {version}")
        else:
            print(f"✗ {args.check} not found")
    elif args.check_all:
        import json
        status = ToolRegistry.check_all()
        print(json.dumps(status, indent=2))
    elif args.missing:
        missing = ToolRegistry.get_missing_tools(required_only=args.required)
        print("Missing tools:")
        for tool in missing:
            info = ToolRegistry.TOOLS[tool]
            req = " (REQUIRED)" if info.required else ""
            print(f"  - {tool}{req}")
    else:
        parser.print_help()
