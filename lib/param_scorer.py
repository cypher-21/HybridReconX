#!/usr/bin/env python3
"""
============================================================================
LIB: PARAMETER SCORER
============================================================================
Scores and prioritizes parameters based on likelihood of being vulnerable.
High-risk parameters (file, url, redirect, id) get tested first and deeper.
============================================================================
"""

import re
import sys
import json
from pathlib import Path
from urllib.parse import urlparse, parse_qs, unquote
from dataclasses import dataclass, asdict
from typing import Dict, List, Set, Tuple
from collections import defaultdict

# ============================================================================
# PARAMETER RISK PROFILES
# ============================================================================

# Weight: Higher = More likely to be vulnerable
PARAM_WEIGHTS = {
    # Critical - Almost always worth deep testing
    'critical': {
        'weight': 100,
        'params': [
            'url', 'uri', 'redirect', 'redirect_url', 'redirect_uri', 
            'return', 'return_url', 'returnUrl', 'next', 'next_url',
            'goto', 'target', 'dest', 'destination', 'rurl', 'redir',
            'callback', 'callback_url', 'continue', 'forward',
        ]
    },
    
    # High - File/Path related (LFI, Path Traversal)
    'high_file': {
        'weight': 90,
        'params': [
            'file', 'filename', 'filepath', 'path', 'pathname',
            'doc', 'document', 'template', 'tpl', 'page', 'pg',
            'include', 'inc', 'require', 'load', 'read', 'fetch',
            'view', 'show', 'display', 'content', 'download', 'src',
            'source', 'pdf', 'image', 'img', 'attachment', 'folder',
            'directory', 'dir', 'root', 'lang', 'locale',
        ]
    },
    
    # High - ID/Reference (IDOR)
    'high_idor': {
        'weight': 85,
        'params': [
            'id', 'uid', 'user_id', 'userid', 'account', 'account_id',
            'order', 'order_id', 'orderid', 'invoice', 'invoice_id',
            'item', 'item_id', 'product', 'product_id', 'pid',
            'doc_id', 'docid', 'ref', 'reference', 'profile', 'member',
            'customer', 'customer_id', 'cid', 'no', 'number', 'num',
        ]
    },
    
    # High - Injection points
    'high_injection': {
        'weight': 80,
        'params': [
            'query', 'q', 'search', 'keyword', 'keywords', 'term',
            'filter', 'sort', 'order', 'orderby', 'sortby', 'column',
            'field', 'fields', 'table', 'where', 'select', 'from',
            'name', 'username', 'email', 'data', 'input', 'value',
            'cmd', 'command', 'exec', 'execute', 'run', 'do', 'func',
            'action', 'process', 'step', 'operation', 'code',
        ]
    },
    
    # Medium - SSRF candidates
    'medium_ssrf': {
        'weight': 70,
        'params': [
            'host', 'hostname', 'server', 'domain', 'site', 'website',
            'ip', 'address', 'port', 'proxy', 'webhook', 'endpoint',
            'api', 'api_url', 'feed', 'feed_url', 'link', 'href',
            'location', 'origin', 'remote', 'external', 'fetch_url',
        ]
    },
    
    # Medium - Template/Rendering (SSTI)
    'medium_ssti': {
        'weight': 65,
        'params': [
            'template', 'tpl', 'theme', 'layout', 'render', 'format',
            'output', 'out', 'result', 'response', 'message', 'msg',
            'text', 'body', 'title', 'subject', 'header', 'footer',
            'preview', 'debug', 'test', 'expr', 'expression', 'eval',
        ]
    },
    
    # Medium - Auth/Session related
    'medium_auth': {
        'weight': 60,
        'params': [
            'token', 'access_token', 'auth', 'authorization', 'key',
            'apikey', 'api_key', 'secret', 'password', 'pass', 'pwd',
            'session', 'sid', 'cookie', 'jwt', 'bearer', 'credential',
        ]
    },
    
    # Low - Generic but worth noting
    'low': {
        'weight': 30,
        'params': [
            'type', 'mode', 'method', 'format', 'size', 'limit',
            'offset', 'start', 'end', 'from', 'to', 'date', 'time',
            'version', 'v', 'lang', 'language', 'locale', 'country',
            'state', 'status', 'flag', 'option', 'setting', 'config',
        ]
    }
}

# Vulnerability type mapping
VULN_TYPE_MAPPING = {
    'critical': ['open_redirect', 'ssrf'],
    'high_file': ['lfi', 'path_traversal', 'rfi'],
    'high_idor': ['idor', 'broken_access_control'],
    'high_injection': ['sqli', 'xss', 'cmdi', 'ssti'],
    'medium_ssrf': ['ssrf', 'rfi'],
    'medium_ssti': ['ssti', 'xss'],
    'medium_auth': ['auth_bypass', 'session_hijacking'],
    'low': ['info_disclosure'],
}


@dataclass
class ScoredParameter:
    """A parameter with its risk score and metadata."""
    url: str
    param: str
    value: str
    score: int
    category: str
    vuln_types: List[str]
    context: str  # Where it appears (query, body, path)


class ParameterScorer:
    """Scores parameters based on vulnerability likelihood."""
    
    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.param_dir = self.output_dir / 'params'
        self.scored_params: List[ScoredParameter] = []
        self.param_stats: Dict[str, int] = defaultdict(int)
        
    def load_urls_with_params(self) -> List[str]:
        """Load URLs from param mining output."""
        urls = []
        files_to_check = [
            'urls_with_params.txt',
            'paramspider_all.txt',
            'arjun_params.txt',
        ]
        
        for filename in files_to_check:
            filepath = self.param_dir / filename
            if filepath.exists():
                with open(filepath, 'r') as f:
                    urls.extend([line.strip() for line in f if line.strip() and '?' in line])
        
        return list(set(urls))
    
    def get_param_category(self, param_name: str) -> Tuple[str, int]:
        """Get the category and weight for a parameter name."""
        param_lower = param_name.lower()
        
        for category, data in PARAM_WEIGHTS.items():
            if param_lower in [p.lower() for p in data['params']]:
                return category, data['weight']
            
            # Fuzzy matching - check if param contains any keyword
            for keyword in data['params']:
                if keyword in param_lower or param_lower in keyword:
                    # Partial match gets slightly lower score
                    return category, int(data['weight'] * 0.8)
        
        return 'unknown', 10  # Unknown params get minimal score
    
    def score_url(self, url: str) -> List[ScoredParameter]:
        """Score all parameters in a URL."""
        results = []
        
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            
            for param, values in params.items():
                category, base_score = self.get_param_category(param)
                
                # Adjust score based on value
                value = values[0] if values else ''
                adjusted_score = self._adjust_score_by_value(base_score, value)
                
                # Get associated vulnerability types
                vuln_types = VULN_TYPE_MAPPING.get(category, ['unknown'])
                
                scored = ScoredParameter(
                    url=url,
                    param=param,
                    value=value[:100],  # Truncate
                    score=adjusted_score,
                    category=category,
                    vuln_types=vuln_types,
                    context='query'
                )
                results.append(scored)
                self.param_stats[param] += 1
                
        except Exception:
            pass
        
        return results
    
    def _adjust_score_by_value(self, base_score: int, value: str) -> int:
        """Adjust score based on parameter value characteristics."""
        adjusted = base_score
        value_lower = value.lower()
        
        # Boost: Value looks like a URL/path
        if value.startswith(('http://', 'https://', '/', '..')):
            adjusted += 15
        
        # Boost: Value looks like a file
        if re.search(r'\.(php|asp|aspx|jsp|txt|xml|json|html|pdf)$', value_lower):
            adjusted += 20
        
        # Boost: Value is numeric (ID-like)
        if value.isdigit():
            adjusted += 10
        
        # Boost: Value contains path traversal indicators
        if '..' in value or '%2e%2e' in value_lower:
            adjusted += 25
        
        # Boost: Value contains injection characters
        if any(c in value for c in ["'", '"', '<', '>', '{', '}']):
            adjusted += 15
        
        return min(adjusted, 150)  # Cap at 150
    
    def score_all(self, urls: List[str]):
        """Score all URLs."""
        print(f"[*] Scoring parameters in {len(urls)} URLs...")
        
        for url in urls:
            scored = self.score_url(url)
            self.scored_params.extend(scored)
        
        # Sort by score descending
        self.scored_params.sort(key=lambda x: x.score, reverse=True)
        
        print(f"[+] Scored {len(self.scored_params)} parameters")
    
    def save_prioritized_output(self):
        """Save prioritized parameter lists."""
        self.param_dir.mkdir(exist_ok=True)
        
        # Split by priority
        critical = [p for p in self.scored_params if p.score >= 90]
        high = [p for p in self.scored_params if 70 <= p.score < 90]
        medium = [p for p in self.scored_params if 50 <= p.score < 70]
        low = [p for p in self.scored_params if p.score < 50]
        
        # Save URL lists
        self._save_url_list('prioritized_critical.txt', critical)
        self._save_url_list('prioritized_high.txt', high)
        self._save_url_list('prioritized_medium.txt', medium)
        self._save_url_list('prioritized_low.txt', low)
        
        # Save full scored data as JSON
        with open(self.param_dir / 'scored_params.json', 'w') as f:
            json.dump([asdict(p) for p in self.scored_params], f, indent=2)
        
        # Save per-vuln-type lists
        vuln_urls = defaultdict(set)
        for p in self.scored_params:
            for vtype in p.vuln_types:
                vuln_urls[vtype].add(p.url)
        
        for vtype, urls in vuln_urls.items():
            with open(self.param_dir / f'targets_{vtype}.txt', 'w') as f:
                f.write('\n'.join(sorted(urls)))
        
        # Print summary
        print(f"\n[+] Priority Distribution:")
        print(f"    CRITICAL (90+): {len(critical)} params")
        print(f"    HIGH (70-89):   {len(high)} params")
        print(f"    MEDIUM (50-69): {len(medium)} params")
        print(f"    LOW (<50):      {len(low)} params")
        
        # Print top parameters by frequency
        print(f"\n[+] Top 10 Most Common Parameters:")
        top_params = sorted(self.param_stats.items(), key=lambda x: x[1], reverse=True)[:10]
        for param, count in top_params:
            category, score = self.get_param_category(param)
            print(f"    {param}: {count}x (category: {category}, base_score: {score})")
    
    def _save_url_list(self, filename: str, params: List[ScoredParameter]):
        """Save unique URLs to a file."""
        unique_urls = sorted(set(p.url for p in params))
        filepath = self.param_dir / filename
        with open(filepath, 'w') as f:
            f.write('\n'.join(unique_urls))
        print(f"[+] Saved {len(unique_urls)} URLs to {filename}")


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='HybridRecon X - Parameter Scorer')
    parser.add_argument('--output', '-o', required=True, help='Output directory')
    args = parser.parse_args()
    
    print("\n" + "="*60)
    print("  PARAMETER PRIORITIZATION ENGINE")
    print("="*60 + "\n")
    
    scorer = ParameterScorer(args.output)
    
    urls = scorer.load_urls_with_params()
    if not urls:
        print("[!] No URLs with parameters found")
        return
    
    scorer.score_all(urls)
    scorer.save_prioritized_output()
    
    print("\n[+] Parameter scoring complete!")
    print(f"    Output: {scorer.param_dir}/prioritized_*.txt")
    print(f"    Full data: {scorer.param_dir}/scored_params.json\n")


if __name__ == '__main__':
    main()
