#!/usr/bin/env python3
import urllib3; urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
"""
============================================================================
MODULE 10: JAVASCRIPT ANALYSIS ENGINE
============================================================================
Analyzes JavaScript files to extract:
- API endpoints and hidden routes
- Hardcoded secrets and API keys
- DOM XSS sinks and sources
- Sensitive data patterns
============================================================================
"""

import json
import os
import re
import sys
import base64
from dataclasses import dataclass, asdict
from typing import Dict, List, Set, Tuple, Optional
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse

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
# SECRET PATTERNS
# ============================================================================
SECRET_PATTERNS = {
    # AWS
    'aws_access_key': r'AKIA[0-9A-Z]{16}',
    'aws_secret_key': r'(?i)aws(.{0,20})?(?-i)[\'"][0-9a-zA-Z/+]{40}[\'"]',
    
    # Google
    'google_api_key': r'AIza[0-9A-Za-z\-_]{35}',
    'google_oauth': r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
    
    # GitHub
    'github_token': r'gh[pousr]_[A-Za-z0-9_]{36,}',
    'github_oauth': r'github_pat_[A-Za-z0-9_]{22,}',
    
    # Slack
    'slack_token': r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*',
    'slack_webhook': r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}',
    
    # Stripe
    'stripe_secret': r'sk_live_[0-9a-zA-Z]{24,}',
    'stripe_publishable': r'pk_live_[0-9a-zA-Z]{24,}',
    
    # Generic API Keys
    'api_key': r'(?i)(api[_-]?key|apikey|api_secret)[\'"\s:=]+[\'"]?([a-zA-Z0-9_\-]{16,})[\'"]?',
    'bearer_token': r'[Bb]earer\s+[a-zA-Z0-9_\-\.=]{20,}',
    'jwt_token': r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*',
    
    # Private Keys
    'private_key': r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
    
    # Database
    'mongodb_uri': r'mongodb(\+srv)?://[^\s\'"]+',
    'postgres_uri': r'postgres(ql)?://[^\s\'"]+',
    'mysql_uri': r'mysql://[^\s\'"]+',
    
    # Generic Secrets
    'password_field': r'(?i)(password|passwd|pwd)[\'"\s:=]+[\'"]?([^\s\'"]{8,})[\'"]?',
    'secret_field': r'(?i)(secret|token|auth)[\'"\s:=]+[\'"]?([a-zA-Z0-9_\-]{16,})[\'"]?',
}

# ============================================================================
# ENDPOINT PATTERNS
# ============================================================================
ENDPOINT_PATTERNS = [
    # API paths
    r'[\'"`]/api/v?\d*/[a-zA-Z0-9_/\-]+[\'"`]',
    r'[\'"`]/v\d+/[a-zA-Z0-9_/\-]+[\'"`]',
    
    # Relative paths
    r'[\'"`]/[a-zA-Z0-9_\-]+/[a-zA-Z0-9_/\-\.]+[\'"`]',
    
    # Full URLs in strings
    r'https?://[a-zA-Z0-9\-\.]+[a-zA-Z0-9_/\-\?=&]+',
    
    # Route definitions (React, Angular, Vue)
    r'path:\s*[\'"`](/[a-zA-Z0-9_/\-:]+)[\'"`]',
    r'route:\s*[\'"`](/[a-zA-Z0-9_/\-:]+)[\'"`]',
]

# Client-side routing and navigational patterns (React Router, Vue Router, Next.js)
FRAMEWORK_ROUTE_PATTERNS = [
    r'(?:path|route)\s*:\s*[\'"`](/[a-zA-Z0-9_\-/:*?]+)[\'"`]',
    r'(?:navigate|push|replace)\s*\(\s*[\'"`](/[a-zA-Z0-9_\-/:*?]+)[\'"`]',
    r'<Route\s+[^>]*path=[\'"`](/[a-zA-Z0-9_\-/:*?]+)[\'"`]',
    r'href\s*:\s*[\'"`](/[a-zA-Z0-9_\-/:*?]+)[\'"`]',
]

# Enhanced: Fetch/Axios/Ajax patterns for API route extraction
API_CALL_PATTERNS = [
    # fetch() calls
    r'fetch\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
    r'fetch\s*\(\s*`([^`]+)`',
    
    # axios calls
    r'axios\.(get|post|put|delete|patch)\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
    r'axios\s*\(\s*\{[^}]*url:\s*[\'"`]([^\'"`]+)[\'"`]',
    
    # jQuery ajax
    r'\$\.ajax\s*\(\s*\{[^}]*url:\s*[\'"`]([^\'"`]+)[\'"`]',
    r'\$\.(get|post)\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
    
    # XMLHttpRequest
    r'\.open\s*\(\s*[\'"`](GET|POST|PUT|DELETE)[\'"`]\s*,\s*[\'"`]([^\'"`]+)[\'"`]',
    
    # API base URL definitions
    r'(api[A-Z]\w*|API_\w+|baseUrl|baseURL|apiUrl|apiURL)\s*[=:]\s*[\'"`]([^\'"`]+)[\'"`]',
]

# Hidden parameter patterns (params in JS objects sent to backend)
HIDDEN_PARAM_PATTERNS = [
    # Object properties being sent
    r'(\w+)\s*:\s*[\'"`]?(\w+)[\'"`]?\s*[,}]',
    r'data\s*:\s*\{([^}]+)\}',
    r'params\s*:\s*\{([^}]+)\}',
    r'body\s*:\s*JSON\.stringify\s*\(\s*\{([^}]+)\}',
    
    # FormData appends
    r'\.append\s*\(\s*[\'"`](\w+)[\'"`]',
    
    # Query string builders
    r'[\'"`](\w+)=\$\{',
    r'[\'"`](\w+)=[\'"`]\s*\+',
]

# Client-side auth patterns (often bypassable)
AUTH_CHECK_PATTERNS = [
    # Role checks
    r'(user|currentUser|auth)\.(role|isAdmin|isAuthenticated|permissions)',
    r'if\s*\(\s*(user|auth)\.(role|admin|authenticated)',
    r'(isAdmin|isAuthenticated|hasPermission|canAccess|checkAuth)\s*[\(\=]',
    
    # JWT/Token handling
    r'localStorage\.getItem\s*\(\s*[\'"`](token|jwt|auth|session)',
    r'sessionStorage\.getItem\s*\(\s*[\'"`](token|jwt|auth|session)',
    
    # Route guards (React, Vue, Angular)
    r'(PrivateRoute|AuthRoute|RequireAuth|authGuard|canActivate)',
    r'(isLoggedIn|isAuthenticated|checkToken)\s*\(',
    
    # Permission checks
    r'(permissions|roles|privileges)\s*\.\s*(includes|contains|indexOf|some)',
]

# GraphQL patterns
GRAPHQL_PATTERNS = [
    # Query definitions
    r'(query|mutation|subscription)\s+(\w+)\s*[\(\{]',
    r'gql\s*`([^`]+)`',
    
    # GraphQL endpoints
    r'[\'"`](/graphql|/api/graphql)[\'"`]',
    
    # Type definitions in queries
    r'\$(\w+)\s*:\s*(\w+!?)',
]

# ============================================================================
# DOM XSS PATTERNS
# ============================================================================
DOM_SINKS = [
    'innerHTML',
    'outerHTML',
    'document.write',
    'document.writeln',
    'eval(',
    'setTimeout(',
    'setInterval(',
    'Function(',
    'execScript',
    '.html(',  # jQuery
    '.append(',  # jQuery
    '.prepend(',  # jQuery
    'insertAdjacentHTML',
    # Additional dangerous sinks
    'createContextualFragment',
    'Range.createContextualFragment',
    '.setAttribute("on',  # Event handlers via setAttribute
    '.src=',
    '.href=',
    'location=',
    'location.href=',
    'window.open(',
]

DOM_SOURCES = [
    'location.hash',
    'location.search',
    'location.href',
    'location.pathname',
    'document.URL',
    'document.documentURI',
    'document.referrer',
    'window.name',
    'postMessage',
    # Additional sources
    'document.cookie',
    'localStorage',
    'sessionStorage',
    'URLSearchParams',
    'history.pushState',
    'history.replaceState',
]


# ============================================================================
# DATA CLASSES
# ============================================================================
@dataclass 
class Secret:
    type: str
    value: str
    url: str
    line: int = 0
    context: str = ""


@dataclass
class Endpoint:
    path: str
    source_url: str
    method: str = "GET"
    params: List[str] = None


@dataclass
class DOMXSSVector:
    sink: str
    source: str
    url: str
    line: int = 0
    code_snippet: str = ""


@dataclass
class APIRoute:
    """An API route extracted from JS code."""
    url: str
    method: str
    source_file: str
    line: int = 0
    context: str = ""


@dataclass
class HiddenParam:
    """A hidden parameter found in JS code."""
    name: str
    source_file: str
    context: str = ""
    line: int = 0


@dataclass
class AuthCheck:
    """A client-side auth check (potentially bypassable)."""
    pattern: str
    source_file: str
    line: int = 0
    code_snippet: str = ""


@dataclass
class GraphQLQuery:
    """A GraphQL query/mutation found in JS."""
    operation_type: str  # query, mutation, subscription
    name: str
    source_file: str
    raw_query: str = ""


@dataclass
class SourceMapAsset:
    """A source map file discovered and reconstructed."""
    map_url: str
    original_js_url: str
    source_files_count: int
    has_sources_content: bool
    interesting_files: List[str]
    endpoints_found: int = 0
    secrets_found: int = 0


# ============================================================================
# JS ANALYZER
# ============================================================================
class JSAnalyzer:
    """Analyzes JavaScript files for secrets, endpoints, and DOM XSS."""
    
    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.session = self._create_session()
        self.secrets: List[Secret] = []
        self.endpoints: Set[str] = set()
        self.dom_xss: List[DOMXSSVector] = []
        # Enhanced analysis tracking
        self.api_routes: List[APIRoute] = []
        self.hidden_params: List[HiddenParam] = []
        self.auth_checks: List[AuthCheck] = []
        self.graphql_queries: List[GraphQLQuery] = []
        # Modern 2026 SourceMap Reconstruction tracking
        self.sourcemap_assets: List[SourceMapAsset] = []
        self.sourcemap_endpoints: Set[str] = set()
        self.sourcemap_files: Set[str] = set()
        self.analyzed_count = 0
    
    def _create_session(self) -> requests.Session:
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        })
        return session
    
    def load_js_urls(self) -> List[str]:
        """Load JS file URLs from ALL possible sources."""
        js_files = []
        sources_checked = []
        
        # 1. Check probe directory - multiple possible filenames
        probe_dir = self.output_dir / 'probed'
        js_file_names = ['js_files.txt', 'katana_js.txt', 'all_js.txt']
        
        for filename in js_file_names:
            js_file = probe_dir / filename
            sources_checked.append(str(js_file))
            if js_file.exists():
                with open(js_file, 'r') as f:
                    for line in f:
                        url = line.strip()
                        if url and url.startswith('http'):
                            js_files.append(url)
                console.log(f"[cyan]Loaded {len(js_files)} from {filename}[/cyan]")
        
        # 2. Check content directory - extract from various files
        content_dir = self.output_dir / 'content'
        content_files = ['katana_js.txt', 'all_urls.txt', 'katana_output.txt', 'ffuf_discovered.txt']
        
        for f in content_files:
            filepath = content_dir / f
            sources_checked.append(str(filepath))
            if filepath.exists():
                try:
                    with open(filepath, 'r') as file:
                        for line in file:
                            # Match JS file URLs
                            if '.js' in line.lower() and 'http' in line.lower():
                                match = re.search(r'https?://[^\s<>"\']+\.js[^\s<>"\']*', line, re.IGNORECASE)
                                if match:
                                    url = match.group().rstrip('?&')
                                    # Clean up the URL
                                    url = re.sub(r'\?.*$', '', url)  # Remove query string
                                    js_files.append(url)
                except Exception as e:
                    console.log(f"[yellow]Error reading {f}: {e}[/yellow]")
        
        # 3. Also check historical URLs for JS files
        hist_file = probe_dir / 'historical_urls.txt'
        sources_checked.append(str(hist_file))
        if hist_file.exists():
            try:
                with open(hist_file, 'r') as f:
                    for line in f:
                        if '.js' in line.lower() and 'http' in line.lower():
                            match = re.search(r'https?://[^\s<>"\']+\.js', line, re.IGNORECASE)
                            if match:
                                js_files.append(match.group())
            except Exception:
                pass
        
        # Deduplicate and filter
        result = list(set(js_files))
        
        # Log diagnostic info
        console.log(f"[cyan]Checked {len(sources_checked)} sources for JS files[/cyan]")
        console.log(f"[green]Found {len(result)} unique JavaScript files to analyze[/green]")
        
        if not result:
            console.log("[yellow]Sources checked:[/yellow]")
            for src in sources_checked[:5]:
                exists = "✓" if Path(src).exists() else "✗"
                console.log(f"  {exists} {src}")
        
        return result
    
    def fetch_js(self, url: str) -> Tuple[str, str]:
        """Fetch JavaScript content with enhanced error handling."""
        try:
            # Validate URL first
            if not url or not url.startswith('http'):
                return url, ""
            
            # Clean URL - remove fragments and normalize
            url = url.split('#')[0].strip()
            
            resp = self.session.get(url, timeout=15, verify=False, allow_redirects=True)
            
            if resp.status_code == 200:
                content = resp.text
                
                # Verify it's actual JS content (not HTML error page)
                if content and len(content) > 50:
                    # Quick check - if it starts with <!DOCTYPE or <html, it's probably not JS
                    if not content.strip().lower().startswith('<!doctype') and \
                       not content.strip().lower().startswith('<html'):
                        return url, content
                    else:
                        # Might be an error page disguised as JS
                        return url, ""
                        
                return url, content
            else:
                # Non-200 response
                return url, ""
                
        except requests.exceptions.Timeout:
            # Timeout - log but continue
            return url, ""
        except requests.exceptions.ConnectionError:
            # Connection failed
            return url, ""
        except Exception as e:
            # Catch-all for unexpected errors
            return url, ""
    
    def find_secrets(self, content: str, url: str) -> List[Secret]:
        """Find secrets in JavaScript content."""
        found = []
        lines = content.split('\n')
        
        for pattern_name, pattern in SECRET_PATTERNS.items():
            for i, line in enumerate(lines):
                matches = re.finditer(pattern, line)
                for match in matches:
                    value = match.group()
                    
                    # Skip common false positives
                    if self._is_false_positive(value, pattern_name):
                        continue
                    
                    # Get context (surrounding characters)
                    start = max(0, match.start() - 20)
                    end = min(len(line), match.end() + 20)
                    context = line[start:end]
                    
                    found.append(Secret(
                        type=pattern_name,
                        value=value[:100],  # Truncate long values
                        url=url,
                        line=i + 1,
                        context=context,
                    ))
        
        return found
    
    def _is_false_positive(self, value: str, pattern_name: str) -> bool:
        """Check if match is a false positive."""
        # Too short
        if len(value) < 10:
            return True
        
        # Placeholder patterns
        placeholders = ['example', 'xxx', 'your_', 'insert', 'placeholder', '000000', 'test', 'sample']
        if any(p in value.lower() for p in placeholders):
            return True
        
        # Environment variable reference
        if 'process.env' in value or '${' in value:
            return True
        
        return False
    
    def find_endpoints(self, content: str, source_url: str) -> Set[str]:
        """Find API endpoints in JavaScript content."""
        found = set()
        base_url = f"{urlparse(source_url).scheme}://{urlparse(source_url).netloc}"
        
        for pattern in ENDPOINT_PATTERNS:
            matches = re.findall(pattern, content)
            for match in matches:
                # Clean up the match
                endpoint = match.strip('\'"` ')
                
                # Skip common non-endpoints
                if self._is_static_resource(endpoint):
                    continue
                
                # Make absolute URL if relative
                if endpoint.startswith('/'):
                    endpoint = urljoin(base_url, endpoint)
                elif not endpoint.startswith('http'):
                    continue
                
                found.add(endpoint)
        
        return found
    
    def _is_static_resource(self, path: str) -> bool:
        """Check if path is a static resource (not an API endpoint)."""
        static_extensions = ['.js', '.css', '.png', '.jpg', '.gif', '.svg', '.woff', '.ttf', '.ico', '.map']
        static_paths = ['/static/', '/assets/', '/images/', '/fonts/', '/css/', '/js/']
        
        path_lower = path.lower()
        
        for ext in static_extensions:
            if path_lower.endswith(ext):
                return True
        
        for sp in static_paths:
            if sp in path_lower:
                return True
        
        return False
    
    def find_dom_xss(self, content: str, url: str) -> List[DOMXSSVector]:
        """Find potential DOM XSS vectors."""
        found = []
        lines = content.split('\n')
        
        for i, line in enumerate(lines):
            # Check for dangerous sink + source combinations
            for sink in DOM_SINKS:
                if sink in line:
                    for source in DOM_SOURCES:
                        if source in line:
                            found.append(DOMXSSVector(
                                sink=sink,
                                source=source,
                                url=url,
                                line=i + 1,
                                code_snippet=line.strip()[:200],
                            ))
                            break
        
        return found
    
    def find_api_routes(self, content: str, url: str) -> List[APIRoute]:
        """Extract API routes from fetch/axios/ajax calls."""
        found = []
        lines = content.split('\n')
        
        for i, line in enumerate(lines):
            for pattern in API_CALL_PATTERNS:
                matches = re.finditer(pattern, line, re.IGNORECASE)
                for match in matches:
                    groups = match.groups()
                    
                    # Determine method and URL based on pattern
                    if len(groups) >= 2:
                        # axios.get(), $.post(), etc.
                        method = groups[0].upper() if groups[0] in ['get', 'post', 'put', 'delete', 'patch', 'GET', 'POST', 'PUT', 'DELETE'] else 'GET'
                        route_url = groups[1] if len(groups) > 1 else groups[0]
                    else:
                        method = 'GET'
                        route_url = groups[0] if groups else ''
                    
                    if route_url and len(route_url) > 1:
                        found.append(APIRoute(
                            url=route_url,
                            method=method,
                            source_file=url,
                            line=i + 1,
                            context=line.strip()[:100],
                        ))
        
        return found
    
    def find_hidden_params(self, content: str, url: str) -> List[HiddenParam]:
        """Find hidden parameters in JS objects sent to backend."""
        found = []
        
        # Look for interesting parameter names in data objects
        interesting_params = [
            'admin', 'role', 'isAdmin', 'debug', 'test', 'internal',
            'bypass', 'override', 'force', 'skip', 'hidden', 'secret',
            'privilege', 'permission', 'access', 'level', 'status',
        ]
        
        lines = content.split('\n')
        for i, line in enumerate(lines):
            for pattern in HIDDEN_PARAM_PATTERNS:
                matches = re.finditer(pattern, line)
                for match in matches:
                    param_name = match.group(1) if match.groups() else ''
                    
                    # Check if it's an interesting param
                    if any(p.lower() in param_name.lower() for p in interesting_params):
                        found.append(HiddenParam(
                            name=param_name,
                            source_file=url,
                            context=line.strip()[:100],
                            line=i + 1,
                        ))
        
        return found
    
    def find_auth_checks(self, content: str, url: str) -> List[AuthCheck]:
        """Find client-side auth checks that may be bypassable."""
        found = []
        lines = content.split('\n')
        
        for i, line in enumerate(lines):
            for pattern in AUTH_CHECK_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    found.append(AuthCheck(
                        pattern=pattern,
                        source_file=url,
                        line=i + 1,
                        code_snippet=line.strip()[:150],
                    ))
                    break  # One per line is enough
        
        return found
    
    def find_graphql_queries(self, content: str, url: str) -> List[GraphQLQuery]:
        """Extract GraphQL queries and mutations."""
        found = []
        
        for pattern in GRAPHQL_PATTERNS:
            matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                groups = match.groups()
                if len(groups) >= 2:
                    op_type = groups[0].lower()
                    name = groups[1]
                    
                    found.append(GraphQLQuery(
                        operation_type=op_type,
                        name=name,
                        source_file=url,
                        raw_query=match.group()[:200],
                    ))
                elif len(groups) == 1 and 'gql' in match.group().lower():
                    # Full gql`` template
                    found.append(GraphQLQuery(
                        operation_type='unknown',
                        name='inline_query',
                        source_file=url,
                        raw_query=groups[0][:200],
                    ))
        
        return found

    def check_sourcemap(self, js_url: str, js_content: str) -> Optional[SourceMapAsset]:
        """Discover, fetch, and reconstruct source maps to extract hidden routes, files, and secrets."""
        map_url = None
        
        # 1. Check for sourceMappingURL comment in content
        match = re.search(r'/[*#]\s*sourceMappingURL=([^\s\'"]+)\s*(?:\*/)?', js_content)
        if match:
            ref = match.group(1).strip()
            if ref.startswith('data:application/json;base64,'):
                try:
                    b64_data = ref.split('base64,', 1)[1]
                    raw_json = base64.b64decode(b64_data).decode('utf-8', errors='ignore')
                    return self._process_sourcemap_json(raw_json, js_url, "inline_base64")
                except Exception:
                    pass
            else:
                map_url = urljoin(js_url, ref)
        else:
            # Fallback candidate: <js_url>.map
            clean_url = js_url.split('?')[0].split('#')[0]
            if clean_url.endswith('.js'):
                map_url = clean_url + '.map'
        
        if not map_url:
            return None
        
        # 2. Fetch sourcemap with size limits (cap to 15MB)
        try:
            resp = self.session.get(map_url, timeout=10, verify=False, stream=True)
            if resp.status_code == 200:
                raw_bytes = bytearray()
                for chunk in resp.iter_content(chunk_size=65536):
                    raw_bytes.extend(chunk)
                    if len(raw_bytes) > 15 * 1024 * 1024:
                        break
                
                raw_text = raw_bytes.decode('utf-8', errors='ignore')
                if raw_text.strip().startswith('{') and '"version"' in raw_text:
                    return self._process_sourcemap_json(raw_text, js_url, map_url)
        except Exception:
            pass
            
        return None

    def _process_sourcemap_json(self, raw_json: str, js_url: str, map_url: str) -> Optional[SourceMapAsset]:
        """Parse source map JSON, unpack sourcesContent, and extract routes & secrets."""
        try:
            data = json.loads(raw_json)
        except Exception:
            return None
        
        sources = data.get('sources', [])
        sources_content = data.get('sourcesContent', [])
        
        if not sources and not sources_content:
            return None
            
        interesting_files = []
        interesting_keywords = ['admin', 'auth', 'login', 'dashboard', 'internal', 'secret', 
                                'token', 'api', 'debug', 'test', 'config', 'credential', 
                                'payment', 'checkout', 'user', 'manage', 'route']
        
        for src in sources:
            src_str = str(src)
            self.sourcemap_files.add(src_str)
            if any(kw in src_str.lower() for kw in interesting_keywords):
                interesting_files.append(src_str)
        
        endpoints_before = len(self.endpoints)
        secrets_before = len(self.secrets)
        
        # If sourcesContent is available, analyze unminified original source code!
        if sources_content and isinstance(sources_content, list):
            for idx, content in enumerate(sources_content):
                if not content or not isinstance(content, str):
                    continue
                src_name = sources[idx] if idx < len(sources) else f"source_{idx}.ts"
                virtual_url = f"{js_url}#sourcemap/{src_name}"
                
                # Analyze unminified source code
                sm_secrets = self.find_secrets(content, virtual_url)
                sm_endpoints = self.find_endpoints(content, js_url)
                sm_api_routes = self.find_api_routes(content, virtual_url)
                sm_hidden_params = self.find_hidden_params(content, virtual_url)
                sm_auth_checks = self.find_auth_checks(content, virtual_url)
                
                # Framework route extractions in React/Vue/Angular router
                for pattern in FRAMEWORK_ROUTE_PATTERNS:
                    matches = re.findall(pattern, content)
                    for route_match in matches:
                        if isinstance(route_match, tuple):
                            route_match = route_match[0]
                        route_clean = route_match.strip('\'"` ')
                        if route_clean.startswith('/'):
                            base_url = f"{urlparse(js_url).scheme}://{urlparse(js_url).netloc}"
                            abs_route = urljoin(base_url, route_clean)
                            self.endpoints.add(abs_route)
                            self.sourcemap_endpoints.add(abs_route)
                
                self.secrets.extend(sm_secrets)
                self.endpoints.update(sm_endpoints)
                self.sourcemap_endpoints.update(sm_endpoints)
                self.api_routes.extend(sm_api_routes)
                self.hidden_params.extend(sm_hidden_params)
                self.auth_checks.extend(sm_auth_checks)
        
        asset = SourceMapAsset(
            map_url=map_url,
            original_js_url=js_url,
            source_files_count=len(sources),
            has_sources_content=bool(sources_content),
            interesting_files=interesting_files[:50],
            endpoints_found=len(self.endpoints) - endpoints_before,
            secrets_found=len(self.secrets) - secrets_before
        )
        self.sourcemap_assets.append(asset)
        console.log(f"[bold green]🗺️ SourceMap exposed ({len(sources)} files, content={bool(sources_content)}): {map_url[:70]}...[/bold green]")
        return asset
    
    def analyze_file(self, url: str) -> Dict:
        """Analyze a single JavaScript file with enhanced detection."""
        url, content = self.fetch_js(url)
        
        if not content:
            return {}
        
        # Original analysis
        secrets = self.find_secrets(content, url)
        endpoints = self.find_endpoints(content, url)
        dom_xss = self.find_dom_xss(content, url)
        
        # Enhanced analysis
        api_routes = self.find_api_routes(content, url)
        hidden_params = self.find_hidden_params(content, url)
        auth_checks = self.find_auth_checks(content, url)
        graphql = self.find_graphql_queries(content, url)
        
        # Modern 2026 SourceMap Discovery and Reconstruction
        sm_asset = self.check_sourcemap(url, content)
        
        # Store results
        self.secrets.extend(secrets)
        self.endpoints.update(endpoints)
        self.dom_xss.extend(dom_xss)
        self.api_routes.extend(api_routes)
        self.hidden_params.extend(hidden_params)
        self.auth_checks.extend(auth_checks)
        self.graphql_queries.extend(graphql)
        self.analyzed_count += 1
        
        return {
            'url': url,
            'secrets': len(secrets),
            'endpoints': len(endpoints),
            'dom_xss': len(dom_xss),
            'api_routes': len(api_routes),
            'hidden_params': len(hidden_params),
            'auth_checks': len(auth_checks),
            'graphql': len(graphql),
            'sourcemap': bool(sm_asset),
        }
    
    def analyze_all(self, js_urls: List[str], max_workers: int = 20):
        """Analyze all JavaScript files."""
        console.log(f"[cyan]Analyzing {len(js_urls)} JavaScript files...[/cyan]")
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(self.analyze_file, url): url for url in js_urls[:500]}  # Limit
            
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result.get('secrets', 0) > 0:
                        console.log(f"[red]🔐 Secrets found in: {result['url'][:60]}...[/red]")
                except Exception as e:
                    pass
        
        console.log(f"[green]Analyzed {self.analyzed_count} files[/green]")
    
    def save_results(self):
        """Save analysis results."""
        intel_dir = self.output_dir / 'intel'
        intel_dir.mkdir(exist_ok=True)
        
        # Save secrets
        if self.secrets:
            with open(intel_dir / 'js_secrets.json', 'w') as f:
                json.dump([asdict(s) for s in self.secrets], f, indent=2)
            console.log(f"[red]🔐 Found {len(self.secrets)} secrets![/red]")
        
        # Save endpoints
        if self.endpoints:
            with open(intel_dir / 'js_endpoints.txt', 'w') as f:
                f.write('\n'.join(sorted(self.endpoints)))
            console.log(f"[cyan]📡 Found {len(self.endpoints)} endpoints[/cyan]")
        
        # Save DOM XSS vectors
        if self.dom_xss:
            with open(intel_dir / 'dom_xss_vectors.json', 'w') as f:
                json.dump([asdict(d) for d in self.dom_xss], f, indent=2)
            console.log(f"[yellow]⚠️ Found {len(self.dom_xss)} DOM XSS vectors[/yellow]")
        
        # Save API routes (enhanced)
        if self.api_routes:
            with open(intel_dir / 'api_routes.json', 'w') as f:
                json.dump([asdict(r) for r in self.api_routes], f, indent=2)
            # Also save as simple text list for fuzzing
            with open(intel_dir / 'api_routes.txt', 'w') as f:
                f.write('\n'.join(sorted(set(r.url for r in self.api_routes))))
            console.log(f"[cyan]🔗 Found {len(self.api_routes)} API routes[/cyan]")
        
        # Save hidden parameters (enhanced)
        if self.hidden_params:
            with open(intel_dir / 'hidden_params.json', 'w') as f:
                json.dump([asdict(p) for p in self.hidden_params], f, indent=2)
            console.log(f"[magenta]🔍 Found {len(self.hidden_params)} hidden parameters[/magenta]")
        
        # Save auth checks (enhanced)
        if self.auth_checks:
            with open(intel_dir / 'auth_checks.json', 'w') as f:
                json.dump([asdict(a) for a in self.auth_checks], f, indent=2)
            console.log(f"[yellow]🔐 Found {len(self.auth_checks)} client-side auth checks[/yellow]")
        
        # Save GraphQL queries (enhanced)
        if self.graphql_queries:
            with open(intel_dir / 'graphql_queries.json', 'w') as f:
                json.dump([asdict(q) for q in self.graphql_queries], f, indent=2)
            console.log(f"[blue]📊 Found {len(self.graphql_queries)} GraphQL queries[/blue]")
            
        # Save SourceMap analysis results (2026 Modern Recon)
        if self.sourcemap_assets:
            with open(intel_dir / 'sourcemap_assets.json', 'w') as f:
                json.dump([asdict(s) for s in self.sourcemap_assets], f, indent=2)
            console.log(f"[bold green]🗺️ Found {len(self.sourcemap_assets)} exposed SourceMap assets![/bold green]")
            
        if self.sourcemap_endpoints:
            with open(intel_dir / 'sourcemap_endpoints.txt', 'w') as f:
                f.write('\n'.join(sorted(self.sourcemap_endpoints)))
            console.log(f"[green]🔗 Extracted {len(self.sourcemap_endpoints)} endpoints from source maps[/green]")
            
        if self.sourcemap_files:
            with open(intel_dir / 'sourcemap_files.txt', 'w') as f:
                f.write('\n'.join(sorted(self.sourcemap_files)))
            console.log(f"[green]📁 Reconstructed {len(self.sourcemap_files)} original source file paths[/green]")
    
    def print_summary(self):
        """Print analysis summary."""
        table = Table(title="JavaScript Analysis Summary")
        table.add_column("Category", style="cyan")
        table.add_column("Count", style="green")
        
        table.add_row("Files Analyzed", str(self.analyzed_count))
        table.add_row("Secrets Found", str(len(self.secrets)))
        table.add_row("Endpoints Discovered", str(len(self.endpoints)))
        table.add_row("DOM XSS Vectors", str(len(self.dom_xss)))
        table.add_row("API Routes", str(len(self.api_routes)))
        table.add_row("Hidden Parameters", str(len(self.hidden_params)))
        table.add_row("Auth Checks", str(len(self.auth_checks)))
        table.add_row("GraphQL Queries", str(len(self.graphql_queries)))
        table.add_row("Source Maps Exposed", str(len(self.sourcemap_assets)))
        table.add_row("Reconstructed Files", str(len(self.sourcemap_files)))
        table.add_row("SourceMap Routes", str(len(self.sourcemap_endpoints)))
        
        console.print(table)
        
        # Show top secrets by type
        if self.secrets:
            secret_types = {}
            for s in self.secrets:
                secret_types[s.type] = secret_types.get(s.type, 0) + 1
            
            console.log("\n[bold]Secret Types Found:[/bold]")
            for stype, count in sorted(secret_types.items(), key=lambda x: x[1], reverse=True):
                console.log(f"  {stype}: {count}")
        
        # Show auth checks (important for manual testing)
        if self.auth_checks:
            console.log("\n[bold yellow]⚠️ Client-Side Auth Checks (may be bypassable):[/bold yellow]")
            for check in self.auth_checks[:5]:
                console.log(f"  • {check.code_snippet[:80]}...")
                console.log(f"    [dim]{check.source_file}:{check.line}[/dim]")


# ============================================================================
# MAIN
# ============================================================================
def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='HybridRecon X - JavaScript Analysis')
    parser.add_argument('--output', '-o', required=True, help='Output directory')
    parser.add_argument('--threads', '-t', type=int, default=20, help='Analysis threads')
    args = parser.parse_args()
    
    console.log("\n[bold magenta]═══ JAVASCRIPT ANALYSIS ENGINE ═══[/bold magenta]\n")
    
    analyzer = JSAnalyzer(args.output)
    
    js_urls = analyzer.load_js_urls()
    if not js_urls:
        console.log("[yellow]No JavaScript files found to analyze[/yellow]")
        return
    
    analyzer.analyze_all(js_urls, max_workers=args.threads)
    analyzer.save_results()
    analyzer.print_summary()
    
    console.log("\n[bold green]JavaScript analysis complete![/bold green]\n")


if __name__ == '__main__':
    main()
