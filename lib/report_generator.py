#!/usr/bin/env python3
"""
============================================================================
REPORT GENERATOR - Generate Comprehensive HTML Reports
============================================================================
Consumes normalized data from data_aggregator.py and generates a complete
HTML report with all required sections.
============================================================================
"""

import html as html_module
import json
import os
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any
from collections import defaultdict

# Try to import rich for console output
try:
    from rich.console import Console
    console = Console()
except ImportError:
    class Console:
        def print(self, *args, **kwargs): print(*args)
        def log(self, *args, **kwargs): print(*args)
    console = Console()


class ReportGenerator:
    """Generate comprehensive HTML reports from aggregated data."""
    
    def __init__(self, data_file: str, output_dir: str):
        self.output_dir = Path(output_dir)
        self.reports_dir = self.output_dir / 'reports'
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        
        # Load aggregated data
        with open(data_file) as f:
            self.data = json.load(f)
        
        # Read version from VERSION file
        version_file = Path(__file__).parent.parent / 'VERSION'
        try:
            self.version = version_file.read_text().strip()
        except Exception:
            self.version = 'unknown'
    
    def generate(self) -> str:
        """Generate the full HTML report."""
        console.log("[REPORT] Generating HTML report...")
        
        html = self._build_html()
        
        report_path = self.reports_dir / 'report.html'
        report_path.write_text(html)
        
        console.log(f"[REPORT] Report saved to: {report_path}")
        return str(report_path)
    
    def _build_html(self) -> str:
        """Build the complete HTML document."""
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HybridRecon X Report - {self.data.get('target', 'Unknown')}</title>
    {self._css()}
</head>
<body>
    <div class="container">
        {self._header()}
        {self._executive_summary()}
        {self._attack_surface()}
        {self._vulnerabilities_section()}
        {self._js_intel_section()}
        {self._technology_section()}
        {self._metadata_section()}
        {self._footer()}
    </div>
    {self._javascript()}
</body>
</html>"""
    
    def _css(self) -> str:
        """Return CSS styles."""
        return """<style>
:root {
    --bg: #0d1117;
    --card: #161b22;
    --border: #30363d;
    --text: #c9d1d9;
    --text-muted: #8b949e;
    --accent: #58a6ff;
    --success: #3fb950;
    --warning: #d29922;
    --danger: #f85149;
    --critical: #ff6b6b;
}
* { margin: 0; padding: 0; box-sizing: border-box; }
body { 
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
    background: var(--bg); 
    color: var(--text); 
    line-height: 1.6; 
}
.container { max-width: 1400px; margin: 0 auto; padding: 20px; }

/* Header */
.header { 
    text-align: center; 
    padding: 50px 20px; 
    border-bottom: 1px solid var(--border); 
    margin-bottom: 30px; 
}
.header h1 { 
    font-size: 3rem; 
    background: linear-gradient(135deg, var(--accent), #a371f7); 
    -webkit-background-clip: text; 
    -webkit-text-fill-color: transparent; 
    margin-bottom: 10px;
}
.header .target { font-size: 1.5rem; color: var(--text-muted); }
.header .meta { color: var(--text-muted); margin-top: 15px; }
.version-badge { 
    background: var(--accent); 
    color: #fff; 
    padding: 4px 14px; 
    border-radius: 14px; 
    font-size: 0.85rem; 
    margin-left: 10px;
}

/* Stats Grid */
.stats-grid { 
    display: grid; 
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); 
    gap: 20px; 
    margin-bottom: 30px; 
}
.stat-card { 
    background: var(--card); 
    border: 1px solid var(--border); 
    border-radius: 16px; 
    padding: 25px; 
    text-align: center;
    transition: transform 0.2s, box-shadow 0.2s;
}
.stat-card:hover { transform: translateY(-2px); box-shadow: 0 8px 25px rgba(0,0,0,0.3); }
.stat-card .number { font-size: 2.5rem; font-weight: 700; color: var(--accent); }
.stat-card .label { color: var(--text-muted); font-size: 0.9rem; margin-top: 5px; }
.stat-card.critical .number { color: var(--critical); }
.stat-card.high .number { color: var(--danger); }
.stat-card.warning .number { color: var(--warning); }
.stat-card.success .number { color: var(--success); }

/* Sections */
.section { 
    background: var(--card); 
    border: 1px solid var(--border); 
    border-radius: 16px; 
    padding: 30px; 
    margin-bottom: 25px; 
}
.section h2 { 
    color: var(--accent); 
    margin-bottom: 20px; 
    font-size: 1.4rem;
    display: flex; 
    align-items: center; 
    gap: 12px; 
}
.section h2::before { 
    content: ''; 
    width: 4px; 
    height: 28px; 
    background: var(--accent); 
    border-radius: 2px; 
}

/* Tables */
table { width: 100%; border-collapse: collapse; margin-top: 15px; }
th, td { padding: 14px 12px; text-align: left; border-bottom: 1px solid var(--border); }
th { color: var(--text-muted); font-weight: 600; font-size: 0.85rem; text-transform: uppercase; }
tr:hover { background: rgba(88, 166, 255, 0.05); }

/* Badges */
.badge { 
    padding: 5px 14px; 
    border-radius: 20px; 
    font-size: 0.75rem; 
    font-weight: 600; 
    text-transform: uppercase;
}
.badge.critical { background: rgba(255, 107, 107, 0.2); color: var(--critical); }
.badge.high { background: rgba(248, 81, 73, 0.2); color: var(--danger); }
.badge.medium { background: rgba(210, 153, 34, 0.2); color: var(--warning); }
.badge.low { background: rgba(88, 166, 255, 0.2); color: var(--accent); }
.badge.info { background: rgba(63, 185, 80, 0.2); color: var(--success); }
.badge.validated { background: rgba(63, 185, 80, 0.3); color: var(--success); }

/* Findings */
.finding { 
    background: rgba(248, 81, 73, 0.08); 
    border-left: 4px solid var(--danger); 
    padding: 20px; 
    margin: 15px 0; 
    border-radius: 0 12px 12px 0; 
}
.finding.critical { border-color: var(--critical); background: rgba(255, 107, 107, 0.08); }
.finding.high { border-color: var(--danger); }
.finding.medium { border-color: var(--warning); background: rgba(210, 153, 34, 0.08); }
.finding.low { border-color: var(--accent); background: rgba(88, 166, 255, 0.08); }
.finding .title { font-weight: 600; margin-bottom: 10px; display: flex; align-items: center; gap: 10px; }
.finding code { 
    background: #21262d; 
    padding: 3px 8px; 
    border-radius: 5px; 
    font-family: 'SFMono-Regular', Consolas, monospace; 
    font-size: 0.85em; 
    word-break: break-all; 
}
.finding .meta { color: var(--text-muted); font-size: 0.85rem; margin-top: 10px; }

/* Code blocks */
pre { 
    background: #21262d; 
    padding: 15px; 
    border-radius: 8px; 
    overflow-x: auto; 
    font-size: 0.85rem;
    margin: 10px 0;
}
code { font-family: 'SFMono-Regular', Consolas, monospace; }

/* Collapsible */
.collapsible { cursor: pointer; user-select: none; }
.collapsible::after { content: ' ▼'; font-size: 0.7em; }
.collapsible.active::after { content: ' ▲'; }
.content { max-height: 0; overflow: hidden; transition: max-height 0.3s ease-out; }
.content.show { max-height: 2000px; }

/* Footer */
.footer { 
    text-align: center; 
    padding: 40px 20px; 
    color: var(--text-muted); 
    border-top: 1px solid var(--border); 
    margin-top: 40px; 
}

/* Responsive */
@media (max-width: 768px) {
    .header h1 { font-size: 2rem; }
    .stats-grid { grid-template-columns: repeat(2, 1fr); }
    .stat-card .number { font-size: 1.8rem; }
}
</style>"""
    
    def _header(self) -> str:
        """Generate header section."""
        stats = self.data.get('stats', {})
        target = self.data.get('target', 'Unknown Target')
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        return f"""
<header class="header">
    <h1>🎯 HybridRecon X</h1>
    <p class="target">Security Assessment Report for <strong>{target}</strong></p>
    <p class="meta">
        Generated: {timestamp}
        <span class="version-badge">v{self.version}</span>
    </p>
</header>

<div class="stats-grid">
    <div class="stat-card"><div class="number">{stats.get('subdomains', 0)}</div><div class="label">Subdomains</div></div>
    <div class="stat-card success"><div class="number">{stats.get('hosts', 0)}</div><div class="label">Live Hosts</div></div>
    <div class="stat-card"><div class="number">{stats.get('urls', 0)}</div><div class="label">URLs</div></div>
    <div class="stat-card"><div class="number">{stats.get('parameters', 0)}</div><div class="label">Parameters</div></div>
    <div class="stat-card critical"><div class="number">{self._count_findings_by_severity('critical')}</div><div class="label">🔴 Critical</div></div>
    <div class="stat-card high"><div class="number">{self._count_findings_by_severity('high')}</div><div class="label">🟠 High</div></div>
    <div class="stat-card warning"><div class="number">{self._count_findings_by_severity('medium')}</div><div class="label">🟡 Medium</div></div>
    <div class="stat-card"><div class="number">{stats.get('js_secrets', 0)}</div><div class="label">🔐 Secrets</div></div>
</div>"""
    
    def _executive_summary(self) -> str:
        """Generate executive summary."""
        findings = self.data.get('findings', [])
        stats = self.data.get('stats', {})
        
        critical_count = self._count_findings_by_severity('critical')
        high_count = self._count_findings_by_severity('high')
        validated_count = sum(1 for f in findings if f.get('validated'))
        
        risk_level = "Critical" if critical_count > 0 else "High" if high_count > 0 else "Medium" if findings else "Low"
        risk_color = "critical" if critical_count > 0 else "high" if high_count > 0 else "warning" if findings else "success"
        
        return f"""
<div class="section">
    <h2>📋 Executive Summary</h2>
    <p style="margin-bottom: 20px;">
        This security assessment of <strong>{self.data.get('target', 'Unknown')}</strong> discovered 
        <strong>{stats.get('subdomains', 0)}</strong> subdomains, <strong>{stats.get('hosts', 0)}</strong> live hosts,
        and <strong>{len(findings)}</strong> potential security vulnerabilities.
    </p>
    
    <div style="display: flex; gap: 20px; flex-wrap: wrap;">
        <div style="flex: 1; min-width: 200px;">
            <strong>Overall Risk Level:</strong>
            <span class="badge {risk_color}" style="margin-left: 10px;">{risk_level}</span>
        </div>
        <div style="flex: 1; min-width: 200px;">
            <strong>Validated Findings:</strong> {validated_count} / {len(findings)}
        </div>
        <div style="flex: 1; min-width: 200px;">
            <strong>JS Secrets Found:</strong> {stats.get('js_secrets', 0)}
        </div>
    </div>
    
    {self._risk_breakdown()}
</div>"""
    
    def _risk_breakdown(self) -> str:
        """Generate risk breakdown by vulnerability type."""
        findings = self.data.get('findings', [])
        by_type = defaultdict(int)
        
        for f in findings:
            by_type[f.get('vuln_type', 'Unknown')] += 1
        
        if not by_type:
            return "<p style='color: var(--text-muted); margin-top: 20px;'>No vulnerabilities detected.</p>"
        
        rows = ""
        for vuln_type, count in sorted(by_type.items(), key=lambda x: -x[1])[:10]:
            rows += f"<tr><td>{vuln_type}</td><td>{count}</td></tr>"
        
        return f"""
<table style="margin-top: 20px;">
    <thead><tr><th>Vulnerability Type</th><th>Count</th></tr></thead>
    <tbody>{rows}</tbody>
</table>"""
    
    def _attack_surface(self) -> str:
        """Generate attack surface overview."""
        hosts = self.data.get('hosts', {})
        subdomains = self.data.get('subdomains', [])
        
        # Sample hosts for display
        host_rows = ""
        for hostname, info in list(hosts.items())[:20]:
            techs = ', '.join(info.get('technologies', [])[:3]) or '-'
            waf = info.get('waf_detected', '-')
            status = info.get('status_code', '-')
            host_rows += f"""<tr>
                <td><code>{html_module.escape(str(hostname))}</code></td>
                <td>{html_module.escape(str(status))}</td>
                <td>{html_module.escape(str(techs))}</td>
                <td>{html_module.escape(str(waf))}</td>
            </tr>"""
        
        return f"""
<div class="section">
    <h2>🌐 Attack Surface Overview</h2>
    
    <h3 style="margin: 20px 0 10px; font-size: 1.1rem;">Discovered Hosts ({len(hosts)})</h3>
    <table>
        <thead><tr><th>Hostname</th><th>Status</th><th>Technologies</th><th>WAF</th></tr></thead>
        <tbody>{host_rows if host_rows else '<tr><td colspan="4" style="text-align:center;color:var(--text-muted);">No hosts discovered</td></tr>'}</tbody>
    </table>
    
    <details style="margin-top: 20px;">
        <summary style="cursor: pointer; color: var(--accent);">View All Subdomains ({len(subdomains)})</summary>
        <pre style="max-height: 300px; overflow-y: auto; margin-top: 10px;">{chr(10).join(subdomains[:100])}{chr(10) + '... and ' + str(len(subdomains) - 100) + ' more' if len(subdomains) > 100 else ''}</pre>
    </details>
</div>"""
    
    def _vulnerabilities_section(self) -> str:
        """Generate vulnerabilities section."""
        findings = self.data.get('findings', [])
        
        if not findings:
            return """
<div class="section">
    <h2>🔍 Vulnerability Findings</h2>
    <p style="color: var(--text-muted); text-align: center; padding: 40px;">
        No vulnerabilities were detected during this scan.
    </p>
</div>"""
        
        # Group by severity
        by_severity = defaultdict(list)
        for f in findings:
            by_severity[f.get('severity', 'medium').lower()].append(f)
        
        html = """<div class="section"><h2>🔍 Vulnerability Findings</h2>"""
        
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            severity_findings = by_severity.get(severity, [])
            if not severity_findings:
                continue
            
            html += f"""<h3 style="margin: 25px 0 15px; text-transform: capitalize;">{severity} ({len(severity_findings)})</h3>"""
            
            for f in severity_findings[:15]:  # Limit per severity
                validated = '<span class="badge validated">Validated</span>' if f.get('validated') else ''
                confidence = f"Confidence: {f.get('confidence', 0):.0%}" if f.get('confidence') else ''
                raw_poc = html_module.escape(f.get('poc', '')) if f.get('poc') else ''
                poc = f"<pre>{raw_poc}</pre>" if raw_poc else ''
                
                url_escaped = html_module.escape(str(f.get('url', 'N/A'))[:100])
                vuln_type_escaped = html_module.escape(str(f.get('vuln_type', 'Unknown')))
                tool_escaped = html_module.escape(str(f.get('tool', 'Unknown')))
                param_escaped = html_module.escape(str(f.get('parameter', ''))) if f.get('parameter') else ''
                evidence_escaped = html_module.escape(str(f.get('evidence', ''))[:200]) if f.get('evidence') else ''
                
                html += f"""
<div class="finding {severity}">
    <div class="title">
        <span class="badge {severity}">{severity}</span>
        {vuln_type_escaped}
        {validated}
    </div>
    <p><strong>URL:</strong> <code>{url_escaped}</code></p>
    <p><strong>Tool:</strong> {tool_escaped}</p>
    {f'<p><strong>Parameter:</strong> {param_escaped}</p>' if param_escaped else ''}
    {f'<p><strong>Evidence:</strong> {evidence_escaped}</p>' if evidence_escaped else ''}
    {poc}
    <div class="meta">{confidence}</div>
</div>"""
        
        html += "</div>"
        return html
    
    def _js_intel_section(self) -> str:
        """Generate JavaScript intelligence section."""
        secrets = self.data.get('js_secrets', [])
        endpoints = self.data.get('js_endpoints', [])
        dom_xss = self.data.get('dom_xss_vectors', [])
        
        secrets_html = ""
        for s in secrets[:20]:
            secrets_html += f"""
<div class="finding medium">
    <div class="title"><span class="badge warning">{s.get('type', 'secret')}</span></div>
    <p><strong>Value:</strong> <code>{s.get('value', '')[:80]}...</code></p>
    <p><strong>Source:</strong> <code>{s.get('url', '')[:60]}</code></p>
</div>"""
        
        endpoints_html = "<ul>" + "".join(f"<li><code>{e[:80]}</code></li>" for e in endpoints[:30]) + "</ul>" if endpoints else "<p style='color:var(--text-muted)'>No endpoints discovered</p>"
        
        return f"""
<div class="section">
    <h2>📜 JavaScript Intelligence</h2>
    
    <h3 style="margin: 20px 0 10px;">Secrets Found ({len(secrets)})</h3>
    {secrets_html if secrets_html else '<p style="color:var(--text-muted)">No secrets detected</p>'}
    
    <h3 style="margin: 30px 0 10px;">API Endpoints ({len(endpoints)})</h3>
    {endpoints_html}
    
    <h3 style="margin: 30px 0 10px;">DOM XSS Vectors ({len(dom_xss)})</h3>
    <p>{len(dom_xss)} potential DOM XSS vectors identified for manual review.</p>
</div>"""
    
    def _technology_section(self) -> str:
        """Generate technology fingerprinting section."""
        hosts = self.data.get('hosts', {})
        
        tech_count = defaultdict(int)
        for host_info in hosts.values():
            for tech in host_info.get('technologies', []):
                tech_count[tech] += 1
        
        if not tech_count:
            return """
<div class="section">
    <h2>🔧 Technology Stack</h2>
    <p style="color: var(--text-muted);">No technology fingerprints detected.</p>
</div>"""
        
        rows = ""
        for tech, count in sorted(tech_count.items(), key=lambda x: -x[1])[:20]:
            rows += f"<tr><td>{tech}</td><td>{count}</td></tr>"
        
        return f"""
<div class="section">
    <h2>🔧 Technology Stack</h2>
    <table>
        <thead><tr><th>Technology</th><th>Hosts</th></tr></thead>
        <tbody>{rows}</tbody>
    </table>
</div>"""
    
    def _metadata_section(self) -> str:
        """Generate scan metadata section."""
        modules_skipped = self.data.get('modules_skipped', [])
        tools_skipped = self.data.get('tools_skipped', [])
        
        skipped_html = ""
        if modules_skipped:
            skipped_html += "<h4>Skipped Modules</h4><ul>"
            for m in modules_skipped:
                skipped_html += f"<li>{m.get('module', 'Unknown')} - {m.get('reason', 'N/A')}</li>"
            skipped_html += "</ul>"
        
        if tools_skipped:
            skipped_html += "<h4>Skipped Tools</h4><ul>"
            for t in tools_skipped[:10]:
                skipped_html += f"<li>{t.get('tool', 'Unknown')} - {t.get('reason', 'N/A')}</li>"
            skipped_html += "</ul>"
        
        return f"""
<div class="section">
    <h2>📊 Scan Metadata</h2>
    <p><strong>Scan Started:</strong> {self.data.get('scan_started', 'Unknown')}</p>
    <p><strong>Scan Completed:</strong> {self.data.get('scan_completed', 'Unknown')}</p>
    <p><strong>Output Directory:</strong> <code>{self.output_dir}</code></p>
    
    {skipped_html if skipped_html else '<p style="color:var(--text-muted)">All modules and tools executed successfully.</p>'}
</div>"""
    
    def _footer(self) -> str:
        """Generate footer."""
        return f"""
<footer class="footer">
    <p>Generated by <strong>HybridRecon X</strong> - Context-Aware Bug Bounty Framework</p>
    <p style="margin-top: 10px; font-size: 0.85rem;">
        Report generated at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
    </p>
</footer>"""
    
    def _javascript(self) -> str:
        """Return JavaScript for interactivity."""
        return """<script>
document.querySelectorAll('.collapsible').forEach(elem => {
    elem.addEventListener('click', function() {
        this.classList.toggle('active');
        const content = this.nextElementSibling;
        content.classList.toggle('show');
    });
});
</script>"""
    
    def _count_findings_by_severity(self, severity: str) -> int:
        """Count findings by severity level."""
        return sum(1 for f in self.data.get('findings', []) 
                   if f.get('severity', '').lower() == severity.lower())


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Generate HybridRecon X HTML report')
    parser.add_argument('--output', '-o', required=True, help='Output directory')
    parser.add_argument('--data', '-d', help='Aggregated data file (default: OUTPUT/reports/aggregated_data.json)')
    args = parser.parse_args()
    
    data_file = args.data or str(Path(args.output) / 'reports' / 'aggregated_data.json')
    
    if not Path(data_file).exists():
        console.log(f"[ERROR] Data file not found: {data_file}")
        console.log("[INFO] Run data_aggregator.py first")
        sys.exit(1)
    
    generator = ReportGenerator(data_file, args.output)
    generator.generate()


if __name__ == '__main__':
    main()
