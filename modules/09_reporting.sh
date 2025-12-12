#!/usr/bin/env bash
# ============================================================================
# MODULE 09: REPORTING
# ============================================================================
# Generate HTML dashboard and send notifications
# ============================================================================

set -euo pipefail

GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
REPORT_DIR="${OUTPUT_BASE}/reports"

log() { echo -e "${GREEN}[REPORT]${NC} $*"; }

count_lines() { [[ -f "$1" ]] && wc -l < "$1" | tr -d ' ' || echo "0"; }

generate_html_report() {
    log "Generating HTML report..."
    
    local report_file="${REPORT_DIR}/report.html"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local target_name="${TARGET:-$(basename "$OUTPUT_BASE")}"
    
    # Collect stats
    local subdomains=$(count_lines "${OUTPUT_BASE}/recon/clean_subdomains.txt")
    local live_hosts=$(count_lines "${OUTPUT_BASE}/probed/live_hosts.txt")
    local urls_found=$(count_lines "${OUTPUT_BASE}/content/all_urls.txt")
    local params_found=$(count_lines "${OUTPUT_BASE}/params/urls_with_params.txt")
    local git_exposed=$(count_lines "${OUTPUT_BASE}/content/git_exposed.txt")
    local env_exposed=$(count_lines "${OUTPUT_BASE}/content/env_exposed.txt")
    
    cat > "$report_file" << EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HybridRecon X Report - ${target_name}</title>
    <style>
        :root { --bg: #0d1117; --card: #161b22; --border: #30363d; --text: #c9d1d9; --accent: #58a6ff; --success: #3fb950; --warning: #d29922; --danger: #f85149; }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; padding: 20px; }
        .container { max-width: 1400px; margin: 0 auto; }
        .header { text-align: center; padding: 40px 0; border-bottom: 1px solid var(--border); margin-bottom: 30px; }
        .header h1 { font-size: 2.5rem; background: linear-gradient(135deg, var(--accent), #a371f7); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .header .meta { color: #8b949e; margin-top: 10px; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .stat-card { background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 20px; text-align: center; }
        .stat-card .number { font-size: 2.5rem; font-weight: bold; color: var(--accent); }
        .stat-card .label { color: #8b949e; font-size: 0.9rem; }
        .stat-card.critical .number { color: var(--danger); }
        .stat-card.warning .number { color: var(--warning); }
        .stat-card.success .number { color: var(--success); }
        .section { background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 25px; margin-bottom: 20px; }
        .section h2 { color: var(--accent); margin-bottom: 15px; display: flex; align-items: center; gap: 10px; }
        .section h2::before { content: ''; width: 4px; height: 24px; background: var(--accent); border-radius: 2px; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid var(--border); }
        th { color: #8b949e; font-weight: 500; }
        .badge { padding: 4px 12px; border-radius: 20px; font-size: 0.8rem; font-weight: 500; }
        .badge.critical { background: rgba(248, 81, 73, 0.2); color: var(--danger); }
        .badge.high { background: rgba(210, 153, 34, 0.2); color: var(--warning); }
        .badge.medium { background: rgba(88, 166, 255, 0.2); color: var(--accent); }
        .finding { background: rgba(248, 81, 73, 0.1); border-left: 3px solid var(--danger); padding: 15px; margin: 10px 0; border-radius: 0 8px 8px 0; }
        .finding.git { border-color: var(--warning); background: rgba(210, 153, 34, 0.1); }
        code { background: #21262d; padding: 2px 6px; border-radius: 4px; font-family: monospace; font-size: 0.9em; }
        .footer { text-align: center; padding: 30px 0; color: #8b949e; border-top: 1px solid var(--border); margin-top: 30px; }
    </style>
</head>
<body>
    <div class="container">
        <header class="header">
            <h1>🎯 HybridRecon X</h1>
            <p class="meta">Security Assessment Report for <strong>${target_name}</strong></p>
            <p class="meta">Generated: ${timestamp}</p>
        </header>

        <div class="stats-grid">
            <div class="stat-card"><div class="number">${subdomains}</div><div class="label">Subdomains</div></div>
            <div class="stat-card success"><div class="number">${live_hosts}</div><div class="label">Live Hosts</div></div>
            <div class="stat-card"><div class="number">${urls_found}</div><div class="label">URLs Discovered</div></div>
            <div class="stat-card"><div class="number">${params_found}</div><div class="label">Parameterized URLs</div></div>
            <div class="stat-card critical"><div class="number">${git_exposed}</div><div class="label">Git Exposed</div></div>
            <div class="stat-card warning"><div class="number">${env_exposed}</div><div class="label">Env Exposed</div></div>
        </div>

        <div class="section">
            <h2>Critical Findings</h2>
EOF

    # Add findings
    if [[ $git_exposed -gt 0 ]]; then
        echo '<div class="finding git"><strong>⚠️ Exposed .git Directories</strong><br>' >> "$report_file"
        head -10 "${OUTPUT_BASE}/content/git_exposed.txt" 2>/dev/null | while read -r url; do
            echo "<code>$url</code><br>" >> "$report_file"
        done
        echo '</div>' >> "$report_file"
    fi
    
    if [[ $env_exposed -gt 0 ]]; then
        echo '<div class="finding"><strong>🔐 Exposed Environment Files</strong><br>' >> "$report_file"
        head -10 "${OUTPUT_BASE}/content/env_exposed.txt" 2>/dev/null | while read -r url; do
            echo "<code>$url</code><br>" >> "$report_file"
        done
        echo '</div>' >> "$report_file"
    fi

    # Add Nuclei findings if available
    local nuclei_results="${OUTPUT_BASE}/vulns/nuclei_general_results.txt"
    if [[ -f "$nuclei_results" ]] && [[ $(count_lines "$nuclei_results") -gt 0 ]]; then
        echo '<table><thead><tr><th>Severity</th><th>Template</th><th>URL</th></tr></thead><tbody>' >> "$report_file"
        head -50 "$nuclei_results" | while IFS= read -r line; do
            local severity=$(echo "$line" | grep -oE '\[critical\]|\[high\]|\[medium\]|\[low\]' | tr -d '[]')
            local template=$(echo "$line" | grep -oE '\[[a-z0-9_-]+\]' | head -1 | tr -d '[]')
            local url=$(echo "$line" | grep -oE 'https?://[^ ]+')
            [[ -n "$severity" ]] && echo "<tr><td><span class='badge $severity'>$severity</span></td><td>$template</td><td><code>$url</code></td></tr>" >> "$report_file"
        done
        echo '</tbody></table>' >> "$report_file"
    fi

    cat >> "$report_file" << 'EOF'
        </div>

        <div class="section">
            <h2>Technology Fingerprints</h2>
            <table>
                <thead><tr><th>Technology</th><th>Count</th></tr></thead>
                <tbody>
EOF

    # Add tech summary
    if [[ -f "${OUTPUT_BASE}/fingerprint/tech_summary.txt" ]]; then
        head -15 "${OUTPUT_BASE}/fingerprint/tech_summary.txt" | while read -r count tech; do
            [[ -n "$tech" ]] && echo "<tr><td>$tech</td><td>$count</td></tr>" >> "$report_file"
        done
    fi

    cat >> "$report_file" << EOF
                </tbody>
            </table>
        </div>

        <footer class="footer">
            <p>Generated by <strong>HybridRecon X</strong> - Context-Aware Bug Bounty Framework</p>
            <p>Output Directory: <code>${OUTPUT_BASE}</code></p>
        </footer>
    </div>
</body>
</html>
EOF

    log "Report saved: $report_file"
}

generate_json_report() {
    log "Generating JSON report..."
    python3 << PYTHON_SCRIPT
import json
import os
from pathlib import Path

output_base = os.environ.get('OUTPUT_BASE', '.')
report = {
    'target': os.environ.get('TARGET', 'unknown'),
    'timestamp': '$(date -Iseconds)',
    'stats': {},
    'findings': []
}

# Collect stats
files = {
    'subdomains': 'recon/clean_subdomains.txt',
    'live_hosts': 'probed/live_hosts.txt',
    'urls': 'content/all_urls.txt',
    'params': 'params/urls_with_params.txt',
    'git_exposed': 'content/git_exposed.txt',
    'env_exposed': 'content/env_exposed.txt'
}

for key, path in files.items():
    full_path = Path(output_base) / path
    report['stats'][key] = len(open(full_path).readlines()) if full_path.exists() else 0

with open(Path(output_base) / 'reports/report.json', 'w') as f:
    json.dump(report, f, indent=2)
PYTHON_SCRIPT
}

send_notifications() {
    log "Sending notifications..."
    command -v notify &>/dev/null || { log "Notify not available"; return; }
    
    local msg="🎯 HybridRecon X Scan Complete
Target: ${TARGET:-unknown}
Live Hosts: $(count_lines "${OUTPUT_BASE}/probed/live_hosts.txt")
URLs: $(count_lines "${OUTPUT_BASE}/content/all_urls.txt")
Git Exposed: $(count_lines "${OUTPUT_BASE}/content/git_exposed.txt")"
    
    echo "$msg" | notify -silent 2>/dev/null || true
}

main() {
    echo -e "\n${CYAN}═══ REPORTING MODULE ═══${NC}\n"
    mkdir -p "$REPORT_DIR"
    generate_html_report
    generate_json_report
    send_notifications
    echo -e "\n${GREEN}Reports generated: ${REPORT_DIR}${NC}\n"
}

main "$@"
