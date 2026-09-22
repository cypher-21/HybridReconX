#!/usr/bin/env bash
# ============================================================================
# MODULE 13: REPORTING
# ============================================================================
# Generate comprehensive HTML dashboard using data aggregator and report
# generator. This module runs LAST in the pipeline.
# ============================================================================

# Don't exit on errors - report generation should complete even if some stats fail
set -uo pipefail

# Interrupt handling
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[[ -f "${SCRIPT_DIR}/../lib/interrupt.sh" ]] && source "${SCRIPT_DIR}/../lib/interrupt.sh" && install_module_handler
# Source config library
[[ -f "${SCRIPT_DIR}/../lib/config.sh" ]] && source "${SCRIPT_DIR}/../lib/config.sh"
# Source logging library (centralized log(), count_lines(), get_threads(), get_rate_limit())
[[ -f "${SCRIPT_DIR}/../lib/logging.sh" ]] && source "${SCRIPT_DIR}/../lib/logging.sh"
set_log_module "REPORT"

REPORT_DIR="${OUTPUT_BASE}/reports"
LIB_DIR="${SCRIPT_DIR}/../lib"

# ============================================================================
# REAL-TIME NOTIFICATIONS - Severity-Based Alerts
# ============================================================================
# Only alert on HIGH/CRITICAL findings to avoid alert fatigue

PENDING_ALERTS_FILE="${OUTPUT_BASE}/.pending_alerts"

# Send immediate notification for critical findings
alert_critical() {
    local finding="$1"
    local details="${2:-}"
    
    # Desktop notification (if available)
    if command -v notify-send &>/dev/null; then
        notify-send -u critical "🚨 CRITICAL FINDING" "$finding" 2>/dev/null || true
    fi
    
    # ProjectDiscovery notify (if configured)
    if command -v notify &>/dev/null && [[ -f ~/.config/notify/provider-config.yaml ]]; then
        echo "🚨 CRITICAL: $finding - $details" | notify -silent 2>/dev/null || true
    fi
    
    # Log to critical findings file
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] CRITICAL: $finding - $details" >> "${OUTPUT_BASE}/critical_findings.log"
    
    log CRITICAL "$finding"
}

# Queue high-severity finding for batched notification
alert_high() {
    local finding="$1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] HIGH: $finding" >> "$PENDING_ALERTS_FILE"
}

# Send batched notifications (called periodically or at end of scan)
send_batched_alerts() {
    if [[ ! -f "$PENDING_ALERTS_FILE" ]]; then
        return 0
    fi
    
    local count=$(wc -l < "$PENDING_ALERTS_FILE" 2>/dev/null || echo "0")
    
    if [[ "$count" -gt 0 ]]; then
        log INFO "Sending $count batched high-severity alerts..."
        
        # Desktop notification with summary
        if command -v notify-send &>/dev/null; then
            notify-send -u normal "⚠️ HybridX: $count High Findings" "Check ${OUTPUT_BASE}/critical_findings.log" 2>/dev/null || true
        fi
        
        # Move to permanent log
        cat "$PENDING_ALERTS_FILE" >> "${OUTPUT_BASE}/high_findings.log"
        rm -f "$PENDING_ALERTS_FILE"
    fi
}

# Scan output files for critical findings and alert
scan_for_critical_findings() {
    log TASK "Scanning results for critical findings..."
    
    local vulns_dir="${OUTPUT_BASE}/vulns"
    
    # Check for confirmed SQLi
    if [[ -f "${vulns_dir}/sqlmap_results.txt" ]]; then
        local sqli_count=$(grep -c "is vulnerable" "${vulns_dir}/sqlmap_results.txt" 2>/dev/null || echo "0")
        if [[ "$sqli_count" -gt 0 ]]; then
            alert_critical "SQL Injection Confirmed" "$sqli_count vulnerable endpoints"
        fi
    fi
    
    # Check for exposed credentials in JS
    if [[ -f "${OUTPUT_BASE}/intel/js_secrets.json" ]]; then
        local creds=$(grep -c '"type": ".*key\|password\|token\|secret"' "${OUTPUT_BASE}/intel/js_secrets.json" 2>/dev/null || echo "0")
        if [[ "$creds" -gt 0 ]]; then
            alert_critical "Exposed Credentials Found" "$creds secrets in JavaScript"
        fi
    fi
    
    # Check for RCE/Command Injection
    if [[ -f "${vulns_dir}/nuclei_findings.json" ]]; then
        local rce=$(grep -ci '"severity": "critical"' "${vulns_dir}/nuclei_findings.json" 2>/dev/null || echo "0")
        if [[ "$rce" -gt 0 ]]; then
            alert_critical "Critical Nuclei Findings" "$rce critical vulnerabilities"
        fi
    fi
    
    # Check for admin panels
    if [[ -f "${OUTPUT_BASE}/content/special_files.txt" ]]; then
        if grep -qi "admin\|login\|dashboard" "${OUTPUT_BASE}/content/special_files.txt" 2>/dev/null; then
            alert_high "Admin/Login panels discovered"
        fi
    fi
    
    # Check for .git exposure
    if grep -q "\.git" "${OUTPUT_BASE}/content/special_files.txt" 2>/dev/null; then
        alert_critical "Git Repository Exposed" "Potential source code disclosure"
    fi
    
    # Check for .env exposure
    if grep -q "\.env" "${OUTPUT_BASE}/content/special_files.txt" 2>/dev/null; then
        alert_critical "Environment File Exposed" "Potential credential disclosure"
    fi
    
    # Send any batched alerts
    send_batched_alerts
}

# ============================================================================
# DATA AGGREGATION
# ============================================================================
aggregate_scan_data() {
    log TASK "Aggregating scan data from all modules..."
    
    if [[ -f "${LIB_DIR}/data_aggregator.py" ]]; then
        python3 "${LIB_DIR}/data_aggregator.py" \
            --output "$OUTPUT_BASE" \
            2>&1 || {
            log WARN "Data aggregation had issues, falling back to basic stats"
            return 1
        }
        return 0
    else
        log WARN "data_aggregator.py not found, using basic reporting"
        return 1
    fi
}

# ============================================================================
# REPORT GENERATION
# ============================================================================
generate_full_report() {
    log TASK "Generating comprehensive HTML report..."
    
    local data_file="${REPORT_DIR}/aggregated_data.json"
    
    if [[ -f "${LIB_DIR}/report_generator.py" ]] && [[ -f "$data_file" ]]; then
        python3 "${LIB_DIR}/report_generator.py" \
            --output "$OUTPUT_BASE" \
            --data "$data_file" \
            2>&1 || {
            log WARN "Report generation had issues, falling back to basic report"
            generate_basic_html_report
        }
    else
        log WARN "Using basic report generator (full report generator unavailable)"
        generate_basic_html_report
    fi
}

# ============================================================================
# BASIC HTML REPORT (Fallback)
# ============================================================================
generate_basic_html_report() {
    log INFO "Generating basic HTML report..."
    
    local report_file="${REPORT_DIR}/report.html"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local target_name="${TARGET:-$(basename "$OUTPUT_BASE")}"
    
    # Collect stats with error handling
    local subdomains=$(count_lines "${OUTPUT_BASE}/recon/clean_subdomains.txt")
    local live_hosts=$(count_lines "${OUTPUT_BASE}/probed/live_hosts.txt")
    local urls_found=$(count_lines "${OUTPUT_BASE}/content/all_urls.txt")
    local params_found=$(count_lines "${OUTPUT_BASE}/params/urls_with_params.txt")
    local git_exposed=$(count_lines "${OUTPUT_BASE}/content/git_exposed.txt")
    local env_exposed=$(count_lines "${OUTPUT_BASE}/content/env_exposed.txt")
    
    # v2.0 stats
    local validated_high=$(cat "${OUTPUT_BASE}/vulns/validated_high.json" 2>/dev/null | jq 'length' 2>/dev/null || echo "0")
    local validated_medium=$(cat "${OUTPUT_BASE}/vulns/validated_medium.json" 2>/dev/null | jq 'length' 2>/dev/null || echo "0")
    local js_secrets=$(cat "${OUTPUT_BASE}/intel/js_secrets.json" 2>/dev/null | jq 'length' 2>/dev/null || echo "0")
    local js_endpoints=$(count_lines "${OUTPUT_BASE}/intel/js_endpoints.txt")
    local nuclei_findings=$(count_lines "${OUTPUT_BASE}/vulns/nuclei_general_results.txt")
    
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
        .header .version { background: var(--accent); color: #fff; padding: 4px 12px; border-radius: 12px; font-size: 0.8rem; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 15px; margin-bottom: 30px; }
        .stat-card { background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 20px; text-align: center; }
        .stat-card .number { font-size: 2.2rem; font-weight: bold; color: var(--accent); }
        .stat-card .label { color: #8b949e; font-size: 0.85rem; }
        .stat-card.critical .number { color: var(--danger); }
        .stat-card.warning .number { color: var(--warning); }
        .stat-card.success .number { color: var(--success); }
        .section { background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 25px; margin-bottom: 20px; }
        .section h2 { color: var(--accent); margin-bottom: 15px; display: flex; align-items: center; gap: 10px; }
        .section h2::before { content: ''; width: 4px; height: 24px; background: var(--accent); border-radius: 2px; }
        code { background: #21262d; padding: 2px 6px; border-radius: 4px; font-family: monospace; font-size: 0.9em; }
        .footer { text-align: center; padding: 30px 0; color: #8b949e; border-top: 1px solid var(--border); margin-top: 30px; }
        .no-findings { color: #8b949e; padding: 20px; text-align: center; }
    </style>
</head>
<body>
    <div class="container">
        <header class="header">
            <h1>🎯 HybridRecon X</h1>
            <p class="meta">Security Assessment Report for <strong>${target_name}</strong> <span class="version">v2.1.1</span></p>
            <p class="meta">Generated: ${timestamp}</p>
        </header>

        <div class="stats-grid">
            <div class="stat-card"><div class="number">${subdomains}</div><div class="label">Subdomains</div></div>
            <div class="stat-card success"><div class="number">${live_hosts}</div><div class="label">Live Hosts</div></div>
            <div class="stat-card"><div class="number">${urls_found}</div><div class="label">URLs Found</div></div>
            <div class="stat-card"><div class="number">${params_found}</div><div class="label">Parameters</div></div>
            <div class="stat-card critical"><div class="number">${validated_high}</div><div class="label">🎯 HIGH Conf</div></div>
            <div class="stat-card warning"><div class="number">${nuclei_findings}</div><div class="label">Nuclei</div></div>
            <div class="stat-card critical"><div class="number">${js_secrets}</div><div class="label">🔐 Secrets</div></div>
            <div class="stat-card"><div class="number">${js_endpoints}</div><div class="label">📡 Endpoints</div></div>
        </div>

        <div class="section">
            <h2>📋 Executive Summary</h2>
            <p>This scan discovered <strong>${subdomains}</strong> subdomains, <strong>${live_hosts}</strong> live hosts, 
               and <strong>${urls_found}</strong> URLs for target <strong>${target_name}</strong>.</p>
            <p style="margin-top: 10px;">Validated findings: <strong>${validated_high}</strong> HIGH, 
               <strong>${validated_medium}</strong> MEDIUM confidence.</p>
        </div>

        <div class="section">
            <h2>🔍 Scan Metadata</h2>
            <p><strong>Output Directory:</strong> <code>${OUTPUT_BASE}</code></p>
            <p><strong>Git Exposed:</strong> ${git_exposed}</p>
            <p><strong>Env Files Exposed:</strong> ${env_exposed}</p>
        </div>

        <footer class="footer">
            <p>Generated by <strong>HybridRecon X</strong> - Context-Aware Bug Bounty Framework</p>
            <p>Output Directory: <code>${OUTPUT_BASE}</code></p>
        </footer>
    </div>
</body>
</html>
EOF

    log INFO "Basic report saved: $report_file"
}

# ============================================================================
# JSON REPORT
# ============================================================================
generate_json_report() {
    log INFO "Generating JSON report..."
    
    local report_file="${REPORT_DIR}/report.json"
    
    # If aggregated data exists, copy it
    if [[ -f "${REPORT_DIR}/aggregated_data.json" ]]; then
        cp "${REPORT_DIR}/aggregated_data.json" "$report_file"
        log INFO "JSON report: $report_file"
        return
    fi
    
    # Otherwise generate basic JSON
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

    log INFO "JSON report: $report_file"
}

# ============================================================================
# NOTIFICATIONS
# ============================================================================
send_notifications() {
    log INFO "Sending notifications..."
    command -v notify &>/dev/null || { log WARN "Notify not available"; return; }
    
    local subdomains=$(count_lines "${OUTPUT_BASE}/recon/clean_subdomains.txt")
    local live_hosts=$(count_lines "${OUTPUT_BASE}/probed/live_hosts.txt")
    local validated_high=$(cat "${OUTPUT_BASE}/vulns/validated_high.json" 2>/dev/null | jq 'length' 2>/dev/null || echo "0")
    
    local msg="🎯 HybridRecon X Scan Complete
Target: ${TARGET:-unknown}
Live Hosts: ${live_hosts}
HIGH Confidence Vulns: ${validated_high}
Report: ${REPORT_DIR}/report.html"
    
    echo "$msg" | notify -silent 2>/dev/null || true
}

# ============================================================================
# MAIN
# ============================================================================
main() {
    echo -e "\n${CYAN}═══ REPORTING MODULE ═══${NC}\n"
    
    mkdir -p "$REPORT_DIR"
    
    # Step 0: Scan for critical findings and send alerts
    scan_for_critical_findings
    
    # Step 1: Aggregate all scan data
    if aggregate_scan_data; then
        log INFO "Data aggregation successful"
    else
        log WARN "Data aggregation failed, using basic stats"
    fi
    
    # Step 2: Generate comprehensive report
    generate_full_report
    
    # Step 3: Generate JSON report
    generate_json_report
    
    # Step 4: Send notifications
    send_notifications
    
    echo -e "\n${GREEN}Reports generated: ${REPORT_DIR}${NC}"
    echo -e "  📊 HTML Report: ${REPORT_DIR}/report.html"
    echo -e "  📋 JSON Report: ${REPORT_DIR}/report.json"
    [[ -f "${REPORT_DIR}/aggregated_data.json" ]] && echo -e "  📦 Aggregated Data: ${REPORT_DIR}/aggregated_data.json"
    [[ -f "${OUTPUT_BASE}/critical_findings.log" ]] && echo -e "  🚨 Critical Findings: ${OUTPUT_BASE}/critical_findings.log"
    echo ""
}

main "$@"
