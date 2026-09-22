#!/usr/bin/env bash
# ============================================================================
# MODULE 03: FINGERPRINTING (THE BRAIN INPUT)
# ============================================================================
# Deep fingerprinting - tech detection, WAF detection, etc.
# This feeds the Smart Router with intelligence for scanning
# ============================================================================

# Don't exit on errors - tools may fail without meaning module failure
set -uo pipefail

# Interrupt handling
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[[ -f "${SCRIPT_DIR}/../lib/interrupt.sh" ]] && source "${SCRIPT_DIR}/../lib/interrupt.sh" && install_module_handler
# Source config library
[[ -f "${SCRIPT_DIR}/../lib/config.sh" ]] && source "${SCRIPT_DIR}/../lib/config.sh"
# Source logging library (centralized log(), count_lines(), get_threads(), get_rate_limit())
[[ -f "${SCRIPT_DIR}/../lib/logging.sh" ]] && source "${SCRIPT_DIR}/../lib/logging.sh"
set_log_module "FINGERPRINT"

PROBE_DIR="${OUTPUT_BASE}/probed"
FINGER_DIR="${OUTPUT_BASE}/fingerprint"

# ============================================================================
# HELPER: Create live_hosts.txt from TARGET for standalone mode
# ============================================================================
ensure_live_hosts_exist() {
    local hosts_file="${PROBE_DIR}/live_hosts.txt"
    
    if [[ ! -f "$hosts_file" ]]; then
        if [[ -n "${TARGET:-}" ]]; then
            log INFO "Creating live hosts from target: $TARGET"
            mkdir -p "${PROBE_DIR}"
            echo "https://${TARGET}" > "$hosts_file"
            echo "http://${TARGET}" >> "$hosts_file"
        else
            return 1
        fi
    fi
    return 0
}

# ============================================================================
# HTTPX TECH DETECTION (PRIMARY)
# ============================================================================
run_httpx_fingerprint() {
    log TASK "Running HTTPX tech detection..."
    
    local input="${PROBE_DIR}/live_hosts.txt"
    local output="${FINGER_DIR}/httpx_tech.json"
    local threads=$(get_threads)
    
    # Ensure live_hosts.txt exists (create from TARGET if needed)
    if ! ensure_live_hosts_exist; then
        log WARN "No live hosts file found and no TARGET specified"
        return 1
    fi
    
    httpx -l "$input" \
        -t "$threads" \
        -timeout 15 \
        -retries 2 \
        -silent \
        -tech-detect \
        -status-code \
        -title \
        -web-server \
        -content-type \
        -cdn \
        -ip \
        -cname \
        -json \
        -o "$output" \
        2>/dev/null || true
    
    log INFO "HTTPX fingerprinted $(count_lines "$output") hosts"
    
    # Create tech summary
    if [[ -f "$output" ]]; then
        jq -r '.tech[]? // empty' "$output" 2>/dev/null | sort | uniq -c | sort -rn > "${FINGER_DIR}/tech_summary.txt" || true
        log INFO "Technology summary created"
    fi
}

# ============================================================================
# WHATWEB DEEP FINGERPRINTING
# ============================================================================
run_whatweb() {
    if ! command -v whatweb &>/dev/null; then
        log WARN "WhatWeb not available, skipping..."
        return
    fi
    
    log TASK "Running WhatWeb deep fingerprinting..."
    
    local input="${PROBE_DIR}/live_hosts.txt"
    local output="${FINGER_DIR}/whatweb.json"
    local aggression=3
    
    if [[ "${STEALTH_MODE:-false}" == true ]]; then
        aggression=1
    elif [[ "${AGGRESSIVE_MODE:-false}" == true ]]; then
        aggression=4
    fi
    
    if [[ ! -f "$input" ]]; then
        return
    fi
    
    # WhatWeb can be slow, limit to manageable number
    local max_hosts=500
    local host_count=$(count_lines "$input")
    
    if [[ $host_count -gt $max_hosts ]]; then
        log WARN "Limiting WhatWeb to first $max_hosts hosts"
        head -"$max_hosts" "$input" > "${FINGER_DIR}/whatweb_input.txt"
    else
        cp "$input" "${FINGER_DIR}/whatweb_input.txt"
    fi
    
    whatweb \
        --input-file "${FINGER_DIR}/whatweb_input.txt" \
        --aggression "$aggression" \
        --log-json="$output" \
        --color never \
        --no-errors \
        --quiet \
        2>/dev/null || true
    
    log INFO "WhatWeb completed fingerprinting"
    
    # Parse CMS detection
    if [[ -f "$output" ]]; then
        # Extract WordPress sites
        grep -i "wordpress" "$output" 2>/dev/null | jq -r '.target // empty' 2>/dev/null | sort -u > "${FINGER_DIR}/cms_wordpress.txt" || true
        
        # Extract Joomla sites
        grep -i "joomla" "$output" 2>/dev/null | jq -r '.target // empty' 2>/dev/null | sort -u > "${FINGER_DIR}/cms_joomla.txt" || true
        
        # Extract Drupal sites
        grep -i "drupal" "$output" 2>/dev/null | jq -r '.target // empty' 2>/dev/null | sort -u > "${FINGER_DIR}/cms_drupal.txt" || true
        
        log INFO "CMS detection complete"
    fi
}

# ============================================================================
# WAF DETECTION
# ============================================================================
run_wafw00f() {
    if ! command -v wafw00f &>/dev/null; then
        log WARN "Wafw00f not available, skipping..."
        return
    fi
    
    log TASK "Running WAF detection..."
    
    local input="${PROBE_DIR}/live_hosts.txt"
    local output="${FINGER_DIR}/waf_detection.txt"
    local output_json="${FINGER_DIR}/waf.json"
    
    if [[ ! -f "$input" ]]; then
        return
    fi
    
    # Clear previous results
    > "$output"
    > "$output_json"
    
    # Limit WAF detection to first 200 hosts
    local max_hosts=200
    local count=0
    
    head -"$max_hosts" "$input" | while IFS= read -r url; do
        ((count++))
        # Run wafw00f and append to output (not overwrite)
        wafw00f "$url" 2>/dev/null >> "$output" || true
    done
    
    # Merge WAF results
    if [[ -f "$output" ]] && [[ -s "$output" ]]; then
        # Parse known WAFs
        grep -qi "cloudflare" "$output" 2>/dev/null && touch "${FINGER_DIR}/waf_cloudflare.flag" || true
        grep -qi "akamai" "$output" 2>/dev/null && touch "${FINGER_DIR}/waf_akamai.flag" || true
        grep -qi "aws" "$output" 2>/dev/null && touch "${FINGER_DIR}/waf_aws.flag" || true
        grep -qi "incapsula" "$output" 2>/dev/null && touch "${FINGER_DIR}/waf_incapsula.flag" || true
        grep -qi "sucuri" "$output" 2>/dev/null && touch "${FINGER_DIR}/waf_sucuri.flag" || true
    fi
    
    log INFO "WAF detection complete"
    
    # Alert if WAF detected
    local waf_flags=$(ls "${FINGER_DIR}"/waf_*.flag 2>/dev/null | wc -l)
    if [[ $waf_flags -gt 0 ]]; then
        log ALERT "⚠ WAF detected! Adjusting scan parameters..."
    fi
}

# ============================================================================
# CONSOLIDATE FINGERPRINTS
# ============================================================================
consolidate_fingerprints() {
    log TASK "Consolidating fingerprint data..."
    
    local consolidated="${FINGER_DIR}/consolidated.json"
    local httpx_file="${FINGER_DIR}/httpx_tech.json"
    local whatweb_file="${FINGER_DIR}/whatweb.json"
    
    # Create Python script to merge fingerprints
    python3 << 'PYTHON_SCRIPT' || true
import json
import os
import sys

finger_dir = os.environ.get('FINGER_DIR', './fingerprint')
probe_dir = os.environ.get('PROBE_DIR', './probed')

httpx_file = os.path.join(finger_dir, 'httpx_tech.json')
whatweb_file = os.path.join(finger_dir, 'whatweb.json')
output_file = os.path.join(finger_dir, 'consolidated.json')

consolidated = {}

# Parse HTTPX output
if os.path.exists(httpx_file):
    with open(httpx_file, 'r') as f:
        for line in f:
            try:
                data = json.loads(line.strip())
                url = data.get('url', '')
                if url:
                    consolidated[url] = {
                        'url': url,
                        'status_code': data.get('status_code', 0),
                        'title': data.get('title', ''),
                        'webserver': data.get('webserver', ''),
                        'content_type': data.get('content_type', ''),
                        'tech': data.get('tech', []),
                        'cdn': data.get('cdn', False),
                        'ip': data.get('host', ''),
                        'cname': data.get('cname', ''),
                    }
            except json.JSONDecodeError:
                continue

# Parse WhatWeb output
if os.path.exists(whatweb_file):
    with open(whatweb_file, 'r') as f:
        try:
            whatweb_data = json.load(f)
            if isinstance(whatweb_data, list):
                for entry in whatweb_data:
                    target = entry.get('target', '')
                    if target in consolidated:
                        plugins = entry.get('plugins', {})
                        whatweb_tech = list(plugins.keys())
                        consolidated[target]['whatweb_tech'] = whatweb_tech
                        
                        # Extract versions
                        for plugin_name, plugin_data in plugins.items():
                            if 'version' in plugin_data:
                                if 'versions' not in consolidated[target]:
                                    consolidated[target]['versions'] = {}
                                consolidated[target]['versions'][plugin_name] = plugin_data['version']
        except (json.JSONDecodeError, TypeError):
            pass

# Check for WAF flags
waf_types = []
for flag_file in os.listdir(finger_dir):
    if flag_file.startswith('waf_') and flag_file.endswith('.flag'):
        waf_type = flag_file.replace('waf_', '').replace('.flag', '')
        waf_types.append(waf_type)

# Add WAF info to all entries
for url in consolidated:
    consolidated[url]['waf'] = waf_types

# Write consolidated output
with open(output_file, 'w') as f:
    json.dump(list(consolidated.values()), f, indent=2)

print(f"Consolidated {len(consolidated)} hosts")
PYTHON_SCRIPT
    
    log INFO "Fingerprint consolidation complete"
}

# ============================================================================
# EXTRACT TECH-SPECIFIC TARGET LISTS
# ============================================================================
generate_target_lists() {
    log TASK "Generating technology-specific target lists..."
    
    local consolidated="${FINGER_DIR}/consolidated.json"
    
    if [[ ! -f "$consolidated" ]]; then
        log WARN "No consolidated fingerprint data found"
        return
    fi
    
    python3 << 'PYTHON_SCRIPT' || true
import json
import os

finger_dir = os.environ.get('FINGER_DIR', './fingerprint')
consolidated_file = os.path.join(finger_dir, 'consolidated.json')

# Tech patterns to look for
tech_patterns = {
    'wordpress': ['WordPress', 'wp-', 'wordpress'],
    'joomla': ['Joomla', 'joomla'],
    'drupal': ['Drupal', 'drupal'],
    'laravel': ['Laravel', 'laravel'],
    'spring': ['Spring', 'spring', 'SpringBoot'],
    'tomcat': ['Tomcat', 'Apache-Tomcat'],
    'nginx': ['nginx', 'Nginx'],
    'iis': ['IIS', 'Microsoft-IIS', 'ASP.NET'],
    'apache': ['Apache', 'apache'],
    'nodejs': ['Node.js', 'Express', 'nodejs'],
    'php': ['PHP', 'php'],
    'java': ['Java', 'java', 'JSP'],
    'python': ['Python', 'Django', 'Flask'],
    'ruby': ['Ruby', 'Rails', 'ruby'],
}

targets = {key: [] for key in tech_patterns}

with open(consolidated_file, 'r') as f:
    data = json.load(f)

for entry in data:
    url = entry.get('url', '')
    tech_list = entry.get('tech', [])
    webserver = entry.get('webserver', '')
    whatweb_tech = entry.get('whatweb_tech', [])
    
    all_tech = tech_list + whatweb_tech + [webserver]
    all_tech_str = ' '.join([str(t).lower() for t in all_tech])
    
    for tech_name, patterns in tech_patterns.items():
        for pattern in patterns:
            if pattern.lower() in all_tech_str:
                if url not in targets[tech_name]:
                    targets[tech_name].append(url)
                break

# Write target files
for tech_name, urls in targets.items():
    if urls:
        output_file = os.path.join(finger_dir, f'targets_{tech_name}.txt')
        with open(output_file, 'w') as f:
            f.write('\n'.join(sorted(set(urls))))
        print(f"  {tech_name}: {len(urls)} targets")

PYTHON_SCRIPT
    
    log INFO "Target lists generated"
}

# ============================================================================
# MAIN
# ============================================================================
main() {
    echo ""
    echo "════════════════════════════════════════════════════════════"
    echo "  FINGERPRINTING MODULE"
    echo "════════════════════════════════════════════════════════════"
    echo ""
    
    mkdir -p "$FINGER_DIR"
    
    # Export dirs for Python script
    export FINGER_DIR
    export PROBE_DIR
    
    # Run fingerprinting tools
    run_httpx_fingerprint
    run_whatweb
    run_wafw00f
    
    # Consolidate and generate target lists
    consolidate_fingerprints
    generate_target_lists
    
    echo ""
    echo "════════════════════════════════════════════════════════════"
    echo "  FINGERPRINTING COMPLETE"
    echo "  Consolidated data: ${FINGER_DIR}/consolidated.json"
    echo "════════════════════════════════════════════════════════════"
    echo ""
}

main "$@"

