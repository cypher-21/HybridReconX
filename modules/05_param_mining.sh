#!/usr/bin/env bash
# ============================================================================
# MODULE 05: PARAMETER MINING
# ============================================================================
# Extract and analyze parameters using ParamSpider, Arjun, and GF patterns
# ============================================================================

set -euo pipefail

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

PROBE_DIR="${OUTPUT_BASE}/probed"
CONTENT_DIR="${OUTPUT_BASE}/content"
PARAM_DIR="${OUTPUT_BASE}/params"

log() {
    local level="$1"; shift
    case "$level" in
        INFO) echo -e "${GREEN}[PARAM]${NC} $*" ;;
        WARN) echo -e "${YELLOW}[PARAM]${NC} $*" ;;
        TASK) echo -e "${CYAN}[PARAM]${NC} $*" ;;
    esac
}

count_lines() {
    [[ -f "$1" ]] && wc -l < "$1" | tr -d ' ' || echo "0"
}

get_threads() {
    if [[ -n "${THREADS:-}" ]]; then
        echo "$THREADS"
    elif [[ "${AGGRESSIVE_MODE:-false}" == true ]]; then
        echo "50"
    elif [[ "${STEALTH_MODE:-false}" == true ]]; then
        echo "5"
    else
        echo "20"
    fi
}

# ============================================================================
# PARAMSPIDER (Archive Mining)
# ============================================================================
run_paramspider() {
    log TASK "Running ParamSpider (archive mining)..."
    
    local output_dir="${PARAM_DIR}/paramspider"
    mkdir -p "$output_dir"
    
    if [[ -n "${TARGET:-}" ]]; then
        python3 /opt/tools/ParamSpider/paramspider.py \
            -d "$TARGET" \
            --exclude "jpg,jpeg,png,gif,svg,ico,woff,woff2,ttf,eot,css" \
            --output "${output_dir}/${TARGET}_params.txt" \
            --level high \
            2>/dev/null || log WARN "ParamSpider failed for $TARGET"
    elif [[ -f "${RECON_DIR:-}/root_domains.txt" ]]; then
        while IFS= read -r domain; do
            python3 /opt/tools/ParamSpider/paramspider.py \
                -d "$domain" \
                --exclude "jpg,jpeg,png,gif,svg,ico,woff,woff2,ttf,eot,css" \
                --output "${output_dir}/${domain}_params.txt" \
                --level high \
                2>/dev/null || true
        done < "${RECON_DIR}/root_domains.txt"
    fi
    
    # Merge results
    cat "${output_dir}"/*.txt 2>/dev/null | sort -u > "${PARAM_DIR}/paramspider_all.txt" || true
    
    log INFO "ParamSpider found $(count_lines "${PARAM_DIR}/paramspider_all.txt") URLs with params"
}

# ============================================================================
# ARJUN (Active Parameter Discovery)
# ============================================================================
run_arjun() {
    if [[ "${FAST_MODE:-false}" == true ]]; then
        log WARN "Skipping Arjun in fast mode"
        return
    fi
    
    if ! command -v arjun &>/dev/null; then
        log WARN "Arjun not available, skipping..."
        return
    fi
    
    log TASK "Running Arjun (active parameter discovery)..."
    
    local input="${PROBE_DIR}/live_hosts.txt"
    local output="${PARAM_DIR}/arjun_output.json"
    local threads=$(get_threads)
    
    if [[ ! -f "$input" ]]; then
        return
    fi
    
    # Limit to first 50 hosts
    head -50 "$input" > "${PARAM_DIR}/arjun_input.txt"
    
    arjun -i "${PARAM_DIR}/arjun_input.txt" \
        -t "$threads" \
        -o "$output" \
        --stable \
        2>/dev/null || true
    
    # Parse output
    if [[ -f "$output" ]]; then
        jq -r 'to_entries[] | .key as $url | .value[] | "\($url)?\(.)=FUZZ"' "$output" 2>/dev/null | \
            sort -u > "${PARAM_DIR}/arjun_params.txt" || true
    fi
    
    log INFO "Arjun discovered $(count_lines "${PARAM_DIR}/arjun_params.txt") parameters"
}

# ============================================================================
# EXTRACT PARAMS FROM URLS
# ============================================================================
extract_params_from_urls() {
    log TASK "Extracting parameters from discovered URLs..."
    
    local output="${PARAM_DIR}/extracted_params.txt"
    
    # Combine all URL sources
    cat "${PROBE_DIR}"/historical_urls.txt \
        "${CONTENT_DIR}"/all_urls.txt \
        "${PROBE_DIR}"/interesting_urls.txt \
        2>/dev/null | \
        grep "?" | \
        sort -u > "${PARAM_DIR}/urls_with_params.txt" || true
    
    log INFO "Found $(count_lines "${PARAM_DIR}/urls_with_params.txt") URLs with parameters"
}

# ============================================================================
# GF PATTERNS (Bug Type Classification)
# ============================================================================
run_gf_patterns() {
    if ! command -v gf &>/dev/null; then
        log WARN "GF not available, skipping..."
        return
    fi
    
    log TASK "Running GF pattern matching..."
    
    local input="${PARAM_DIR}/urls_with_params.txt"
    
    if [[ ! -f "$input" ]] || [[ $(count_lines "$input") -eq 0 ]]; then
        log WARN "No URLs with parameters found"
        return
    fi
    
    # Pattern categories
    local patterns=(
        "xss"
        "sqli"
        "lfi"
        "rce"
        "redirect"
        "ssrf"
        "ssti"
        "idor"
        "debug_logic"
        "interestingparams"
        "interestingsubs"
    )
    
    for pattern in "${patterns[@]}"; do
        local output_file="${PARAM_DIR}/gf_${pattern}.txt"
        cat "$input" | gf "$pattern" 2>/dev/null | sort -u > "$output_file" || true
        
        local count=$(count_lines "$output_file")
        if [[ $count -gt 0 ]]; then
            log INFO "GF $pattern: $count matches"
        fi
    done
    
    log INFO "GF pattern matching complete"
}

# ============================================================================
# QSREPLACE (Prepare for Fuzzing)
# ============================================================================
prepare_fuzz_payloads() {
    if ! command -v qsreplace &>/dev/null; then
        log WARN "qsreplace not available, skipping..."
        return
    fi
    
    log TASK "Preparing URLs for fuzzing..."
    
    # XSS test payloads
    if [[ -f "${PARAM_DIR}/gf_xss.txt" ]] && [[ $(count_lines "${PARAM_DIR}/gf_xss.txt") -gt 0 ]]; then
        cat "${PARAM_DIR}/gf_xss.txt" | qsreplace 'FUZZ' | sort -u > "${PARAM_DIR}/xss_fuzz_ready.txt" 2>/dev/null || true
        log INFO "XSS fuzz-ready URLs: $(count_lines "${PARAM_DIR}/xss_fuzz_ready.txt")"
    fi
    
    # SQLi test payloads
    if [[ -f "${PARAM_DIR}/gf_sqli.txt" ]] && [[ $(count_lines "${PARAM_DIR}/gf_sqli.txt") -gt 0 ]]; then
        cat "${PARAM_DIR}/gf_sqli.txt" | qsreplace 'FUZZ' | sort -u > "${PARAM_DIR}/sqli_fuzz_ready.txt" 2>/dev/null || true
        log INFO "SQLi fuzz-ready URLs: $(count_lines "${PARAM_DIR}/sqli_fuzz_ready.txt")"
    fi
    
    # LFI test payloads
    if [[ -f "${PARAM_DIR}/gf_lfi.txt" ]] && [[ $(count_lines "${PARAM_DIR}/gf_lfi.txt") -gt 0 ]]; then
        cat "${PARAM_DIR}/gf_lfi.txt" | qsreplace 'FUZZ' | sort -u > "${PARAM_DIR}/lfi_fuzz_ready.txt" 2>/dev/null || true
        log INFO "LFI fuzz-ready URLs: $(count_lines "${PARAM_DIR}/lfi_fuzz_ready.txt")"
    fi
    
    # SSRF test payloads
    if [[ -f "${PARAM_DIR}/gf_ssrf.txt" ]] && [[ $(count_lines "${PARAM_DIR}/gf_ssrf.txt") -gt 0 ]]; then
        cat "${PARAM_DIR}/gf_ssrf.txt" | qsreplace 'FUZZ' | sort -u > "${PARAM_DIR}/ssrf_fuzz_ready.txt" 2>/dev/null || true
        log INFO "SSRF fuzz-ready URLs: $(count_lines "${PARAM_DIR}/ssrf_fuzz_ready.txt")"
    fi
    
    # RCE test payloads
    if [[ -f "${PARAM_DIR}/gf_rce.txt" ]] && [[ $(count_lines "${PARAM_DIR}/gf_rce.txt") -gt 0 ]]; then
        cat "${PARAM_DIR}/gf_rce.txt" | qsreplace 'FUZZ' | sort -u > "${PARAM_DIR}/rce_fuzz_ready.txt" 2>/dev/null || true
        log INFO "RCE fuzz-ready URLs: $(count_lines "${PARAM_DIR}/rce_fuzz_ready.txt")"
    fi
    
    # SSTI test payloads
    if [[ -f "${PARAM_DIR}/gf_ssti.txt" ]] && [[ $(count_lines "${PARAM_DIR}/gf_ssti.txt") -gt 0 ]]; then
        cat "${PARAM_DIR}/gf_ssti.txt" | qsreplace 'FUZZ' | sort -u > "${PARAM_DIR}/ssti_fuzz_ready.txt" 2>/dev/null || true
        log INFO "SSTI fuzz-ready URLs: $(count_lines "${PARAM_DIR}/ssti_fuzz_ready.txt")"
    fi
}

# ============================================================================
# GENERATE PARAMETER SUMMARY
# ============================================================================
generate_param_summary() {
    log TASK "Generating parameter summary..."
    
    local summary="${PARAM_DIR}/summary.json"
    
    python3 << 'PYTHON_SCRIPT' || true
import json
import os
from pathlib import Path
from urllib.parse import urlparse, parse_qs

param_dir = os.environ.get('PARAM_DIR', './params')
summary = {
    'total_urls_with_params': 0,
    'unique_parameters': [],
    'by_category': {},
    'top_parameters': {}
}

# Count parameters
param_counts = {}

urls_file = os.path.join(param_dir, 'urls_with_params.txt')
if os.path.exists(urls_file):
    with open(urls_file, 'r') as f:
        for line in f:
            line = line.strip()
            if '?' in line:
                summary['total_urls_with_params'] += 1
                try:
                    parsed = urlparse(line)
                    params = parse_qs(parsed.query)
                    for param in params.keys():
                        param_counts[param] = param_counts.get(param, 0) + 1
                except:
                    pass

# Top parameters
top_params = sorted(param_counts.items(), key=lambda x: x[1], reverse=True)[:50]
summary['top_parameters'] = dict(top_params)
summary['unique_parameters'] = list(param_counts.keys())

# Category counts
categories = ['xss', 'sqli', 'lfi', 'rce', 'ssrf', 'ssti', 'redirect', 'idor']
for cat in categories:
    cat_file = os.path.join(param_dir, f'gf_{cat}.txt')
    if os.path.exists(cat_file):
        with open(cat_file, 'r') as f:
            summary['by_category'][cat] = len(f.readlines())

# Write summary
with open(os.path.join(param_dir, 'summary.json'), 'w') as f:
    json.dump(summary, f, indent=2)

print(f"Total URLs with params: {summary['total_urls_with_params']}")
print(f"Unique parameters: {len(summary['unique_parameters'])}")
for cat, count in summary['by_category'].items():
    if count > 0:
        print(f"  {cat}: {count}")
PYTHON_SCRIPT
    
    log INFO "Parameter summary generated"
}

# ============================================================================
# MAIN
# ============================================================================
main() {
    echo ""
    echo "════════════════════════════════════════════════════════════"
    echo "  PARAMETER MINING MODULE"
    echo "════════════════════════════════════════════════════════════"
    echo ""
    
    mkdir -p "$PARAM_DIR"
    export PARAM_DIR
    export RECON_DIR="${OUTPUT_BASE}/recon"
    
    # Run param mining tools
    run_paramspider
    run_arjun
    extract_params_from_urls
    
    # Pattern matching
    run_gf_patterns
    
    # Prepare for fuzzing
    prepare_fuzz_payloads
    
    # Summary
    generate_param_summary
    
    echo ""
    echo "════════════════════════════════════════════════════════════"
    echo "  PARAMETER MINING COMPLETE"
    echo "  URLs with params: $(count_lines "${PARAM_DIR}/urls_with_params.txt")"
    echo "  XSS candidates: $(count_lines "${PARAM_DIR}/gf_xss.txt")"
    echo "  SQLi candidates: $(count_lines "${PARAM_DIR}/gf_sqli.txt")"
    echo "════════════════════════════════════════════════════════════"
    echo ""
}

main "$@"
