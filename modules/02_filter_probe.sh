#!/usr/bin/env bash
# ============================================================================
# MODULE 02: PROBING & URL EXTRACTION
# ============================================================================
# HTTPX probing for live hosts + Historical URL fetching
# ============================================================================

set -euo pipefail

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

PROBE_DIR="${OUTPUT_BASE}/probed"
RECON_DIR="${OUTPUT_BASE}/recon"

log() {
    local level="$1"; shift
    case "$level" in
        INFO) echo -e "${GREEN}[PROBE]${NC} $*" ;;
        WARN) echo -e "${YELLOW}[PROBE]${NC} $*" ;;
        TASK) echo -e "${CYAN}[PROBE]${NC} $*" ;;
    esac
}

count_lines() {
    [[ -f "$1" ]] && wc -l < "$1" | tr -d ' ' || echo "0"
}

get_threads() {
    if [[ -n "${THREADS:-}" ]]; then
        echo "$THREADS"
    elif [[ "${AGGRESSIVE_MODE:-false}" == true ]]; then
        echo "100"
    elif [[ "${STEALTH_MODE:-false}" == true ]]; then
        echo "10"
    else
        echo "50"
    fi
}

get_rate_limit() {
    if [[ -n "${RATE_LIMIT:-}" ]]; then
        echo "$RATE_LIMIT"
    elif [[ "${STEALTH_MODE:-false}" == true ]]; then
        echo "10"
    else
        echo "150"
    fi
}

# ============================================================================
# HTTPX PROBING (THE CORE)
# ============================================================================
run_httpx() {
    log TASK "Running HTTPX probing..."
    
    local input="${RECON_DIR}/clean_subdomains.txt"
    local output="${PROBE_DIR}/httpx_output.json"
    local live_hosts="${PROBE_DIR}/live_hosts.txt"
    local threads=$(get_threads)
    local rate=$(get_rate_limit)
    
    if [[ ! -f "$input" ]]; then
        log WARN "No subdomains file found at $input"
        # Create from target if available
        if [[ -n "${TARGET:-}" ]]; then
            echo "$TARGET" > "$input"
        else
            return 1
        fi
    fi
    
    httpx -l "$input" \
        -t "$threads" \
        -rl "$rate" \
        -timeout 10 \
        -retries 2 \
        -silent \
        -status-code \
        -content-length \
        -title \
        -web-server \
        -tech-detect \
        -cdn \
        -location \
        -method \
        -ip \
        -cname \
        -follow-redirects \
        -json \
        -o "$output" \
        2>/dev/null || true
    
    # Extract just the URLs for other tools
    if [[ -f "$output" ]]; then
        jq -r '.url // empty' "$output" 2>/dev/null | sort -u > "$live_hosts"
    fi
    
    log INFO "Found $(count_lines "$live_hosts") live hosts"
}

# ============================================================================
# CREATE SIMPLIFIED HOSTS LIST
# ============================================================================
create_host_lists() {
    log TASK "Creating categorized host lists..."
    
    local json_file="${PROBE_DIR}/httpx_output.json"
    
    if [[ ! -f "$json_file" ]]; then
        log WARN "No HTTPX JSON output found"
        return
    fi
    
    # By status code
    jq -r 'select(.status_code >= 200 and .status_code < 300) | .url' "$json_file" 2>/dev/null | sort -u > "${PROBE_DIR}/live_2xx.txt" || true
    jq -r 'select(.status_code >= 300 and .status_code < 400) | .url' "$json_file" 2>/dev/null | sort -u > "${PROBE_DIR}/live_3xx.txt" || true
    jq -r 'select(.status_code == 401 or .status_code == 403) | .url' "$json_file" 2>/dev/null | sort -u > "${PROBE_DIR}/live_auth.txt" || true
    jq -r 'select(.status_code >= 500) | .url' "$json_file" 2>/dev/null | sort -u > "${PROBE_DIR}/live_5xx.txt" || true
    
    # Extract hosts with interesting content lengths (potential content)
    jq -r 'select(.content_length > 0) | .url' "$json_file" 2>/dev/null | sort -u > "${PROBE_DIR}/live_with_content.txt" || true
    
    log INFO "Categorized hosts by status code"
}

# ============================================================================
# HISTORICAL URL FETCHING
# ============================================================================
run_gau() {
    log TASK "Fetching historical URLs (GAU)..."
    
    local output="${PROBE_DIR}/gau_urls.txt"
    
    if [[ -n "${TARGET:-}" ]]; then
        echo "$TARGET" | gau --threads 5 --subs 2>/dev/null > "$output" || true
    elif [[ -f "${RECON_DIR}/root_domains.txt" ]]; then
        while IFS= read -r domain; do
            echo "$domain" | gau --threads 5 --subs 2>/dev/null >> "$output" || true
        done < "${RECON_DIR}/root_domains.txt"
    fi
    
    log INFO "GAU found $(count_lines "$output") historical URLs"
}

run_waybackurls() {
    log TASK "Fetching Wayback URLs..."
    
    local output="${PROBE_DIR}/wayback_urls.txt"
    
    if [[ -n "${TARGET:-}" ]]; then
        echo "$TARGET" | waybackurls 2>/dev/null > "$output" || true
    elif [[ -f "${RECON_DIR}/root_domains.txt" ]]; then
        cat "${RECON_DIR}/root_domains.txt" | waybackurls 2>/dev/null > "$output" || true
    fi
    
    log INFO "Wayback found $(count_lines "$output") historical URLs"
}

# ============================================================================
# MERGE HISTORICAL URLS
# ============================================================================
merge_historical_urls() {
    log TASK "Merging historical URLs..."
    
    local merged="${PROBE_DIR}/historical_urls.txt"
    
    cat "${PROBE_DIR}"/gau_urls.txt "${PROBE_DIR}"/wayback_urls.txt 2>/dev/null | \
        sort -u | \
        grep -v "\.jpg$\|\.jpeg$\|\.png$\|\.gif$\|\.svg$\|\.ico$\|\.woff\|\.ttf\|\.css$" \
        > "$merged" 2>/dev/null || true
    
    # Filter for interesting extensions
    grep -iE "\.(php|asp|aspx|jsp|json|xml|txt|js|html|htm|action|do|cgi)(\?|$)" "$merged" 2>/dev/null | \
        sort -u > "${PROBE_DIR}/interesting_urls.txt" || true
    
    log INFO "Total unique historical URLs: $(count_lines "$merged")"
    log INFO "Interesting URLs: $(count_lines "${PROBE_DIR}/interesting_urls.txt")"
}

# ============================================================================
# PROBE HISTORICAL URLS
# ============================================================================
probe_historical() {
    if [[ "${FAST_MODE:-false}" == true ]]; then
        log WARN "Skipping historical URL probing in fast mode"
        return
    fi
    
    log TASK "Probing historical URLs..."
    
    local input="${PROBE_DIR}/interesting_urls.txt"
    local output="${PROBE_DIR}/historical_live.txt"
    local threads=$(get_threads)
    local rate=$(get_rate_limit)
    
    if [[ -f "$input" ]] && [[ $(count_lines "$input") -gt 0 ]]; then
        # Limit to first 5000 URLs to avoid overwhelming
        head -5000 "$input" | httpx \
            -t "$threads" \
            -rl "$rate" \
            -timeout 5 \
            -silent \
            -mc 200,201,301,302,307,401,403,405,500 \
            -o "$output" \
            2>/dev/null || true
        
        log INFO "Live historical URLs: $(count_lines "$output")"
    fi
}

# ============================================================================
# EXTRACT JS FILES
# ============================================================================
extract_js_files() {
    log TASK "Extracting JavaScript files..."
    
    local output="${PROBE_DIR}/js_files.txt"
    
    # From httpx output
    if [[ -f "${PROBE_DIR}/httpx_output.json" ]]; then
        jq -r '.url // empty' "${PROBE_DIR}/httpx_output.json" 2>/dev/null | \
            grep -iE "\.js(\?|$)" >> "$output" 2>/dev/null || true
    fi
    
    # From historical URLs
    cat "${PROBE_DIR}"/*_urls.txt 2>/dev/null | \
        grep -iE "\.js(\?|$)" | \
        sort -u >> "$output" 2>/dev/null || true
    
    sort -u -o "$output" "$output" 2>/dev/null || true
    
    log INFO "Found $(count_lines "$output") JavaScript files"
}

# ============================================================================
# MAIN
# ============================================================================
main() {
    echo ""
    echo "════════════════════════════════════════════════════════════"
    echo "  HTTP PROBING & URL EXTRACTION"
    echo "════════════════════════════════════════════════════════════"
    echo ""
    
    mkdir -p "$PROBE_DIR"
    
    # Core probing
    run_httpx
    create_host_lists
    
    # Historical URL fetching
    run_gau
    run_waybackurls
    merge_historical_urls
    probe_historical
    
    # Extract interesting file types
    extract_js_files
    
    echo ""
    echo "════════════════════════════════════════════════════════════"
    echo "  PROBING COMPLETE"
    echo "  Live hosts: $(count_lines "${PROBE_DIR}/live_hosts.txt")"
    echo "  Historical URLs: $(count_lines "${PROBE_DIR}/historical_urls.txt")"
    echo "════════════════════════════════════════════════════════════"
    echo ""
}

main "$@"
