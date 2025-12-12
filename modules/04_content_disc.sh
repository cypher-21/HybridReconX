#!/usr/bin/env bash
# ============================================================================
# MODULE 04: CONTENT DISCOVERY
# ============================================================================
# Fuzzing with FFUF, crawling with Katana, special file detection
# ============================================================================

set -euo pipefail

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RED='\033[0;31m'
NC='\033[0m'

PROBE_DIR="${OUTPUT_BASE}/probed"
CONTENT_DIR="${OUTPUT_BASE}/content"
FINGER_DIR="${OUTPUT_BASE}/fingerprint"

log() {
    local level="$1"; shift
    case "$level" in
        INFO) echo -e "${GREEN}[CONTENT]${NC} $*" ;;
        WARN) echo -e "${YELLOW}[CONTENT]${NC} $*" ;;
        TASK) echo -e "${CYAN}[CONTENT]${NC} $*" ;;
        ALERT) echo -e "${RED}[!!! FINDING]${NC} $*" ;;
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
        echo "40"
    fi
}

get_rate_limit() {
    # Check if WAF was detected
    if [[ -f "${FINGER_DIR}/waf_cloudflare.flag" ]]; then
        echo "10"
        return
    elif [[ -f "${FINGER_DIR}/waf_akamai.flag" ]]; then
        echo "5"
        return
    fi
    
    if [[ -n "${RATE_LIMIT:-}" ]]; then
        echo "$RATE_LIMIT"
    elif [[ "${STEALTH_MODE:-false}" == true ]]; then
        echo "5"
    else
        echo "150"
    fi
}

get_wordlist() {
    # Try to find best available wordlist
    local wordlists=(
        "/opt/wordlists/active/directories.txt"
        "/opt/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories.txt"
        "/opt/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt"
        "${DATA_DIR}/wordlists/common.txt"
    )
    
    for wl in "${wordlists[@]}"; do
        if [[ -f "$wl" ]]; then
            echo "$wl"
            return
        fi
    done
    
    echo ""
}

# ============================================================================
# FFUF DIRECTORY FUZZING (PRIMARY FUZZER)
# ============================================================================
run_ffuf() {
    log TASK "Running FFUF directory fuzzing..."
    
    local input="${PROBE_DIR}/live_hosts.txt"
    local output_dir="${CONTENT_DIR}/ffuf"
    local threads=$(get_threads)
    local rate=$(get_rate_limit)
    local wordlist=$(get_wordlist)
    
    mkdir -p "$output_dir"
    
    if [[ -z "$wordlist" ]]; then
        log WARN "No wordlist found, skipping FFUF"
        return
    fi
    
    if [[ ! -f "$input" ]]; then
        log WARN "No live hosts file found"
        return
    fi
    
    local host_count=$(count_lines "$input")
    local max_hosts=100
    
    if [[ $host_count -gt $max_hosts ]]; then
        log WARN "Limiting FFUF to first $max_hosts hosts"
        head -"$max_hosts" "$input" > "${output_dir}/ffuf_targets.txt"
    else
        cp "$input" "${output_dir}/ffuf_targets.txt"
    fi
    
    while IFS= read -r url; do
        # Sanitize URL for filename
        local safe_name=$(echo "$url" | sed 's/[^a-zA-Z0-9]/_/g' | cut -c1-50)
        local output_file="${output_dir}/${safe_name}.json"
        
        log INFO "Fuzzing: $url"
        
        ffuf -u "${url}/FUZZ" \
            -w "$wordlist" \
            -t "$threads" \
            -rate "$rate" \
            -timeout 10 \
            -ac \
            -mc "200,201,204,301,302,307,401,403,405,500" \
            -fs 0 \
            -fc 404 \
            -sf \
            -se \
            -o "$output_file" \
            -of json \
            -s \
            2>/dev/null || true
        
    done < "${output_dir}/ffuf_targets.txt"
    
    # Merge results
    log TASK "Merging FFUF results..."
    find "$output_dir" -name "*.json" -exec cat {} \; 2>/dev/null | \
        jq -r '.results[]? | .url // empty' 2>/dev/null | \
        sort -u > "${CONTENT_DIR}/ffuf_discovered.txt" || true
    
    log INFO "FFUF discovered $(count_lines "${CONTENT_DIR}/ffuf_discovered.txt") paths"
}

# ============================================================================
# SPECIAL FILE DETECTION (.git, .env, etc.)
# ============================================================================
detect_special_files() {
    log TASK "Detecting special/sensitive files..."
    
    local input="${PROBE_DIR}/live_hosts.txt"
    local output="${CONTENT_DIR}/special_files.txt"
    local git_found="${CONTENT_DIR}/git_exposed.txt"
    local env_found="${CONTENT_DIR}/env_exposed.txt"
    local threads=$(get_threads)
    local rate=$(get_rate_limit)
    
    # Special paths to check
    local special_paths=(
        ".git/config"
        ".git/HEAD"
        ".env"
        ".env.local"
        ".env.production"
        ".env.backup"
        "wp-config.php.bak"
        "web.config"
        "config.php.bak"
        "database.yml"
        ".htpasswd"
        ".DS_Store"
        "backup.sql"
        "dump.sql"
        ".svn/entries"
        "phpinfo.php"
        "info.php"
        "server-status"
        "actuator/env"
        "actuator/heapdump"
        ".well-known/security.txt"
        "robots.txt"
        "sitemap.xml"
        "crossdomain.xml"
        "composer.json"
        "package.json"
    )
    
    # Create temp wordlist
    printf '%s\n' "${special_paths[@]}" > "${CONTENT_DIR}/special_paths.txt"
    
    if [[ ! -f "$input" ]]; then
        return
    fi
    
    # Use HTTPX for fast checking
    while IFS= read -r url; do
        for path in "${special_paths[@]}"; do
            local full_url="${url}/${path}"
            echo "$full_url"
        done
    done < "$input" | head -5000 | httpx \
        -t "$threads" \
        -rl "$rate" \
        -silent \
        -mc 200 \
        -cl \
        -o "$output" \
        2>/dev/null || true
    
    # Extract .git exposures
    grep -i "\.git" "$output" 2>/dev/null > "$git_found" || true
    
    # Extract .env exposures
    grep -i "\.env" "$output" 2>/dev/null > "$env_found" || true
    
    local git_count=$(count_lines "$git_found")
    local env_count=$(count_lines "$env_found")
    
    if [[ $git_count -gt 0 ]]; then
        log ALERT "🚨 FOUND $git_count exposed .git directories!"
        cat "$git_found"
    fi
    
    if [[ $env_count -gt 0 ]]; then
        log ALERT "🚨 FOUND $env_count exposed .env files!"
        cat "$env_found"
    fi
    
    log INFO "Special file detection complete"
}

# ============================================================================
# KATANA CRAWLING
# ============================================================================
run_katana() {
    if ! command -v katana &>/dev/null; then
        log WARN "Katana not available, skipping..."
        return
    fi
    
    log TASK "Running Katana crawling..."
    
    local input="${PROBE_DIR}/live_hosts.txt"
    local output="${CONTENT_DIR}/katana_output.txt"
    local js_output="${CONTENT_DIR}/katana_js.txt"
    local threads=$(get_threads)
    
    if [[ ! -f "$input" ]]; then
        return
    fi
    
    local depth=3
    if [[ "${FAST_MODE:-false}" == true ]]; then
        depth=2
    elif [[ "${AGGRESSIVE_MODE:-false}" == true ]]; then
        depth=5
    fi
    
    # Limit number of hosts
    local max_hosts=50
    head -"$max_hosts" "$input" > "${CONTENT_DIR}/katana_input.txt"
    
    katana -list "${CONTENT_DIR}/katana_input.txt" \
        -d "$depth" \
        -c "$threads" \
        -jc \
        -kf all \
        -silent \
        -o "$output" \
        2>/dev/null || true
    
    # Extract JS files
    grep -iE "\.js(\?|$)" "$output" 2>/dev/null | sort -u > "$js_output" || true
    
    log INFO "Katana discovered $(count_lines "$output") URLs"
    log INFO "JavaScript files: $(count_lines "$js_output")"
}

# ============================================================================
# HAKRAWLER (Fast Go Crawler)
# ============================================================================
run_hakrawler() {
    if [[ "${FAST_MODE:-false}" == true ]]; then
        log WARN "Skipping Hakrawler in fast mode"
        return
    fi
    
    if ! command -v hakrawler &>/dev/null; then
        log WARN "Hakrawler not available, skipping..."
        return
    fi
    
    log TASK "Running Hakrawler..."
    
    local input="${PROBE_DIR}/live_hosts.txt"
    local output="${CONTENT_DIR}/hakrawler_output.txt"
    
    if [[ ! -f "$input" ]]; then
        return
    fi
    
    head -50 "$input" | hakrawler -d 3 -subs -u 2>/dev/null > "$output" || true
    
    log INFO "Hakrawler discovered $(count_lines "$output") URLs"
}

# ============================================================================
# FEROXBUSTER (Recursive - Heavy)
# ============================================================================
run_feroxbuster() {
    if [[ "${FAST_MODE:-false}" == true ]]; then
        log WARN "Skipping Feroxbuster in fast mode"
        return
    fi
    
    if ! command -v feroxbuster &>/dev/null; then
        log WARN "Feroxbuster not available, skipping..."
        return
    fi
    
    log TASK "Running Feroxbuster (recursive)..."
    
    local input="${PROBE_DIR}/live_hosts.txt"
    local output_dir="${CONTENT_DIR}/feroxbuster"
    local wordlist=$(get_wordlist)
    local threads=$(get_threads)
    local rate=$(get_rate_limit)
    
    mkdir -p "$output_dir"
    
    if [[ -z "$wordlist" ]]; then
        return
    fi
    
    # Only run on first 10 hosts due to recursion being heavy
    head -10 "$input" | while IFS= read -r url; do
        local safe_name=$(echo "$url" | sed 's/[^a-zA-Z0-9]/_/g' | cut -c1-50)
        
        timeout 300 feroxbuster \
            -u "$url" \
            -w "$wordlist" \
            -t "$threads" \
            --rate-limit "$rate" \
            -d 2 \
            --silent \
            -o "${output_dir}/${safe_name}.txt" \
            2>/dev/null || true
    done
    
    # Merge
    cat "${output_dir}"/*.txt 2>/dev/null | sort -u > "${CONTENT_DIR}/feroxbuster_all.txt" || true
    
    log INFO "Feroxbuster completed"
}

# ============================================================================
# MERGE ALL DISCOVERED CONTENT
# ============================================================================
merge_all_content() {
    log TASK "Merging all discovered content..."
    
    local merged="${CONTENT_DIR}/all_urls.txt"
    
    # Merge all sources
    cat "${CONTENT_DIR}"/*.txt \
        "${CONTENT_DIR}/ffuf"/*.json 2>/dev/null | \
        grep -E "^https?://" | \
        sort -u > "$merged" 2>/dev/null || true
    
    # Merge JSON outputs
    find "${CONTENT_DIR}" -name "*.json" -exec jq -r '.results[]?.url // empty' {} \; 2>/dev/null | \
        sort -u >> "$merged" 2>/dev/null || true
    
    sort -u -o "$merged" "$merged"
    
    log INFO "Total unique URLs discovered: $(count_lines "$merged")"
    
    # Create categorized lists
    grep -iE "\.(php|asp|aspx|jsp)" "$merged" 2>/dev/null | sort -u > "${CONTENT_DIR}/dynamic_pages.txt" || true
    grep -iE "/api/|/v[0-9]+/|graphql" "$merged" 2>/dev/null | sort -u > "${CONTENT_DIR}/api_endpoints.txt" || true
    grep -iE "admin|login|dashboard|panel|manage" "$merged" 2>/dev/null | sort -u > "${CONTENT_DIR}/admin_pages.txt" || true
    grep -iE "upload|file|download|export|import" "$merged" 2>/dev/null | sort -u > "${CONTENT_DIR}/file_handling.txt" || true
    
    log INFO "Categorized output created"
}

# ============================================================================
# MAIN
# ============================================================================
main() {
    echo ""
    echo "════════════════════════════════════════════════════════════"
    echo "  CONTENT DISCOVERY MODULE"
    echo "════════════════════════════════════════════════════════════"
    echo ""
    
    mkdir -p "$CONTENT_DIR"
    
    # Run discovery tools
    run_ffuf
    detect_special_files
    run_katana
    run_hakrawler
    run_feroxbuster
    
    # Merge results
    merge_all_content
    
    echo ""
    echo "════════════════════════════════════════════════════════════"
    echo "  CONTENT DISCOVERY COMPLETE"
    echo "  Total URLs: $(count_lines "${CONTENT_DIR}/all_urls.txt")"
    echo "  Git exposed: $(count_lines "${CONTENT_DIR}/git_exposed.txt")"
    echo "  Env exposed: $(count_lines "${CONTENT_DIR}/env_exposed.txt")"
    echo "════════════════════════════════════════════════════════════"
    echo ""
}

main "$@"
