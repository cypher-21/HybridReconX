#!/usr/bin/env bash
# ============================================================================
# MODULE 04: CONTENT DISCOVERY
# ============================================================================
# Fuzzing with FFUF, crawling with Katana, special file detection
# ============================================================================

# Don't exit on errors - tools may fail without meaning module failure
set -uo pipefail

# ============================================================================
# INTERRUPT HANDLING
# ============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source config library
[[ -f "${SCRIPT_DIR}/../lib/config.sh" ]] && source "${SCRIPT_DIR}/../lib/config.sh"

# Source interrupt handling
if [[ -f "${SCRIPT_DIR}/../lib/interrupt.sh" ]]; then
    source "${SCRIPT_DIR}/../lib/interrupt.sh"
    install_module_handler
fi

# Source logging library (centralized log(), count_lines(), get_threads(), get_rate_limit())
[[ -f "${SCRIPT_DIR}/../lib/logging.sh" ]] && source "${SCRIPT_DIR}/../lib/logging.sh"
set_log_module "CONTENT"

PROBE_DIR="${OUTPUT_BASE}/probed"
CONTENT_DIR="${OUTPUT_BASE}/content"
FINGER_DIR="${OUTPUT_BASE}/fingerprint"

# Module-specific get_rate_limit that checks for WAF flags
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
    # If in fast mode, prioritize small high-signal common wordlist
    if [[ "${FAST_MODE:-false}" == true ]]; then
        local fast_lists=(
            "/opt/wordlists/SecLists/Discovery/Web-Content/common.txt"
            "${DATA_DIR}/wordlists/common.txt"
        )
        for wl in "${fast_lists[@]}"; do
            [[ -f "$wl" ]] && echo "$wl" && return
        done
    fi
    
    # Return the best primary wordlist for FFUF (SecLists for broad coverage)
    local wordlists=(
        "/opt/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories.txt"
        "/opt/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt"
        "/opt/wordlists/SecLists/Discovery/Web-Content/common.txt"
        "/opt/wordlists/active/directories.txt"
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

get_merged_wordlist() {
    # Create merged wordlist: Custom (high-signal) + SecLists (broad coverage)
    # Returns path to merged file
    local merged_file="${CONTENT_DIR}/.merged_wordlist.txt"
    local temp_custom="${CONTENT_DIR}/.custom_words.txt"
    local temp_seclists="${CONTENT_DIR}/.seclists_words.txt"
    
    mkdir -p "${CONTENT_DIR}"
    > "$temp_custom"
    > "$temp_seclists"
    
    # Step 1: Collect custom wordlists (high-signal, run first)
    log INFO "Loading custom wordlists..."
    local custom_dir="${DATA_DIR}/wordlists/custom"
    if [[ -d "$custom_dir" ]]; then
        for f in "$custom_dir"/*.txt; do
            [[ -f "$f" ]] && cat "$f" >> "$temp_custom"
        done
    fi
    [[ -f "${DATA_DIR}/wordlists/common.txt" ]] && cat "${DATA_DIR}/wordlists/common.txt" >> "$temp_custom"
    
    # Step 2: Collect SecLists wordlists (broad coverage)
    log INFO "Loading SecLists wordlists..."
    local seclists="/opt/wordlists/SecLists/Discovery/Web-Content"
    if [[ -d "$seclists" ]]; then
        [[ -f "$seclists/common.txt" ]] && cat "$seclists/common.txt" >> "$temp_seclists"
        [[ -f "$seclists/raft-medium-directories.txt" ]] && cat "$seclists/raft-medium-directories.txt" >> "$temp_seclists"
    fi
    
    # Step 3: Merge - custom first, then seclists (deduplicated)
    # Custom first ensures high-signal paths are tested first
    cat "$temp_custom" "$temp_seclists" 2>/dev/null | sort -u > "$merged_file"
    
    # Cleanup temp files
    rm -f "$temp_custom" "$temp_seclists"
    
    local total_lines=$(wc -l < "$merged_file")
    log INFO "Created merged wordlist: $total_lines entries (custom + SecLists)"
    
    echo "$merged_file"
}

get_all_wordlists() {
    # Return ALL available wordlists for maximum coverage (as array)
    local found_lists=()
    
    # Custom wordlists FIRST (high-signal)
    local custom_dir="${DATA_DIR}/wordlists/custom"
    if [[ -d "$custom_dir" ]]; then
        for f in "$custom_dir"/*.txt; do
            [[ -f "$f" ]] && found_lists+=("$f")
        done
    fi
    
    # SecLists directories (broad coverage)
    local seclists="/opt/wordlists/SecLists/Discovery/Web-Content"
    if [[ -d "$seclists" ]]; then
        [[ -f "$seclists/common.txt" ]] && found_lists+=("$seclists/common.txt")
        [[ -f "$seclists/raft-medium-directories.txt" ]] && found_lists+=("$seclists/raft-medium-directories.txt")
    fi
    
    printf '%s\n' "${found_lists[@]}"
}

# ============================================================================
# HTTPX QUICK PATH CHECK (Fast Discovery)
# ============================================================================
# Uses httpx -path to quickly check common sensitive paths before heavy fuzzing
run_httpx_quick_paths() {
    log TASK "Running HTTPX quick path checks..."
    
    local input="${PROBE_DIR}/live_hosts.txt"
    local output="${CONTENT_DIR}/httpx_paths.txt"
    local special="${CONTENT_DIR}/special_files.txt"
    
    if [[ ! -f "$input" ]]; then
        log WARN "No live hosts file, skipping quick path checks"
        return
    fi
    
    mkdir -p "${CONTENT_DIR}"
    
    # High-value paths to check - these are goldmines
    local paths=(
        "/.git/HEAD"
        "/.git/config"
        "/.env"
        "/.env.local"
        "/.env.production"
        "/admin"
        "/administrator"
        "/admin/login"
        "/wp-admin"
        "/wp-login.php"
        "/login"
        "/dashboard"
        "/api"
        "/api/v1"
        "/api/swagger"
        "/swagger.json"
        "/swagger-ui.html"
        "/graphql"
        "/graphiql"
        "/debug"
        "/.htaccess"
        "/.htpasswd"
        "/backup"
        "/backup.zip"
        "/backup.sql"
        "/db.sql"
        "/dump.sql"
        "/phpinfo.php"
        "/info.php"
        "/server-status"
        "/robots.txt"
        "/sitemap.xml"
        "/.well-known/security.txt"
        "/actuator"
        "/actuator/health"
        "/actuator/env"
        "/config.php"
        "/config.json"
        "/config.yml"
        "/package.json"
        "/composer.json"
        "/.aws/credentials"
        "/.docker/config.json"
    )
    
    # Create temp file with paths
    local paths_file="${CONTENT_DIR}/.quick_paths.txt"
    printf '%s\n' "${paths[@]}" > "$paths_file"
    
    local threads=$(get_threads)
    local rate=$(get_rate_limit)
    
    # Run httpx with path probing
    if command -v httpx &>/dev/null; then
        cat "$input" | httpx \
            -paths "$paths_file" \
            -t "$threads" \
            -rl "$rate" \
            -silent \
            -mc 200,201,301,302,401,403,405 \
            -o "$output" \
            2>/dev/null || true
        
        local found=$(count_lines "$output")
        log INFO "Quick path check found $found accessible paths"
        
        # Extract special/sensitive files
        grep -iE "\.git|\.env|admin|backup|dump|sql|config|phpinfo|actuator|swagger|graphql" "$output" 2>/dev/null > "$special" || true
        
        local sensitive=$(count_lines "$special")
        if [[ "$sensitive" -gt 0 ]]; then
            log SUCCESS "🎯 Found $sensitive potentially sensitive paths!"
        fi
    else
        log WARN "HTTPX not found for quick path checks"
    fi
    
    rm -f "$paths_file"
}

# ============================================================================
# FFUF DIRECTORY FUZZING (PRIMARY FUZZER)
# ============================================================================

# Helper: Ensure live_hosts.txt exists (for standalone --only-content mode)
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
    
    # Ensure live_hosts.txt exists (create from TARGET if needed)
    if ! ensure_live_hosts_exist; then
        log WARN "No live hosts file found and no TARGET specified"
        return
    fi
    
    # Determine max hosts adaptively
    local max_hosts=10
    if [[ "${FAST_MODE:-false}" == true ]]; then
        max_hosts=3
    elif [[ "${AGGRESSIVE_MODE:-false}" == true ]]; then
        max_hosts=25
    fi
    
    # Prioritize 2xx and content-bearing hosts first
    local prioritized_hosts="${output_dir}/ffuf_prioritized.txt"
    : > "$prioritized_hosts"
    
    [[ -f "${PROBE_DIR}/live_2xx.txt" ]] && cat "${PROBE_DIR}/live_2xx.txt" >> "$prioritized_hosts"
    [[ -f "${PROBE_DIR}/live_with_content.txt" ]] && cat "${PROBE_DIR}/live_with_content.txt" >> "$prioritized_hosts"
    cat "$input" >> "$prioritized_hosts"
    
    sort -u "$prioritized_hosts" | head -"$max_hosts" > "${output_dir}/ffuf_targets.txt"
    local selected_count=$(count_lines "${output_dir}/ffuf_targets.txt")
    log INFO "Selected $selected_count prioritized live host(s) for FFUF (max: $max_hosts)"
    
    while IFS= read -r url; do
        if type is_module_interrupted &>/dev/null && is_module_interrupted; then
            log WARN "FFUF interrupted - skipping remaining targets"
            break
        fi
        
        [[ -z "$url" ]] && continue
        
        # Sanitize URL for filename
        local safe_name=$(echo "$url" | sed 's/[^a-zA-Z0-9]/_/g' | cut -c1-50)
        local output_file="${output_dir}/${safe_name}.json"
        
        log INFO "Fuzzing: $url"
        
        local target_url="${url%/}"
        ffuf -u "${target_url}/FUZZ" \
            -w "$wordlist" \
            -t "$threads" \
            -rate "$rate" \
            -timeout 10 \
            -maxtime 300 \
            -ac \
            -mc 200,201,204,301,302,307,401,403,405 \
            -fc 404,400,429,503 \
            -fl 0 \
            -fs 0 \
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
    local log_file="${CONTENT_DIR}/feroxbuster.log"
    local wordlist=$(get_wordlist)
    local threads=$(get_threads)
    local rate=$(get_rate_limit)
    
    mkdir -p "$output_dir"
    : > "$log_file"
    
    # Validate wordlist
    if [[ -z "$wordlist" ]]; then
        log WARN "No wordlist found for Feroxbuster"
        echo "[ERROR] No wordlist found. Checked paths:" >> "$log_file"
        echo "  - /opt/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories.txt" >> "$log_file"
        echo "  - /opt/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt" >> "$log_file"
        echo "  - /opt/wordlists/SecLists/Discovery/Web-Content/common.txt" >> "$log_file"
        return
    fi
    
    if [[ ! -f "$wordlist" ]]; then
        log WARN "Wordlist file does not exist: $wordlist"
        echo "[ERROR] Wordlist not found: $wordlist" >> "$log_file"
        return
    fi
    
    log INFO "Using wordlist: $wordlist"
    echo "[INFO] Wordlist: $wordlist" >> "$log_file"
    
    if [[ ! -f "$input" ]]; then
        log WARN "No live hosts file found"
        echo "[ERROR] No live hosts file: $input" >> "$log_file"
        return
    fi
    
    local host_count=$(wc -l < "$input" 2>/dev/null || echo 0)
    log INFO "Feroxbuster scanning $host_count hosts (max 10)"
    
    local scanned=0
    local success=0
    
    # Only run on first 10 hosts due to recursion being heavy
    head -10 "$input" | while IFS= read -r url; do
        [[ -z "$url" ]] && continue
        
        ((scanned++))
        local safe_name=$(echo "$url" | sed 's/[^a-zA-Z0-9]/_/g' | cut -c1-50)
        local result_file="${output_dir}/${safe_name}.txt"
        
        log INFO "[$scanned/10] Feroxbuster: $url"
        echo "[$scanned] Scanning: $url" >> "$log_file"
        
        # Use proper status code filtering with error capture
        # Note: feroxbuster -s (status-codes) specifies which codes to REPORT
        # Cannot use both -s and -C together
        if timeout 300 feroxbuster \
            -u "$url" \
            -w "$wordlist" \
            -t "$threads" \
            --rate-limit "$rate" \
            -d 2 \
            -s 200,201,204,301,302,307,401,403,405 \
            --auto-tune \
            --silent \
            -o "$result_file" \
            2>&1 | tee -a "$log_file"; then
            ((success++))
            log INFO "Feroxbuster completed for: ${url:0:50}"
        else
            log WARN "Feroxbuster failed or timed out for: ${url:0:50}"
            echo "[WARN] Failed or timed out: $url" >> "$log_file"
        fi
    done
    
    # Merge and filter - only keep valid URLs
    local merged="${CONTENT_DIR}/feroxbuster_all.txt"
    if ls "${output_dir}"/*.txt 1>/dev/null 2>&1; then
        cat "${output_dir}"/*.txt 2>/dev/null | grep -E "^https?://" | sort -u > "$merged"
        local count=$(wc -l < "$merged" 2>/dev/null || echo 0)
        log INFO "Feroxbuster discovered $count unique URLs"
    else
        log WARN "No Feroxbuster results generated"
        echo "[WARN] No result files created" >> "$log_file"
    fi
    
    log INFO "Feroxbuster completed (log: $log_file)"
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
# IIS SHORTNAME SCANNER
# ============================================================================
run_shortscan() {
    # IIS shortname enumeration
    if [[ "$(config_should_run_tool content_discovery shortscan 2>/dev/null)" == "false" ]]; then
        log WARN "shortscan disabled in config, skipping..."
        return 0
    fi
    
    if ! command -v shortscan &>/dev/null; then
        log WARN "shortscan not available, skipping..."
        return 0
    fi
    
    # Only run on IIS targets
    local iis_targets="${FINGER_DIR}/iis_targets.txt"
    if [[ ! -f "$iis_targets" ]]; then
        # Try to find IIS targets from fingerprint
        grep -liE "iis|microsoft|asp\.net" "${FINGER_DIR}"/*.txt "${FINGER_DIR}"/*.json 2>/dev/null | head -1 > /dev/null || {
            log INFO "No IIS targets detected, skipping shortscan"
            return 0
        }
    fi
    
    log TASK "Running shortscan (IIS shortname enumeration)..."
    
    local input="${PROBE_DIR}/live_hosts.txt"
    local output="${CONTENT_DIR}/shortscan_results.txt"
    
    [[ ! -f "$input" ]] && return 0
    
    # Filter for IIS targets if fingerprint available
    if [[ -f "${FINGER_DIR}/consolidated.json" ]]; then
        grep -iE "iis|asp\.net|microsoft" "${FINGER_DIR}/consolidated.json" 2>/dev/null | \
            grep -oE '"url":\s*"[^"]+"' | sed 's/"url":\s*"//;s/"$//' > "${CONTENT_DIR}/iis_hosts.txt" || true
        
        if [[ -s "${CONTENT_DIR}/iis_hosts.txt" ]]; then
            input="${CONTENT_DIR}/iis_hosts.txt"
        fi
    fi
    
    head -20 "$input" | while read -r url; do
        shortscan -u "$url" 2>/dev/null | tee -a "$output" || true
    done
    
    local found=$(grep -c "8.3" "$output" 2>/dev/null || echo "0")
    if [[ $found -gt 0 ]]; then
        log WARN "⚠️  Found $found IIS shortname vulnerabilities!"
    else
        log INFO "No IIS shortname issues found"
    fi
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
    
    # Quick wins FIRST - fast path checking
    run_httpx_quick_paths
    
    # Run discovery tools
    run_ffuf
    detect_special_files
    run_katana
    run_hakrawler
    run_feroxbuster
    run_shortscan
    
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

