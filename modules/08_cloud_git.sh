#!/usr/bin/env bash
# ============================================================================
# MODULE 08: CLOUD & GIT ENUMERATION
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
set_log_module "CLOUD"

CONTENT_DIR="${OUTPUT_BASE}/content"
CLOUD_DIR="${OUTPUT_BASE}/cloud"
PROBE_DIR="${OUTPUT_BASE}/probed"

get_target_company() {
    local target="${1:-${TARGET:-}}"
    [[ -z "$target" ]] && echo "unknown" && return
    
    local domain=""
    if python3 -c "import tldextract" 2>/dev/null; then
        domain=$(python3 -c "import tldextract; ext = tldextract.extract('$target'); print(ext.domain if ext.domain else '$target')" 2>/dev/null)
    fi
    if [[ -n "$domain" ]]; then
        echo "$domain"
    else
        echo "$target" | sed 's/\..*//'
    fi
}

run_git_dumper() {
    log TASK "Running Git repository dumping..."
    local input="${CONTENT_DIR}/git_exposed.txt"; local output_dir="${CLOUD_DIR}/git_dumps"
    mkdir -p "$output_dir"
    [[ ! -f "$input" ]] && { log WARN "No exposed .git found"; return; }
    while IFS= read -r url; do
        local base_url=$(echo "$url" | sed 's/\.git.*//;s/\/$//')
        local safe_name=$(echo "$base_url" | md5sum | cut -c1-10)
        git-dumper "${base_url}/.git/" "${output_dir}/${safe_name}" 2>/dev/null && log CRITICAL "Dumped: $base_url" || true
    done < "$input"
}

run_gitleaks() {
    command -v gitleaks &>/dev/null || return
    log TASK "Running Gitleaks..."
    find "${CLOUD_DIR}/git_dumps" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | while read -r repo; do
        gitleaks detect --source="$repo" --report-format=json --report-path="${CLOUD_DIR}/gitleaks_$(basename "$repo").json" --no-git 2>/dev/null || true
    done
}

scan_js_secrets() {
    log TASK "Scanning JS files for secrets..."
    local js_files="${PROBE_DIR}/js_files.txt"; local output="${CLOUD_DIR}/js_secrets.txt"
    [[ ! -f "$js_files" ]] && return
    local patterns="api[_-]?key|api[_-]?secret|access[_-]?token|AKIA[A-Z0-9]{16}|ghp_[a-zA-Z0-9]{36}"
    head -50 "$js_files" | while read -r url; do
        local content=$(curl -s -k -L --max-time 10 "$url" 2>/dev/null)
        echo "$content" | grep -oiE "${patterns}['\"]?\s*[:=]\s*['\"][^'\"]{8,}" | head -3 && { echo "=== $url ===" >> "$output"; log CRITICAL "Secret in: $url"; }
    done
}

run_cloud_enum() {
    log TASK "Enumerating cloud buckets..."
    mkdir -p "${CLOUD_DIR}/buckets"
    [[ -n "${TARGET:-}" ]] || return
    local company=$(get_target_company "$TARGET")
    [[ -d "/opt/tools/cloud_enum" ]] && python3 /opt/tools/cloud_enum/cloud_enum.py -k "$company" -l "${CLOUD_DIR}/buckets/results.txt" -t 10 2>/dev/null || true
    grep -hiE "s3\.amazonaws\.com" "${CONTENT_DIR}"/*.txt "${PROBE_DIR}"/*.txt 2>/dev/null | sort -u > "${CLOUD_DIR}/s3_buckets.txt" || true
}

check_exposed_env() {
    log TASK "Checking exposed .env files..."
    local input="${CONTENT_DIR}/env_exposed.txt"
    [[ ! -f "$input" ]] && return
    log CRITICAL "Found $(count_lines "$input") exposed .env files!"
    while read -r url; do curl -s -k "$url" >> "${CLOUD_DIR}/env_contents.txt" 2>/dev/null; done < "$input"
}

run_s3scanner() {
    # S3 bucket enumeration
    if [[ "$(config_should_run_tool cloud s3scanner 2>/dev/null)" == "false" ]]; then
        log WARN "s3scanner disabled in config, skipping..."
        return 0
    fi
    
    if ! command -v s3scanner &>/dev/null; then
        log WARN "s3scanner not available, skipping..."
        return 0
    fi
    
    log TASK "Running s3scanner (S3 bucket enumeration)..."
    
    local output="${CLOUD_DIR}/s3scanner_results.txt"
    local company=$(get_target_company "${TARGET:-unknown}")
    
    # Create wordlist from target name variations
    local wordlist="${CLOUD_DIR}/s3_wordlist.txt"
    echo -e "${company}\n${company}-prod\n${company}-dev\n${company}-staging\n${company}-backup\n${company}-data\n${company}-assets\n${company}-static" > "$wordlist"
    
    s3scanner -bucket-file "$wordlist" -enumerate 2>/dev/null > "$output" || true
    
    local found=$(grep -c "exists" "$output" 2>/dev/null || echo "0")
    if [[ $found -gt 0 ]]; then
        log CRITICAL "⚠️  Found $found accessible S3 buckets!"
    else
        log INFO "No accessible S3 buckets found"
    fi
}

run_trufflehog() {
    # Deep secret scanning with TruffleHog
    if [[ "$(config_should_run_tool cloud trufflehog 2>/dev/null)" == "false" ]]; then
        log WARN "trufflehog disabled in config, skipping..."
        return 0
    fi
    
    if [[ "${FAST_MODE:-false}" == true ]]; then
        log WARN "Skipping trufflehog in fast mode"
        return 0
    fi
    
    if ! command -v trufflehog &>/dev/null; then
        log WARN "trufflehog not available, skipping..."
        return 0
    fi
    
    log TASK "Running TruffleHog (deep secret scanning)..."
    
    local output="${CLOUD_DIR}/trufflehog_results.json"
    local git_dumps="${CLOUD_DIR}/git_dumps"
    
    # Scan dumped git repos
    if [[ -d "$git_dumps" ]] && [[ $(find "$git_dumps" -mindepth 1 -maxdepth 1 -type d | wc -l) -gt 0 ]]; then
        find "$git_dumps" -mindepth 1 -maxdepth 1 -type d | while read -r repo; do
            trufflehog filesystem "$repo" --json 2>/dev/null >> "$output" || true
        done
    fi
    
    # Also scan JS files if available
    local js_dir="${OUTPUT_BASE}/intel/js_files"
    if [[ -d "$js_dir" ]]; then
        trufflehog filesystem "$js_dir" --json 2>/dev/null >> "$output" || true
    fi
    
    local count=$(grep -c '"Raw":' "$output" 2>/dev/null || echo "0")
    if [[ $count -gt 0 ]]; then
        log CRITICAL "⚠️  TruffleHog found $count potential secrets!"
    else
        log INFO "TruffleHog scan complete - no secrets found"
    fi
}

main() {
    echo -e "\n${CYAN}═══ CLOUD & GIT MODULE ═══${NC}\n"
    mkdir -p "$CLOUD_DIR"
    
    # Git repository attacks
    run_git_dumper
    run_gitleaks
    run_trufflehog
    
    # Secret scanning
    scan_js_secrets
    check_exposed_env
    
    # Cloud enumeration
    run_cloud_enum
    run_s3scanner
    
    echo -e "\n${GREEN}Cloud module complete. Git dumps: $(find "${CLOUD_DIR}/git_dumps" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l)${NC}\n"
}
main "$@"

