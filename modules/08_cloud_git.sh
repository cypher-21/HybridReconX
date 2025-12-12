#!/usr/bin/env bash
# ============================================================================
# MODULE 08: CLOUD & GIT ENUMERATION
# ============================================================================

set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; RED='\033[0;31m'; NC='\033[0m'
CONTENT_DIR="${OUTPUT_BASE}/content"
CLOUD_DIR="${OUTPUT_BASE}/cloud"
PROBE_DIR="${OUTPUT_BASE}/probed"

log() { local l="$1"; shift; case "$l" in INFO) echo -e "${GREEN}[CLOUD]${NC} $*";; WARN) echo -e "${YELLOW}[CLOUD]${NC} $*";; TASK) echo -e "${CYAN}[CLOUD]${NC} $*";; CRITICAL) echo -e "${RED}[!!! SECRET]${NC} $*";; esac; }
count_lines() { [[ -f "$1" ]] && wc -l < "$1" | tr -d ' ' || echo "0"; }

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
    local company=$(echo "$TARGET" | sed 's/\..*//')
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

main() {
    echo -e "\n${CYAN}═══ CLOUD & GIT MODULE ═══${NC}\n"
    mkdir -p "$CLOUD_DIR"
    run_git_dumper; run_gitleaks; scan_js_secrets; run_cloud_enum; check_exposed_env
    echo -e "\n${GREEN}Cloud module complete. Git dumps: $(find "${CLOUD_DIR}/git_dumps" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l)${NC}\n"
}
main "$@"
