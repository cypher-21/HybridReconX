#!/usr/bin/env bash
# ============================================================================
# MODULE 01: SUBDOMAIN RECONNAISSANCE
# ============================================================================
# Hybrid passive + active subdomain enumeration with DNS resolution
# ============================================================================

# Don't exit on errors - tools may fail without meaning module failure
set -uo pipefail

# ============================================================================
# LIBRARY SOURCING
# ============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source interrupt handling
[[ -f "${SCRIPT_DIR}/../lib/interrupt.sh" ]] && source "${SCRIPT_DIR}/../lib/interrupt.sh" && install_module_handler

# Source config library
[[ -f "${SCRIPT_DIR}/../lib/config.sh" ]] && source "${SCRIPT_DIR}/../lib/config.sh"

# Source logging library (centralized log(), count_lines(), get_threads(), get_rate_limit())
[[ -f "${SCRIPT_DIR}/../lib/logging.sh" ]] && source "${SCRIPT_DIR}/../lib/logging.sh"
set_log_module "RECON"

RECON_DIR="${OUTPUT_BASE}/recon"

# ============================================================================
# PASSIVE ENUMERATION
# ============================================================================
run_subfinder() {
    # Check if subfinder is enabled in config
    if [[ "$(config_should_run_tool recon subfinder 2>/dev/null)" == "false" ]]; then
        log WARN "Subfinder disabled in config, skipping..."
        return 0
    fi
    
    log TASK "Running Subfinder (passive)..."
    
    local threads=$(get_threads)
    local output="${RECON_DIR}/subfinder.txt"
    
    if [[ -n "${TARGET:-}" ]]; then
        subfinder -d "$TARGET" -all -silent -t "$threads" -o "$output" 2>/dev/null || true
    elif [[ -n "${TARGET_LIST:-}" ]]; then
        subfinder -dL "$TARGET_LIST" -all -silent -t "$threads" -o "$output" 2>/dev/null || true
    fi
    
    log INFO "Subfinder found $(count_lines "$output") subdomains"
}

run_assetfinder() {
    # Check if assetfinder is enabled in config
    if [[ "$(config_should_run_tool recon assetfinder 2>/dev/null)" == "false" ]]; then
        log WARN "Assetfinder disabled in config, skipping..."
        return 0
    fi
    
    log TASK "Running Assetfinder (passive)..."
    
    local output="${RECON_DIR}/assetfinder.txt"
    
    if [[ -n "${TARGET:-}" ]]; then
        assetfinder --subs-only "$TARGET" 2>/dev/null > "$output" || true
    elif [[ -n "${TARGET_LIST:-}" ]]; then
        while IFS= read -r domain; do
            assetfinder --subs-only "$domain" 2>/dev/null >> "$output" || true
        done < "$TARGET_LIST"
    fi
    
    log INFO "Assetfinder found $(count_lines "$output") subdomains"
}

run_findomain() {
    # Check if findomain is enabled in config
    if [[ "$(config_should_run_tool recon findomain 2>/dev/null)" == "false" ]]; then
        log WARN "Findomain disabled in config, skipping..."
        return 0
    fi
    
    if ! command -v findomain &>/dev/null; then
        log WARN "Findomain not available, skipping..."
        return 0
    fi
    
    log TASK "Running Findomain (passive)..."
    
    local output="${RECON_DIR}/findomain.txt"
    
    if [[ -n "${TARGET:-}" ]]; then
        findomain -t "$TARGET" -q 2>/dev/null | tee "$output" || true
    elif [[ -n "${TARGET_LIST:-}" ]]; then
        findomain -f "$TARGET_LIST" -q 2>/dev/null | tee "$output" || true
    fi
    
    log INFO "Findomain found $(count_lines "$output") subdomains"
}

run_amass() {
    # Check if amass is enabled in config
    if [[ "$(config_should_run_tool recon amass 2>/dev/null)" == "false" ]]; then
        log WARN "Amass disabled in config, skipping..."
        return 0
    fi
    
    if [[ "${FAST_MODE:-false}" == true ]]; then
        log WARN "Skipping Amass in fast mode"
        return 0
    fi
    
    log TASK "Running Amass (deep enumeration)..."
    log INFO "This may take a while..."
    
    local output="${RECON_DIR}/amass.txt"
    local timeout="${AMASS_TIMEOUT:-15m}"
    
    if [[ -n "${TARGET:-}" ]]; then
        timeout "$timeout" amass enum -passive -d "$TARGET" -o "$output" 2>/dev/null || {
            log WARN "Amass timed out or failed"
        }
    elif [[ -n "${TARGET_LIST:-}" ]]; then
        timeout "$timeout" amass enum -passive -df "$TARGET_LIST" -o "$output" 2>/dev/null || {
            log WARN "Amass timed out or failed"
        }
    fi
    
    log INFO "Amass found $(count_lines "$output") subdomains"
}

# ============================================================================
# MERGE & DEDUPE (with ANEW for incremental scanning)
# ============================================================================
merge_subdomains() {
    log TASK "Merging and deduplicating subdomains..."
    
    local merged="${RECON_DIR}/all_subdomains_raw.txt"
    local history="${RECON_DIR}/.subdomain_history.txt"
    local new_subs="${RECON_DIR}/new_subdomains.txt"
    
    # Merge all sources
    cat "${RECON_DIR}"/*.txt 2>/dev/null | \
        grep -v "^$" | \
        tr '[:upper:]' '[:lower:]' | \
        sort -u > "$merged"
    
    # Filter out-of-scope if exclusion pattern provided
    if [[ -n "${EXCLUDE_PATTERN:-}" ]]; then
        grep -vE "$EXCLUDE_PATTERN" "$merged" > "${merged}.filtered"
        mv "${merged}.filtered" "$merged"
    fi
    
    local total=$(count_lines "$merged")
    
    # Use ANEW for incremental scanning (only new subdomains)
    if command -v anew &>/dev/null; then
        # Create history file if it doesn't exist
        touch "$history"
        
        # Find only NEW subdomains
        cat "$merged" | anew "$history" > "$new_subs" 2>/dev/null || cp "$merged" "$new_subs"
        
        local new_count=$(count_lines "$new_subs")
        if [[ "$new_count" -gt 0 ]]; then
            log INFO "Total subdomains: $total, NEW subdomains: $new_count"
            log SUCCESS "🆕 $new_count new subdomains found since last scan!"
        else
            log INFO "No new subdomains found (all $total already seen)"
        fi
    else
        log WARN "ANEW not found - install with: go install github.com/tomnomnom/anew@latest"
        # Fall back to using all subdomains
        cp "$merged" "$new_subs" 2>/dev/null || true
    fi
    
    log INFO "Merged result: $(count_lines "$merged") unique subdomains"
}

# ============================================================================
# DNS RESOLUTION
# ============================================================================
resolve_dns() {
    log TASK "Resolving DNS records..."
    
    local input="${RECON_DIR}/all_subdomains_raw.txt"
    local output="${RECON_DIR}/resolved.txt"
    local clean_output="${RECON_DIR}/clean_subdomains.txt"
    local threads=$(get_threads)
    
    # Find resolvers file
    local resolvers=""
    if [[ -f "/opt/resolvers/trusted.txt" ]]; then
        resolvers="/opt/resolvers/trusted.txt"
    elif [[ -f "${DATA_DIR}/resolvers.txt" ]]; then
        resolvers="${DATA_DIR}/resolvers.txt"
    fi
    
    if command -v puredns &>/dev/null && [[ -n "$resolvers" ]]; then
        log INFO "Using PureDNS for resolution..."
        puredns resolve "$input" \
            -r "$resolvers" \
            -w "$output" \
            --wildcard-tests 3 \
            -t "$threads" \
            --rate-limit 500 \
            2>/dev/null || true
    elif command -v dnsx &>/dev/null; then
        log INFO "Using DNSx for resolution..."
        dnsx -l "$input" \
            -t "$threads" \
            -silent \
            -retry 2 \
            -o "$output" \
            2>/dev/null || true
    elif command -v shuffledns &>/dev/null && [[ -n "$resolvers" ]]; then
        log INFO "Using Shuffledns for resolution..."
        if command -v massdns &>/dev/null; then
            shuffledns -d "$TARGET" \
                -list "$input" \
                -r "$resolvers" \
                -o "$output" \
                -silent \
                2>/dev/null || true
        fi
    else
        log WARN "No DNS resolver tool available, using raw list"
        cp "$input" "$output"
    fi
    
    # Create clean output
    if [[ -f "$output" ]]; then
        sort -u "$output" > "$clean_output"
    else
        sort -u "$input" > "$clean_output"
    fi
    
    log INFO "Resolved $(count_lines "$clean_output") live subdomains"
}

# ============================================================================
# WILDCARD DETECTION
# ============================================================================
detect_wildcards() {
    log TASK "Detecting wildcard DNS..."
    
    local clean="${RECON_DIR}/clean_subdomains.txt"
    local wildcards="${RECON_DIR}/wildcards.txt"
    
    if command -v dnsx &>/dev/null; then
        dnsx -l "$clean" \
            -wd "${TARGET:-$(head -1 "$TARGET_LIST")}" \
            -silent \
            2>/dev/null | sort -u > "$wildcards" || true
            
        local wc_count=$(count_lines "$wildcards")
        if [[ $wc_count -gt 0 ]]; then
            log WARN "Detected $wc_count wildcard entries"
        fi
    fi
}

# ============================================================================
# EXTRACT ROOT DOMAINS (for scope)
# ============================================================================
extract_root_domains() {
    log TASK "Extracting root domains..."
    
    local clean="${RECON_DIR}/clean_subdomains.txt"
    local roots="${RECON_DIR}/root_domains.txt"
    
    # Extract unique root domains using tldextract (Public Suffix List compliant)
    # Correctly handles multi-part TLDs (e.g. .co.uk, .com.au, .gov.in)
    if python3 -c "import tldextract" 2>/dev/null; then
        python3 -c "
import sys, tldextract
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    ext = tldextract.extract(line)
    if ext.domain and ext.suffix:
        print(f'{ext.domain}.{ext.suffix}')
    elif line:
        print(line)
" < "$clean" 2>/dev/null | sort -u > "$roots" || true
    else
        # Fallback if tldextract not available
        awk -F. '{if (NF>=2) print $(NF-1)"."$NF; else print $0}' "$clean" 2>/dev/null | sort -u > "$roots" || true
    fi
    
    log INFO "Found $(count_lines "$roots") unique root domains"
}

# ============================================================================
# ENHANCED RECON TOOLS
# ============================================================================

run_tlsx() {
    # TLS certificate-based subdomain discovery
    if [[ "$(config_should_run_tool recon tlsx 2>/dev/null)" == "false" ]]; then
        log WARN "tlsx disabled in config, skipping..."
        return 0
    fi
    
    if ! command -v tlsx &>/dev/null; then
        log WARN "tlsx not available, skipping..."
        return 0
    fi
    
    log TASK "Running tlsx (TLS subdomain discovery)..."
    
    local input="${RECON_DIR}/clean_subdomains.txt"
    local output="${RECON_DIR}/tlsx_subs.txt"
    
    [[ ! -f "$input" ]] && return 0
    
    # Extract subdomains from TLS certificates
    cat "$input" | tlsx -san -cn -silent 2>/dev/null | sort -u > "$output" || true
    
    log INFO "tlsx found $(count_lines "$output") additional subdomains from TLS certs"
}

run_gotator() {
    # Subdomain permutation
    if [[ "$(config_should_run_tool recon gotator 2>/dev/null)" == "false" ]]; then
        log WARN "gotator disabled in config, skipping..."
        return 0
    fi
    
    if [[ "${FAST_MODE:-false}" == true ]]; then
        log WARN "Skipping gotator in fast mode"
        return 0
    fi
    
    if ! command -v gotator &>/dev/null; then
        log WARN "gotator not available, skipping..."
        return 0
    fi
    
    log TASK "Running gotator (subdomain permutation)..."
    
    local input="${RECON_DIR}/clean_subdomains.txt"
    local output="${RECON_DIR}/gotator_permutations.txt"
    local wordlist="/opt/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt"
    
    [[ ! -f "$input" ]] && return 0
    [[ ! -f "$wordlist" ]] && wordlist=""
    
    if [[ -n "$wordlist" ]]; then
        gotator -sub "$input" -perm "$wordlist" -depth 1 -numbers 3 -md 2>/dev/null | head -10000 > "$output" || true
    else
        gotator -sub "$input" -depth 1 -numbers 3 -md 2>/dev/null | head -10000 > "$output" || true
    fi
    
    log INFO "gotator generated $(count_lines "$output") permutations"
}

run_dnstake() {
    # Subdomain takeover detection
    if [[ "$(config_should_run_tool recon dnstake 2>/dev/null)" == "false" ]]; then
        log WARN "dnstake disabled in config, skipping..."
        return 0
    fi
    
    if ! command -v dnstake &>/dev/null; then
        log WARN "dnstake not available, skipping..."
        return 0
    fi
    
    log TASK "Running dnstake (subdomain takeover detection)..."
    
    local input="${RECON_DIR}/clean_subdomains.txt"
    local output="${RECON_DIR}/takeover_vulnerable.txt"
    
    [[ ! -f "$input" ]] && return 0
    
    dnstake -l "$input" -o "$output" -silent 2>/dev/null || true
    
    local count=$(count_lines "$output")
    if [[ $count -gt 0 ]]; then
        log WARN "⚠️  FOUND $count potential subdomain takeovers!"
    else
        log INFO "No subdomain takeovers detected"
    fi
}

# ============================================================================
# NMAP PORT SCANNING
# ============================================================================
run_nmap() {
    # Port scanning on resolved hosts
    if [[ "$(config_should_run_tool recon nmap 2>/dev/null)" == "false" ]]; then
        log WARN "nmap disabled in config, skipping..."
        return 0
    fi
    
    if ! command -v nmap &>/dev/null; then
        log WARN "nmap not available, skipping..."
        return 0
    fi
    
    log TASK "Running nmap (port scanning)..."
    
    local input="${RECON_DIR}/clean_subdomains.txt"
    local output="${RECON_DIR}/nmap_results.txt"
    local ports_output="${RECON_DIR}/open_ports.txt"
    
    [[ ! -f "$input" ]] && { log WARN "No subdomains for nmap"; return 0; }
    
    # Extract IPs/hosts - limit to prevent excessive scanning
    local max_hosts=50
    local hosts_file="${RECON_DIR}/nmap_targets.txt"
    head -n "$max_hosts" "$input" > "$hosts_file"
    
    local host_count=$(wc -l < "$hosts_file")
    log INFO "Scanning $host_count hosts (max $max_hosts)"
    
    # Port selection based on mode
    local ports="--top-ports 100"
    if [[ "${FAST_MODE:-false}" == true ]]; then
        ports="--top-ports 20"
        log INFO "Fast mode: scanning top 20 ports"
    elif [[ "${AGGRESSIVE_MODE:-false}" == true ]]; then
        ports="--top-ports 1000"
        log INFO "Aggressive mode: scanning top 1000 ports"
    else
        log INFO "Default mode: scanning top 100 ports"
    fi
    
    # Rate limiting for stealth
    local rate=""
    if [[ "${STEALTH_MODE:-false}" == true ]]; then
        rate="-T2"
        log INFO "Stealth mode: using timing template T2"
    else
        rate="-T4"
    fi
    
    # Run nmap
    nmap -iL "$hosts_file" $ports $rate -oN "$output" --open -Pn 2>/dev/null || {
        log WARN "nmap scan completed with warnings"
    }
    
    # Extract open ports
    grep -E "^[0-9]+/(tcp|udp)" "$output" 2>/dev/null | sort -u > "$ports_output" || true
    
    # Parse for high-value ports
    local http_count=$(grep -cE "80/|443/|8080/|8443/" "$output" 2>/dev/null || echo "0")
    local ssh_count=$(grep -c "22/" "$output" 2>/dev/null || echo "0")
    local db_count=$(grep -cE "3306/|5432/|1433/|27017/" "$output" 2>/dev/null || echo "0")
    
    log INFO "Port scan complete:"
    log INFO "  HTTP/HTTPS ports: $http_count"
    log INFO "  SSH ports: $ssh_count"
    log INFO "  Database ports: $db_count"
    
    # Alert on critical findings
    if [[ $db_count -gt 0 ]]; then
        log WARN "⚠️  Database ports exposed! Check $output"
    fi
}

# ============================================================================
# MAIN
# ============================================================================
main() {
    echo ""
    echo "════════════════════════════════════════════════════════════"
    echo "  SUBDOMAIN RECONNAISSANCE"
    echo "════════════════════════════════════════════════════════════"
    echo ""
    
    mkdir -p "$RECON_DIR"
    
    # Run passive enumeration tools
    run_subfinder
    run_assetfinder
    run_findomain
    run_amass
    
    # Process and merge results
    merge_subdomains
    
    # Enhanced discovery
    run_tlsx
    run_gotator
    
    # DNS resolution and filtering
    resolve_dns
    detect_wildcards
    
    # Takeover detection
    run_dnstake
    
    # Extract root domains
    extract_root_domains
    
    # Port scanning
    run_nmap
    
    echo ""
    echo "════════════════════════════════════════════════════════════"
    echo "  RECONNAISSANCE COMPLETE"
    echo "  Total live subdomains: $(count_lines "${RECON_DIR}/clean_subdomains.txt")"
    echo "════════════════════════════════════════════════════════════"
    echo ""
}

main "$@"


