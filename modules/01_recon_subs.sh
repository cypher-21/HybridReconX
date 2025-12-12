#!/usr/bin/env bash
# ============================================================================
# MODULE 01: SUBDOMAIN RECONNAISSANCE
# ============================================================================
# Hybrid passive + active subdomain enumeration with DNS resolution
# ============================================================================

set -euo pipefail

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

RECON_DIR="${OUTPUT_BASE}/recon"

log() {
    local level="$1"; shift
    case "$level" in
        INFO) echo -e "${GREEN}[RECON]${NC} $*" ;;
        WARN) echo -e "${YELLOW}[RECON]${NC} $*" ;;
        TASK) echo -e "${CYAN}[RECON]${NC} $*" ;;
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

# ============================================================================
# PASSIVE ENUMERATION
# ============================================================================
run_subfinder() {
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
    if ! command -v findomain &>/dev/null; then
        log WARN "Findomain not available, skipping..."
        return
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
    if [[ "${FAST_MODE:-false}" == true ]]; then
        log WARN "Skipping Amass in fast mode"
        return
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
# MERGE & DEDUPE
# ============================================================================
merge_subdomains() {
    log TASK "Merging and deduplicating subdomains..."
    
    local merged="${RECON_DIR}/all_subdomains_raw.txt"
    
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
    
    # Extract unique root domains
    cat "$clean" | rev | cut -d. -f1,2 | rev | sort -u > "$roots"
    
    log INFO "Found $(count_lines "$roots") unique root domains"
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
    
    # Run passive enumeration tools in sequence
    run_subfinder
    run_assetfinder
    run_findomain
    run_amass
    
    # Process results
    merge_subdomains
    resolve_dns
    detect_wildcards
    extract_root_domains
    
    echo ""
    echo "════════════════════════════════════════════════════════════"
    echo "  RECONNAISSANCE COMPLETE"
    echo "  Total live subdomains: $(count_lines "${RECON_DIR}/clean_subdomains.txt")"
    echo "════════════════════════════════════════════════════════════"
    echo ""
}

main "$@"
