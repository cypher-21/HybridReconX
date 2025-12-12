#!/usr/bin/env bash
# ============================================================================
# MODULE 00: PRE-FLIGHT CHECKS
# ============================================================================
# Validates environment, connectivity, and updates before scan
# ============================================================================

set -euo pipefail

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log() {
    local level="$1"; shift
    case "$level" in
        INFO) echo -e "${GREEN}[PREFLIGHT]${NC} $*" ;;
        WARN) echo -e "${YELLOW}[PREFLIGHT]${NC} $*" ;;
        ERROR) echo -e "${RED}[PREFLIGHT]${NC} $*" ;;
    esac
}

# ============================================================================
# NETWORK CONNECTIVITY CHECK
# ============================================================================
check_network() {
    log INFO "Checking network connectivity..."
    
    local connected=false
    
    # Try curl first (works in Docker without ICMP)
    if curl -s --max-time 5 -o /dev/null https://www.google.com 2>/dev/null; then
        connected=true
    # Fallback to wget
    elif wget -q --spider --timeout=5 https://www.google.com 2>/dev/null; then
        connected=true
    # Fallback to DNS check
    elif nslookup google.com >/dev/null 2>&1; then
        connected=true
    # Last resort: ping (may not work in Docker)
    elif ping -c 1 -W 2 8.8.8.8 &>/dev/null; then
        connected=true
    fi
    
    if [[ "$connected" == true ]]; then
        log INFO "✓ Network connectivity OK"
    else
        log WARN "⚠ Network check failed - continuing anyway (may work)"
        # Don't exit, just warn - network might still work for tools
    fi
}

# ============================================================================
# DNS RESOLUTION CHECK
# ============================================================================
check_dns() {
    log INFO "Checking DNS resolution..."
    
    if nslookup google.com &>/dev/null || dig google.com +short &>/dev/null; then
        log INFO "✓ DNS resolution OK"
    else
        log WARN "⚠ DNS resolution issues detected"
    fi
}

# ============================================================================
# CONFIG VALIDATION
# ============================================================================
validate_config() {
    log INFO "Validating configuration..."
    
    if [[ -f "$CONFIG_FILE" ]]; then
        if yq '.' "$CONFIG_FILE" &>/dev/null; then
            log INFO "✓ Config file is valid YAML"
        else
            log ERROR "✗ Config file is invalid YAML"
            exit 1
        fi
        
        # Check for API keys
        local has_api_keys=false
        local subfinder_keys=$(yq -r '.api_keys.shodan // ""' "$CONFIG_FILE")
        if [[ -n "$subfinder_keys" ]]; then
            has_api_keys=true
        fi
        
        if [[ "$has_api_keys" == false ]]; then
            log WARN "⚠ No API keys configured - results may be limited"
        else
            log INFO "✓ API keys configured"
        fi
    else
        log WARN "⚠ Using default configuration"
    fi
}

# ============================================================================
# TOOL AVAILABILITY CHECK
# ============================================================================
check_tools() {
    log INFO "Checking tool availability..."
    
    local critical_tools=("httpx" "nuclei" "subfinder" "ffuf")
    local optional_tools=("amass" "whatweb" "wafw00f" "dalfox" "sqlmap" "wpscan")
    local missing_critical=()
    local missing_optional=()
    
    for tool in "${critical_tools[@]}"; do
        if ! command -v "$tool" &>/dev/null; then
            missing_critical+=("$tool")
        fi
    done
    
    for tool in "${optional_tools[@]}"; do
        if ! command -v "$tool" &>/dev/null; then
            missing_optional+=("$tool")
        fi
    done
    
    if [[ ${#missing_critical[@]} -gt 0 ]]; then
        log ERROR "✗ Missing critical tools: ${missing_critical[*]}"
        log ERROR "Please run inside Docker container"
        exit 1
    fi
    
    if [[ ${#missing_optional[@]} -gt 0 ]]; then
        log WARN "⚠ Some optional tools missing: ${missing_optional[*]}"
    fi
    
    log INFO "✓ All critical tools available"
}

# ============================================================================
# NUCLEI TEMPLATES UPDATE
# ============================================================================
update_nuclei_templates() {
    log INFO "Checking Nuclei templates..."
    
    if command -v nuclei &>/dev/null; then
        # Get template count before
        local template_dir="${HOME}/nuclei-templates"
        local template_count=0
        if [[ -d "$template_dir" ]]; then
            template_count=$(find "$template_dir" -name "*.yaml" 2>/dev/null | wc -l)
        fi
        
        if [[ "$template_count" -eq 0 ]] || [[ "${FORCE_UPDATE:-false}" == true ]]; then
            log INFO "Updating Nuclei templates..."
            nuclei -update-templates -silent 2>/dev/null || true
        else
            log INFO "✓ Nuclei templates present ($template_count templates)"
        fi
    fi
}

# ============================================================================
# WORDLIST CHECK
# ============================================================================
check_wordlists() {
    log INFO "Checking wordlists..."
    
    local required_wordlists=(
        "/opt/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories.txt"
        "/opt/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt"
    )
    
    local missing=0
    for wl in "${required_wordlists[@]}"; do
        if [[ ! -f "$wl" ]]; then
            ((missing++))
        fi
    done
    
    if [[ $missing -gt 0 ]]; then
        # Fallback to .data wordlists
        if [[ -f "${DATA_DIR}/wordlists/common.txt" ]]; then
            log WARN "⚠ Using minimal wordlists from .data/"
        else
            log WARN "⚠ Wordlists not found - fuzzing will be limited"
        fi
    else
        log INFO "✓ Wordlists available"
    fi
}

# ============================================================================
# RESOLVER CHECK
# ============================================================================
check_resolvers() {
    log INFO "Checking DNS resolvers..."
    
    local resolvers_found=false
    local resolver_paths=(
        "/opt/resolvers/trusted.txt"
        "${DATA_DIR}/resolvers.txt"
    )
    
    for rp in "${resolver_paths[@]}"; do
        if [[ -f "$rp" ]]; then
            local count=$(wc -l < "$rp")
            log INFO "✓ Found $count resolvers in $rp"
            resolvers_found=true
            break
        fi
    done
    
    if [[ "$resolvers_found" == false ]]; then
        log WARN "⚠ No resolver list found - DNS resolution may be slow"
    fi
}

# ============================================================================
# DISK SPACE CHECK
# ============================================================================
check_disk_space() {
    log INFO "Checking disk space..."
    
    local available_gb=$(df -BG "${OUTPUT_BASE:-/tmp}" 2>/dev/null | tail -1 | awk '{print $4}' | tr -d 'G')
    
    if [[ -n "$available_gb" ]] && [[ "$available_gb" -lt 5 ]]; then
        log WARN "⚠ Low disk space: ${available_gb}GB available"
    else
        log INFO "✓ Disk space OK (${available_gb:-unknown}GB available)"
    fi
}

# ============================================================================
# SCOPE VALIDATION
# ============================================================================
validate_scope() {
    log INFO "Validating target scope..."
    
    if [[ -n "${TARGET:-}" ]]; then
        # Check if it's a wildcard
        if [[ "$TARGET" == \** ]]; then
            log INFO "✓ Wildcard target detected: $TARGET"
        else
            # Validate domain format
            if [[ "$TARGET" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$ ]]; then
                log INFO "✓ Valid domain format: $TARGET"
            else
                log WARN "⚠ Unusual domain format: $TARGET"
            fi
        fi
    fi
    
    if [[ -n "${TARGET_LIST:-}" ]]; then
        local count=$(wc -l < "$TARGET_LIST")
        log INFO "✓ Target list contains $count domains"
    fi
}

# ============================================================================
# CREATE OUTPUT STRUCTURE
# ============================================================================
create_output_structure() {
    log INFO "Creating output directory structure..."
    
    local dirs=(
        "recon"
        "probed"
        "fingerprint"
        "content"
        "params"
        "vulns"
        "exploits"
        "cloud"
        "reports"
        "logs"
        "screenshots"
    )
    
    for dir in "${dirs[@]}"; do
        mkdir -p "${OUTPUT_BASE}/${dir}"
    done
    
    log INFO "✓ Output structure created"
}

# ============================================================================
# MAIN
# ============================================================================
main() {
    echo ""
    echo "════════════════════════════════════════════════════════════"
    echo "  PRE-FLIGHT CHECKS"
    echo "════════════════════════════════════════════════════════════"
    echo ""
    
    check_network
    check_dns
    validate_config
    check_tools
    update_nuclei_templates
    check_wordlists
    check_resolvers
    check_disk_space
    validate_scope
    create_output_structure
    
    echo ""
    echo "════════════════════════════════════════════════════════════"
    echo "  PRE-FLIGHT CHECKS COMPLETE ✓"
    echo "════════════════════════════════════════════════════════════"
    echo ""
}

main "$@"
