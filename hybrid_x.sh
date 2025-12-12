#!/usr/bin/env bash
# ============================================================================
# HYBRIDRECON X - MAIN ORCHESTRATOR
# ============================================================================
# Context-Aware Bug Bounty & Pentesting Framework
# The Smart Recon Platform that thinks before it attacks
# ============================================================================

set -euo pipefail

# ============================================================================
# GLOBAL VARIABLES
# ============================================================================
VERSION="1.0.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/config.yaml"
MODULES_DIR="${SCRIPT_DIR}/modules"
DATA_DIR="${SCRIPT_DIR}/.data"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
OUTPUT_BASE=""
LOG_FILE=""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Default values
TARGET=""
TARGET_LIST=""
SCOPE_FILE=""
EXCLUDE_PATTERN=""
FAST_MODE=false
AGGRESSIVE_MODE=false
STEALTH_MODE=false
SKIP_RECON=false
SKIP_CONTENT=false
SKIP_VULN=false
ONLY_RECON=false
ONLY_FINGERPRINT=false
RESUME=false
DRY_RUN=false
NOTIFY_ON_FINDINGS=true
THREADS=""
RATE_LIMIT=""

# ============================================================================
# BANNER
# ============================================================================
show_banner() {
    echo -e "${CYAN}"
    cat << 'EOF'

    ██╗  ██╗██╗   ██╗██████╗ ██████╗ ██╗██████╗ ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
    ██║  ██║╚██╗ ██╔╝██╔══██╗██╔══██╗██║██╔══██╗██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
    ███████║ ╚████╔╝ ██████╔╝██████╔╝██║██║  ██║██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
    ██╔══██║  ╚██╔╝  ██╔══██╗██╔══██╗██║██║  ██║██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
    ██║  ██║   ██║   ██████╔╝██║  ██║██║██████╔╝██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
    ╚═╝  ╚═╝   ╚═╝   ╚═════╝ ╚═╝  ╚═╝╚═╝╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
                                                                                            
                               ██╗  ██╗                                                     
                               ╚██╗██╔╝                                                     
                                ╚███╔╝                                                      
                                ██╔██╗                                                      
                               ██╔╝ ██╗                                                     
                               ╚═╝  ╚═╝                                                     
                                                                                            
EOF
    echo -e "${NC}"
    echo -e "${WHITE}${BOLD}    ═══════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}${BOLD}                    Context-Aware Bug Bounty Framework${NC}"
    echo -e "${WHITE}                           Version: ${VERSION}${NC}"
    echo -e "${WHITE}${BOLD}    ═══════════════════════════════════════════════════════════════════════${NC}"
    echo ""
}

# ============================================================================
# LOGGING FUNCTIONS
# ============================================================================
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case "$level" in
        INFO)
            echo -e "${GREEN}[*]${NC} ${message}"
            ;;
        WARN)
            echo -e "${YELLOW}[!]${NC} ${message}"
            ;;
        ERROR)
            echo -e "${RED}[✗]${NC} ${message}"
            ;;
        SUCCESS)
            echo -e "${GREEN}[✓]${NC} ${message}"
            ;;
        DEBUG)
            [[ "${DEBUG:-false}" == "true" ]] && echo -e "${PURPLE}[D]${NC} ${message}"
            ;;
        TASK)
            echo -e "${CYAN}[»]${NC} ${BOLD}${message}${NC}"
            ;;
        CRITICAL)
            echo -e "${RED}${BOLD}[!!!]${NC} ${RED}${message}${NC}"
            ;;
    esac
    
    # Write to log file if set
    if [[ -n "${LOG_FILE:-}" ]]; then
        echo "[${timestamp}] [${level}] ${message}" >> "$LOG_FILE"
    fi
}

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================
check_dependencies() {
    local deps=("yq" "jq" "python3" "httpx" "nuclei")
    local missing=()
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing+=("$dep")
        fi
    done
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        log ERROR "Missing dependencies: ${missing[*]}"
        log INFO "Run inside Docker container or install missing tools"
        exit 1
    fi
}

setup_output_directory() {
    local target_name="$1"
    # Sanitize target name for directory
    target_name=$(echo "$target_name" | sed 's/[^a-zA-Z0-9._-]/_/g')
    
    OUTPUT_BASE="${SCRIPT_DIR}/output/${target_name}/${TIMESTAMP}"
    mkdir -p "${OUTPUT_BASE}"/{recon,probed,fingerprint,content,params,vulns,exploits,cloud,reports,logs}
    
    LOG_FILE="${OUTPUT_BASE}/logs/hybridrecon.log"
    
    log INFO "Output directory: ${OUTPUT_BASE}"
}

read_config() {
    local key="$1"
    local default="${2:-}"
    
    if [[ -f "$CONFIG_FILE" ]]; then
        local value
        value=$(yq -r "$key // \"$default\"" "$CONFIG_FILE" 2>/dev/null)
        echo "${value:-$default}"
    else
        echo "$default"
    fi
}

count_lines() {
    local file="$1"
    if [[ -f "$file" ]]; then
        wc -l < "$file" | tr -d ' '
    else
        echo "0"
    fi
}

elapsed_time() {
    local start="$1"
    local end=$(date +%s)
    local elapsed=$((end - start))
    local hours=$((elapsed / 3600))
    local minutes=$(( (elapsed % 3600) / 60 ))
    local seconds=$((elapsed % 60))
    printf "%02d:%02d:%02d" $hours $minutes $seconds
}

send_notification() {
    local message="$1"
    local severity="${2:-info}"
    
    if [[ "$NOTIFY_ON_FINDINGS" == true ]] && command -v notify &> /dev/null; then
        echo "$message" | notify -silent 2>/dev/null || true
    fi
}

# ============================================================================
# USAGE / HELP
# ============================================================================
show_usage() {
    cat << EOF
${BOLD}USAGE:${NC}
    ./hybrid_x.sh [OPTIONS] -d <domain>
    ./hybrid_x.sh [OPTIONS] -l <domain_list>

${BOLD}TARGET OPTIONS:${NC}
    -d, --domain <domain>       Single target domain (e.g., example.com)
    -l, --list <file>           File containing list of domains
    -s, --scope <file>          File containing in-scope patterns
    --exclude <pattern>         Exclude pattern (regex)

${BOLD}MODE OPTIONS:${NC}
    -f, --fast                  Fast mode: Skip slow tools (amass, feroxbuster)
    -a, --aggressive            Aggressive mode: Higher threads, deeper scans
    --stealth                   Stealth mode: Low rate, bypass WAF detection
    --dry-run                   Show what would be executed without running

${BOLD}SKIP OPTIONS:${NC}
    --skip-recon                Skip subdomain enumeration
    --skip-content              Skip content discovery
    --skip-vuln                 Skip vulnerability scanning
    --only-recon                Only run reconnaissance modules
    --only-fingerprint          Only run fingerprinting (requires prior recon)

${BOLD}PERFORMANCE OPTIONS:${NC}
    -t, --threads <n>           Override thread count
    -r, --rate-limit <n>        Override rate limit (requests/second)
    --resume                    Resume from previous scan

${BOLD}OUTPUT OPTIONS:${NC}
    -o, --output <dir>          Custom output directory
    --no-notify                 Disable notifications
    -c, --config <file>         Use custom config file

${BOLD}GENERAL OPTIONS:${NC}
    -h, --help                  Show this help message
    -v, --version               Show version
    --update                    Update Nuclei templates

${BOLD}EXAMPLES:${NC}
    # Full scan on single domain
    ./hybrid_x.sh -d hackerone.com

    # Fast scan on multiple domains
    ./hybrid_x.sh -l targets.txt --fast

    # Stealth scan with custom config
    ./hybrid_x.sh -d target.com --stealth -c custom_config.yaml

    # Resume previous scan
    ./hybrid_x.sh -d target.com --resume

    # Dry run to see what would happen
    ./hybrid_x.sh -d target.com --dry-run

EOF
}

# ============================================================================
# ARGUMENT PARSING
# ============================================================================
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -d|--domain)
                TARGET="$2"
                shift 2
                ;;
            -l|--list)
                TARGET_LIST="$2"
                shift 2
                ;;
            -s|--scope)
                SCOPE_FILE="$2"
                shift 2
                ;;
            --exclude)
                EXCLUDE_PATTERN="$2"
                shift 2
                ;;
            -f|--fast)
                FAST_MODE=true
                shift
                ;;
            -a|--aggressive)
                AGGRESSIVE_MODE=true
                shift
                ;;
            --stealth)
                STEALTH_MODE=true
                shift
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --skip-recon)
                SKIP_RECON=true
                shift
                ;;
            --skip-content)
                SKIP_CONTENT=true
                shift
                ;;
            --skip-vuln)
                SKIP_VULN=true
                shift
                ;;
            --only-recon)
                ONLY_RECON=true
                shift
                ;;
            --only-fingerprint)
                ONLY_FINGERPRINT=true
                shift
                ;;
            -t|--threads)
                THREADS="$2"
                shift 2
                ;;
            -r|--rate-limit)
                RATE_LIMIT="$2"
                shift 2
                ;;
            --resume)
                RESUME=true
                shift
                ;;
            -o|--output)
                OUTPUT_BASE="$2"
                shift 2
                ;;
            --no-notify)
                NOTIFY_ON_FINDINGS=false
                shift
                ;;
            -c|--config)
                CONFIG_FILE="$2"
                shift 2
                ;;
            --update)
                log INFO "Updating Nuclei templates..."
                nuclei -update-templates
                exit 0
                ;;
            -h|--help)
                show_banner
                show_usage
                exit 0
                ;;
            -v|--version)
                echo "HybridRecon X version ${VERSION}"
                exit 0
                ;;
            --preflight-only)
                PREFLIGHT_ONLY=true
                shift
                ;;
            *)
                log ERROR "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
}

validate_arguments() {
    if [[ -z "$TARGET" && -z "$TARGET_LIST" ]]; then
        log ERROR "No target specified. Use -d <domain> or -l <file>"
        show_usage
        exit 1
    fi
    
    if [[ -n "$TARGET_LIST" && ! -f "$TARGET_LIST" ]]; then
        log ERROR "Target list file not found: $TARGET_LIST"
        exit 1
    fi
    
    if [[ ! -f "$CONFIG_FILE" ]]; then
        log WARN "Config file not found: $CONFIG_FILE"
        log INFO "Using default settings"
    fi
    
    # Validate conflicting options
    if [[ "$FAST_MODE" == true && "$AGGRESSIVE_MODE" == true ]]; then
        log ERROR "Cannot use --fast and --aggressive together"
        exit 1
    fi
}

# ============================================================================
# MODULE EXECUTION
# ============================================================================
run_module() {
    local module_name="$1"
    local module_script="${MODULES_DIR}/${module_name}"
    
    if [[ ! -f "$module_script" ]]; then
        log ERROR "Module not found: $module_script"
        return 1
    fi
    
    if [[ "$DRY_RUN" == true ]]; then
        log INFO "[DRY-RUN] Would execute: $module_script"
        return 0
    fi
    
    log TASK "Running module: ${module_name%.sh}"
    
    local start_time=$(date +%s)
    
    # Export variables for modules
    export TARGET
    export TARGET_LIST
    export OUTPUT_BASE
    export CONFIG_FILE
    export FAST_MODE
    export AGGRESSIVE_MODE
    export STEALTH_MODE
    export THREADS
    export RATE_LIMIT
    export EXCLUDE_PATTERN
    export SCRIPT_DIR
    export DATA_DIR
    
    # Execute module
    if bash "$module_script" 2>&1 | tee -a "$LOG_FILE"; then
        log SUCCESS "Module completed: ${module_name%.sh} ($(elapsed_time $start_time))"
        return 0
    else
        log ERROR "Module failed: ${module_name%.sh}"
        return 1
    fi
}

# ============================================================================
# MAIN PIPELINE
# ============================================================================
main() {
    local total_start=$(date +%s)
    
    show_banner
    parse_arguments "$@"
    validate_arguments
    
    # Setup
    local target_name="${TARGET:-$(basename "${TARGET_LIST%.*}")}"
    setup_output_directory "$target_name"
    
    log INFO "Starting HybridRecon X scan"
    log INFO "Target: ${TARGET:-$TARGET_LIST}"
    log INFO "Mode: $([ "$FAST_MODE" = true ] && echo "FAST" || ([ "$AGGRESSIVE_MODE" = true ] && echo "AGGRESSIVE" || ([ "$STEALTH_MODE" = true ] && echo "STEALTH" || echo "NORMAL")))"
    echo ""
    
    # Check dependencies
    check_dependencies
    
    # ========== PHASE 0: PRE-FLIGHT ==========
    run_module "00_preflight.sh" || {
        log ERROR "Pre-flight checks failed"
        exit 1
    }
    
    [[ "${PREFLIGHT_ONLY:-false}" == true ]] && {
        log SUCCESS "Pre-flight checks completed"
        exit 0
    }
    
    # ========== PHASE 1: RECONNAISSANCE ==========
    if [[ "$SKIP_RECON" != true ]]; then
        run_module "01_recon_subs.sh" || log WARN "Recon module had errors"
    else
        log INFO "Skipping reconnaissance (--skip-recon)"
    fi
    
    [[ "$ONLY_RECON" == true ]] && {
        log SUCCESS "Reconnaissance completed (--only-recon)"
        exit 0
    }
    
    # ========== PHASE 2: PROBING ==========
    run_module "02_filter_probe.sh" || log WARN "Probing module had errors"
    
    # ========== PHASE 3: FINGERPRINTING ==========
    run_module "03_fingerprint.sh" || log WARN "Fingerprinting module had errors"
    
    [[ "$ONLY_FINGERPRINT" == true ]] && {
        log SUCCESS "Fingerprinting completed (--only-fingerprint)"
        exit 0
    }
    
    # ========== PHASE 4: CONTENT DISCOVERY ==========
    if [[ "$SKIP_CONTENT" != true ]]; then
        run_module "04_content_disc.sh" || log WARN "Content discovery module had errors"
    else
        log INFO "Skipping content discovery (--skip-content)"
    fi
    
    # ========== PHASE 5: PARAMETER MINING ==========
    run_module "05_param_mining.sh" || log WARN "Parameter mining module had errors"
    
    # ========== PHASE 6: SMART VULNERABILITY ROUTING ==========
    if [[ "$SKIP_VULN" != true ]]; then
        log TASK "Running Smart Router (Python)"
        if [[ "$DRY_RUN" == true ]]; then
            log INFO "[DRY-RUN] Would execute: 06_vuln_smart.py"
        else
            python3 "${MODULES_DIR}/06_vuln_smart.py" \
                --output "$OUTPUT_BASE" \
                --config "$CONFIG_FILE" \
                $([ "$FAST_MODE" = true ] && echo "--fast") \
                $([ "$STEALTH_MODE" = true ] && echo "--stealth") \
                2>&1 | tee -a "$LOG_FILE"
        fi
        
        # ========== PHASE 7: SPECIFIC EXPLOITS ==========
        run_module "07_exploits_specific.sh" || log WARN "Exploits module had errors"
    else
        log INFO "Skipping vulnerability scanning (--skip-vuln)"
    fi
    
    # ========== PHASE 8: CLOUD & GIT ==========
    run_module "08_cloud_git.sh" || log WARN "Cloud/Git module had errors"
    
    # ========== PHASE 9: REPORTING ==========
    run_module "09_reporting.sh" || log WARN "Reporting module had errors"
    
    # ========== COMPLETE ==========
    echo ""
    log SUCCESS "═══════════════════════════════════════════════════════════════"
    log SUCCESS "HybridRecon X scan completed!"
    log SUCCESS "Total time: $(elapsed_time $total_start)"
    log SUCCESS "Results: ${OUTPUT_BASE}"
    log SUCCESS "═══════════════════════════════════════════════════════════════"
    
    # Send completion notification
    send_notification "🎯 HybridRecon X scan completed for ${target_name}. Check results at ${OUTPUT_BASE}" "info"
    
    # Print summary
    echo ""
    log INFO "Quick Summary:"
    echo "  - Subdomains found: $(count_lines "${OUTPUT_BASE}/recon/clean_subdomains.txt")"
    echo "  - Live hosts: $(count_lines "${OUTPUT_BASE}/probed/live_hosts.txt")"
    echo "  - URLs discovered: $(count_lines "${OUTPUT_BASE}/content/all_urls.txt")"
    echo "  - Vulnerabilities: $(find "${OUTPUT_BASE}/vulns" -name "*.txt" -exec cat {} \; 2>/dev/null | wc -l)"
    echo ""
    echo "  📊 Full report: ${OUTPUT_BASE}/reports/report.html"
}

# ============================================================================
# ENTRY POINT
# ============================================================================
main "$@"
