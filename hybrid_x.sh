#!/usr/bin/env bash
# ============================================================================
# HYBRIDRECON X - MAIN ORCHESTRATOR
# ============================================================================
# Context-Aware Bug Bounty & Pentesting Framework
# The Smart Recon Platform that thinks before it attacks
# ============================================================================

# Note: -e removed intentionally - we handle errors explicitly
set -uo pipefail

# ============================================================================
# GLOBAL VARIABLES
# ============================================================================
VERSION=$(cat "$(dirname "${BASH_SOURCE[0]}")/VERSION" 2>/dev/null || echo "2.2.0")
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/config.yaml"
MODULES_DIR="${SCRIPT_DIR}/modules"
LIB_DIR="${SCRIPT_DIR}/lib"
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
EXCLUDE_FILE=""        # NEW: File with out-of-scope subdomains
INCLUDE_FILE=""        # NEW: File with in-scope only subdomains
ORG_NAME=""            # NEW: Organization name for multi-domain enum

# Mode flags
FAST_MODE=false
AGGRESSIVE_MODE=false
STEALTH_MODE=false

# NEW: Workflow mode flags
MODE_RECON=false       # Full recon without active attacks
MODE_SUBDOMAINS=false  # Only subdomain enum + probing
MODE_PASSIVE=false     # Passive recon only
MODE_ALL=false         # Full pipeline (default behavior)
MODE_WEB=false         # Web-related modules only

# Skip flags
SKIP_RECON=false
SKIP_CONTENT=false
SKIP_VULN=false

# Only flags
ONLY_RECON=false
ONLY_FINGERPRINT=false
ONLY_SUBDOMAINS=false
ONLY_PROBING=false
ONLY_CONTENT=false
ONLY_PARAMS=false
ONLY_VULN=false
ONLY_CLOUD=false
ONLY_REPORTING=false

# Other flags
RESUME=false
DRY_RUN=false
NOTIFY_ON_FINDINGS=true
THREADS=""
RATE_LIMIT=""
CURRENT_MODULE=""


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
    local deps=("jq" "python3" "httpx" "nuclei")
    local missing=()
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing+=("$dep")
        fi
    done
    
    if ! command -v "yq" &> /dev/null; then
        log WARN "yq is not installed; YAML parsing will use defaults or Python"
    fi
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        if [[ "${DRY_RUN:-false}" == true ]]; then
            log WARN "Missing tool binaries on host: ${missing[*]}"
            log INFO "[DRY-RUN] Simulating execution pipeline..."
            return 0
        else
            log ERROR "Missing dependencies: ${missing[*]}"
            log INFO "Run inside Docker container or install missing tools"
            exit 1
        fi
    fi
}

setup_output_directory() {
    local target_name="$1"
    # Sanitize target name for directory
    target_name=$(echo "$target_name" | sed 's/[^a-zA-Z0-9._-]/_/g')
    
    # Use consistent directory name for output
    OUTPUT_BASE="${SCRIPT_DIR}/output/${target_name}"
    
    # If directory exists and has checkpoint, we're resuming - don't recreate
    if [[ -f "${OUTPUT_BASE}/.checkpoint.json" ]]; then
        local status
        status=$(jq -r '.status // "unknown"' "${OUTPUT_BASE}/.checkpoint.json" 2>/dev/null)
        if [[ "$status" != "completed" ]]; then
            log INFO "Using existing scan directory: ${OUTPUT_BASE}"
            return 0
        fi
    fi
    
    # Create/recreate directory structure
    mkdir -p "${OUTPUT_BASE}"/{recon,probed,fingerprint,content,params,vulns,exploits,cloud,reports,logs,intel}
    
    # Save scan start timestamp in a metadata file
    echo "$TIMESTAMP" > "${OUTPUT_BASE}/.scan_started"
    
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
    ./hybrid_x.sh [OPTIONS] --org <company_name>

${BOLD}TARGET OPTIONS:${NC}
    -d, --domain, --target <domain>  Single target domain (e.g., example.com)
    -l, --list <file>                File containing list of domains (one per line)
    --org <name>                     Multi-domain enumeration by company/brand name
    -s, --scope <file>               File containing in-scope patterns
    --exclude <pattern>              Exclude pattern (regex)
    --exclude-file <file>            File containing out-of-scope subdomains
    --include-file <file>            File with in-scope subdomains only

${BOLD}WORKFLOW MODES:${NC}
    --recon                          Full recon without active attacks
    --subdomains                     Subdomain enum + probing + takeover checks only
    --passive                        Passive reconnaissance only (no active scans)
    --all                            Full recon + active vulnerability scanning (default)
    --web                            Web-related modules only (probing, content, vulns)

${BOLD}SCAN MODES:${NC}
    -f, --fast                       Fast mode: Skip slow tools (amass, feroxbuster)
    -a, --aggressive                 Aggressive mode: Higher threads, deeper scans
    --stealth                        Stealth mode: Low rate, bypass WAF detection
    --dry-run                        Show what would be executed without running

${BOLD}SKIP OPTIONS:${NC}
    --skip-recon                     Skip subdomain enumeration
    --skip-content                   Skip content discovery
    --skip-vuln                      Skip vulnerability scanning

${BOLD}MODULE-ONLY OPTIONS:${NC}
    --only-recon                     Run only reconnaissance (subdomains + probing)
    --only-subdomains                Run only subdomain enumeration
    --only-probing                   Run only HTTP probing (requires subdomains)
    --only-fingerprint               Run only fingerprinting (requires live hosts)
    --only-content                   Run only content discovery
    --only-params                    Run only parameter mining
    --only-vuln                      Run only vulnerability scanning
    --only-cloud                     Run only cloud/git enumeration
    --only-reporting                 Run only report generation

${BOLD}RESUME OPTIONS:${NC}
    --resume                         Resume from last checkpoint (automatic)

${BOLD}PERFORMANCE OPTIONS:${NC}
    -t, --threads <n>                Override thread count
    -r, --rate-limit <n>             Override rate limit (requests/second)

${BOLD}OUTPUT OPTIONS:${NC}
    -o, --output <dir>               Custom output directory
    --no-notify                      Disable notifications
    -c, --config <file>              Use custom config file

${BOLD}GENERAL OPTIONS:${NC}
    -h, --help                       Show this help message
    -v, --version                    Show version
    --update                         Update Nuclei templates

${BOLD}EXAMPLES:${NC}
    # Full scan on single domain
    ./hybrid_x.sh -d hackerone.com

    # Fast recon only (no vuln scanning)
    ./hybrid_x.sh -d target.com --recon --fast

    # Passive reconnaissance only
    ./hybrid_x.sh -d target.com --passive

    # Web modules only with stealth
    ./hybrid_x.sh -d target.com --web --stealth

    # Multi-domain by organization name
    ./hybrid_x.sh --org "Acme Corp" --fast

    # With scope exclusions
    ./hybrid_x.sh -d target.com --exclude-file out_of_scope.txt

    # Resume previous scan
    ./hybrid_x.sh -d target.com --resume

EOF
}

# ============================================================================
# ARGUMENT PARSING
# ============================================================================
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            # Target options
            -d|--domain|--target)
                TARGET="$2"
                shift 2
                ;;
            -l|--list)
                TARGET_LIST="$2"
                shift 2
                ;;
            --org)
                ORG_NAME="$2"
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
            --exclude-file)
                EXCLUDE_FILE="$2"
                shift 2
                ;;
            --include-file)
                INCLUDE_FILE="$2"
                shift 2
                ;;
            # Workflow modes (mutually exclusive)
            --recon)
                MODE_RECON=true
                shift
                ;;
            --subdomains)
                MODE_SUBDOMAINS=true
                shift
                ;;
            --passive)
                MODE_PASSIVE=true
                shift
                ;;
            --all)
                MODE_ALL=true
                shift
                ;;
            --web)
                MODE_WEB=true
                shift
                ;;
            # Scan modes
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
            # Skip options
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
            --only-subdomains)
                ONLY_SUBDOMAINS=true
                shift
                ;;
            --only-probing)
                ONLY_PROBING=true
                shift
                ;;
            --only-content)
                ONLY_CONTENT=true
                shift
                ;;
            --only-params)
                ONLY_PARAMS=true
                shift
                ;;
            --only-vuln)
                ONLY_VULN=true
                shift
                ;;
            --only-cloud)
                ONLY_CLOUD=true
                shift
                ;;
            --only-reporting)
                ONLY_REPORTING=true
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
    # Check target specification - org mode doesn't require -d or -l
    if [[ -z "$TARGET" && -z "$TARGET_LIST" && -z "$ORG_NAME" ]]; then
        log ERROR "No target specified. Use -d <domain>, -l <file>, or --org <name>"
        show_usage
        exit 1
    fi
    
    if [[ -n "$TARGET_LIST" && ! -f "$TARGET_LIST" ]]; then
        log ERROR "Target list file not found: $TARGET_LIST"
        exit 1
    fi
    
    if [[ -n "$EXCLUDE_FILE" && ! -f "$EXCLUDE_FILE" ]]; then
        log ERROR "Exclude file not found: $EXCLUDE_FILE"
        exit 1
    fi
    
    if [[ -n "$INCLUDE_FILE" && ! -f "$INCLUDE_FILE" ]]; then
        log ERROR "Include file not found: $INCLUDE_FILE"
        exit 1
    fi
    
    if [[ ! -f "$CONFIG_FILE" ]]; then
        if [[ -f "${SCRIPT_DIR}/config.yaml.example" ]]; then
            log WARN "Config file not found: $CONFIG_FILE"
            log INFO "Creating config.yaml from config.yaml.example..."
            cp "${SCRIPT_DIR}/config.yaml.example" "$CONFIG_FILE"
            log INFO "→ Edit config.yaml to add your API keys and customize settings"
        else
            log WARN "Config file not found: $CONFIG_FILE"
            log INFO "Using default settings"
        fi
    fi
    
    # Validate conflicting options
    if [[ "$FAST_MODE" == true && "$AGGRESSIVE_MODE" == true ]]; then
        log ERROR "Cannot use --fast and --aggressive together"
        exit 1
    fi
    
    # Handle --org mode: generate target list from organization name
    if [[ -n "$ORG_NAME" ]]; then
        log INFO "Organization mode: Discovering domains for '$ORG_NAME'"
        # Create a target from the org name (simplified - real impl would use APIs)
        local org_slug
        org_slug=$(echo "$ORG_NAME" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9]//g')
        TARGET="${org_slug}.com"
        log INFO "Primary target set to: $TARGET"
    fi
    
    # Apply workflow modes - set SKIP flags based on mode
    if [[ "$MODE_PASSIVE" == true ]]; then
        log INFO "Mode: PASSIVE - No active scans"
        SKIP_VULN=true
        export PASSIVE_ONLY=true
    fi
    
    if [[ "$MODE_RECON" == true ]]; then
        log INFO "Mode: RECON - Full recon without active attacks"
        SKIP_VULN=true
    fi
    
    if [[ "$MODE_SUBDOMAINS" == true ]]; then
        log INFO "Mode: SUBDOMAINS - Subdomain enumeration only"
        ONLY_SUBDOMAINS=true
    fi
    
    if [[ "$MODE_WEB" == true ]]; then
        log INFO "Mode: WEB - Web-related modules only"
        SKIP_RECON=true
        export WEB_MODE=true
    fi
    
    if [[ "$MODE_ALL" == true ]]; then
        log INFO "Mode: ALL - Full pipeline"
    fi
}

# ============================================================================
# MODULE EXECUTION
# ============================================================================
run_module() {
    local module_name="$1"
    local module_script="${MODULES_DIR}/${module_name}"
    
    # Check if script is located in LIB_DIR instead of MODULES_DIR
    if [[ ! -f "$module_script" && -f "${LIB_DIR}/${module_name}" ]]; then
        module_script="${LIB_DIR}/${module_name}"
    fi
    
    local module_base="${module_name%.sh}"
    module_base="${module_base%.py}"
    
    if [[ ! -f "$module_script" ]]; then
        log ERROR "Module not found: $module_script"
        return 1
    fi
    
    # Check if we should skip this module (resume support)
    if [[ -n "${RESUME_FROM:-}" ]]; then
        local found_resume=false
        for m in 00_preflight 01_recon_subs 02_filter_probe anomaly_detector 03_fingerprint 04_content_disc 05_param_mining param_scorer 06_vuln_smart 07_exploits_specific escalation_engine 08_cloud_git 10_js_analysis 11_response_diff 12_advanced_vulns 09_validate 13_reporting; do
            if [[ "$m" == "$RESUME_FROM" ]]; then
                found_resume=true
            fi
            if [[ "$found_resume" == false && "$module_base" == "$m" ]]; then
                log INFO "[RESUME] Skipping completed module: $module_base"
                return 0
            fi
            if [[ "$module_base" == "$RESUME_FROM" ]]; then
                unset RESUME_FROM  # Clear so we don't skip again
                break
            fi
        done
    fi
    
    if [[ "$DRY_RUN" == true ]]; then
        log INFO "[DRY-RUN] Would execute: $module_script"
        return 0
    fi
    
    # Check if module already completed (for resume)
    if checkpoint_is_module_done "$module_base"; then
        log INFO "Skipping completed module: $module_base"
        return 0
    fi
    
    # Mark module as started in checkpoint
    checkpoint_module_start "$module_base"
    
    log TASK "Running module: $module_base"
    
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
    export EXCLUDE_FILE
    export INCLUDE_FILE
    export ORG_NAME
    export SCRIPT_DIR
    export DATA_DIR
    # Export mode flags
    export MODE_RECON
    export MODE_SUBDOMAINS
    export MODE_PASSIVE
    export MODE_ALL
    export MODE_WEB
    export PASSIVE_ONLY
    export WEB_MODE
    
    # Reset interrupt flags for this module
    reset_module_interrupt
    
    # Build execution command (Python vs Bash)
    local exec_cmd=()
    if [[ "$module_script" == *.py ]]; then
        exec_cmd=(python3 "$module_script")
        if [[ "$module_name" == "06_vuln_smart.py" ]]; then
            exec_cmd+=(--output "$OUTPUT_BASE" --config "$CONFIG_FILE")
            [[ "$FAST_MODE" == true ]] && exec_cmd+=(--fast)
            [[ "$STEALTH_MODE" == true ]] && exec_cmd+=(--stealth)
        elif [[ "$module_name" == "12_advanced_vulns.py" ]]; then
            exec_cmd+=(--output "$OUTPUT_BASE" --config "$CONFIG_FILE")
            [[ -n "$THREADS" ]] && exec_cmd+=(--threads "$THREADS")
            [[ "$FAST_MODE" == true ]] && exec_cmd+=(--fast)
            [[ "$STEALTH_MODE" == true ]] && exec_cmd+=(--stealth)
        elif [[ "$module_name" == "09_validate.py" || "$module_name" == "10_js_analysis.py" || "$module_name" == "11_response_diff.py" || "$module_name" == "param_scorer.py" || "$module_name" == "anomaly_detector.py" || "$module_name" == "escalation_engine.py" ]]; then
            exec_cmd+=(--output "$OUTPUT_BASE")
        fi
    else
        exec_cmd=(bash "$module_script")
    fi
    
    # Execute module
    local module_result=0
    if "${exec_cmd[@]}" 2>&1 | tee -a "$LOG_FILE"; then
        # Check if module was interrupted
        if is_module_interrupted; then
            log WARN "Module interrupted: $module_base ($(elapsed_time $start_time))"
            checkpoint_mark_interrupted "$module_base" "interrupted"
            module_result=0  # Allow pipeline to continue
        else
            log SUCCESS "Module completed: $module_base ($(elapsed_time $start_time))"
            checkpoint_module_done "$module_base"
        fi
    else
        local exit_code=$?
        # Check if exit was due to interrupt (130 = SIGINT, 137 = SIGKILL, 143 = SIGTERM)
        if [[ $exit_code -eq 130 || $exit_code -eq 137 || $exit_code -eq 143 ]] || is_module_interrupted; then
            log WARN "Module interrupted: $module_base"
            checkpoint_mark_interrupted "$module_base" "interrupted"
            module_result=0  # Allow pipeline to continue
        else
            log WARN "Module completed with errors: $module_base (exit code: $exit_code)"
            checkpoint_module_done "$module_base" "failed"
            module_result=0  # Allow pipeline to continue despite errors
        fi
    fi
    
    return $module_result
}

# ============================================================================
# CHECKPOINT SYSTEM - Source the checkpoint manager
# ============================================================================
source "${LIB_DIR}/checkpoint.sh"

# ============================================================================
# INTERRUPT HANDLING - Source the interrupt handler
# ============================================================================
source "${LIB_DIR}/interrupt.sh"

# ============================================================================
# CONFIG SYSTEM - Source the config library
# ============================================================================
source "${LIB_DIR}/config.sh"

# ============================================================================
# CONFIG RESOLVER - Unified configuration resolution
# ============================================================================
source "${LIB_DIR}/config_resolver.sh"

main() {
    local total_start=$(date +%s)
    
    show_banner
    parse_arguments "$@"
    validate_arguments
    
    # Initialize config system
    config_init
    config_export_for_module
    
    # Setup
    local target_name="${TARGET:-$(basename "${TARGET_LIST%.*}")}"
    
    # ==========================================
    # CHECKPOINT SYSTEM - Auto-detect resume
    # ==========================================
    local checkpoint_file
    checkpoint_file=$(checkpoint_find "$target_name") || true
    
    if [[ -n "$checkpoint_file" && -f "$checkpoint_file" ]]; then
        log WARN "═══════════════════════════════════════════════════"
        log WARN "  INCOMPLETE SCAN DETECTED"
        log WARN "  Target: $target_name"
        log WARN "  Checkpoint: $checkpoint_file"
        log WARN "═══════════════════════════════════════════════════"
        
        # Load checkpoint
        if checkpoint_load "$checkpoint_file"; then
            log SUCCESS "Resuming scan from checkpoint"
            RESUME=true
        else
            log WARN "Failed to load checkpoint, starting fresh"
        fi
    fi
    
    # Create new output directory if not resuming
    if [[ -z "${OUTPUT_BASE:-}" || ! -d "${OUTPUT_BASE:-}" ]]; then
        setup_output_directory "$target_name"
        # Initialize checkpoint for new scan
        checkpoint_init "$OUTPUT_BASE" "${TARGET:-$TARGET_LIST}"
    fi
    
    LOG_FILE="${OUTPUT_BASE}/logs/hybridrecon.log"
    mkdir -p "$(dirname "$LOG_FILE")"
    
    # Install graceful interrupt handler (doesn't exit, allows pipeline to continue)
    install_global_handler
    
    log INFO "Starting HybridRecon X scan"
    log INFO "Target: ${TARGET:-$TARGET_LIST}"
    log INFO "Output: $OUTPUT_BASE"
    log INFO "Mode: $([ "$FAST_MODE" = true ] && echo "FAST" || ([ "$AGGRESSIVE_MODE" = true ] && echo "AGGRESSIVE" || ([ "$STEALTH_MODE" = true ] && echo "STEALTH" || echo "NORMAL")))"
    echo ""
    
    # Check dependencies
    check_dependencies
    
    # ============================================================================
    # RESOLVE CONFIGURATION - Single source of truth for all settings
    # ============================================================================
    # This resolves CLI → config.yaml → defaults priority ONCE before any module runs
    config_resolve_all
    config_export_resolved
    
    log INFO "Configuration resolved:"
    log INFO "  Threads: $(resolved_get runtime.threads 50)"
    log INFO "  Rate Limit: $(resolved_get runtime.rate_limit 50)"
    echo ""
    
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
    # Run if: explicitly requested OR (not skipped AND no other --only-* flag is set)
    local any_only_flag=false
    [[ "$ONLY_SUBDOMAINS" == true || "$ONLY_PROBING" == true || "$ONLY_FINGERPRINT" == true || "$ONLY_CONTENT" == true || "$ONLY_PARAMS" == true || "$ONLY_VULN" == true || "$ONLY_CLOUD" == true || "$ONLY_REPORTING" == true ]] && any_only_flag=true
    
    if [[ "$ONLY_SUBDOMAINS" == true || "$ONLY_RECON" == true || ( "$any_only_flag" == false && "$SKIP_RECON" != true ) ]]; then
        run_module "01_recon_subs.sh" || log WARN "Recon module had errors"
    fi
    
    [[ "$ONLY_SUBDOMAINS" == true ]] && {
        log SUCCESS "Subdomain enumeration completed (--only-subdomains)"
        exit 0
    }
    
    # ========== PHASE 2: PROBING ==========
    if [[ "$ONLY_PROBING" == true || "$ONLY_RECON" == true || ( "$any_only_flag" == false ) ]]; then
        run_module "02_filter_probe.sh" || log WARN "Probing module had errors"
        # Run Anomaly Detector on HTTP response metadata
        if [[ "$DRY_RUN" == true || -f "${OUTPUT_BASE}/probed/httpx_output.json" ]]; then
            run_module "anomaly_detector.py" || log WARN "Anomaly detector had warnings"
        fi
    fi
    
    [[ "$ONLY_PROBING" == true ]] && {
        log SUCCESS "HTTP probing completed (--only-probing)"
        exit 0
    }
    
    [[ "$ONLY_RECON" == true ]] && {
        log SUCCESS "Reconnaissance completed (--only-recon)"
        exit 0
    }
    
    # ========== PHASE 3: FINGERPRINTING ==========
    if [[ "$ONLY_FINGERPRINT" == true || "$any_only_flag" == false ]]; then
        run_module "03_fingerprint.sh" || log WARN "Fingerprinting module had errors"
    fi
    
    [[ "$ONLY_FINGERPRINT" == true ]] && {
        log SUCCESS "Fingerprinting completed (--only-fingerprint)"
        exit 0
    }
    
    # ========== PHASE 4: CONTENT DISCOVERY ==========
    if [[ "$ONLY_CONTENT" == true || ( "$any_only_flag" == false && "$SKIP_CONTENT" != true ) ]]; then
        run_module "04_content_disc.sh" || log WARN "Content discovery module had errors"
    fi
    
    [[ "$ONLY_CONTENT" == true ]] && {
        log SUCCESS "Content discovery completed (--only-content)"
        exit 0
    }
    
    # ========== PHASE 5: PARAMETER MINING ==========
    if [[ "$ONLY_PARAMS" == true || "$any_only_flag" == false ]]; then
        run_module "05_param_mining.sh" || log WARN "Parameter mining module had errors"
        # Run Parameter Prioritization Scorer
        if [[ "$DRY_RUN" == true || -f "${OUTPUT_BASE}/params/urls_with_params.txt" ]]; then
            run_module "param_scorer.py" || log WARN "Parameter scorer had warnings"
        fi
    fi
    
    [[ "$ONLY_PARAMS" == true ]] && {
        log SUCCESS "Parameter mining completed (--only-params)"
        exit 0
    }
    
    # ========== PHASE 6: SMART VULNERABILITY ROUTING ==========
    if [[ "$ONLY_VULN" == true || ( "$any_only_flag" == false && "$SKIP_VULN" != true ) ]]; then
        run_module "06_vuln_smart.py" || log WARN "Smart router module had errors"
        
        # ========== PHASE 7: SPECIFIC EXPLOITS ==========
        run_module "07_exploits_specific.sh" || log WARN "Exploits module had errors"
        
        # ========== PHASE 7.5: ESCALATION ENGINE ==========
        if [[ "$DRY_RUN" == true || -f "${OUTPUT_BASE}/intel/anomalies.json" ]]; then
            run_module "escalation_engine.py" || log WARN "Escalation engine had warnings"
        fi
        
        # ========== PHASE 8: ADVANCED VULNERABILITIES ==========
        run_module "12_advanced_vulns.py" || log WARN "Advanced vulns module had warnings"
    fi
    
    [[ "$ONLY_VULN" == true ]] && {
        log SUCCESS "Vulnerability scanning completed (--only-vuln)"
        exit 0
    }
    
    # ========== PHASE 9: CLOUD & GIT ==========
    if [[ "$ONLY_CLOUD" == true || "$any_only_flag" == false ]]; then
        run_module "08_cloud_git.sh" || log WARN "Cloud/Git module had errors"
    fi
    
    [[ "$ONLY_CLOUD" == true ]] && {
        log SUCCESS "Cloud/Git enumeration completed (--only-cloud)"
        exit 0
    }
    
    # ========== PHASE 10: JAVASCRIPT ANALYSIS ==========
    run_module "10_js_analysis.py" || log WARN "JS analysis had warnings"
    
    # ========== PHASE 11: RESPONSE DIFF ANALYSIS ==========
    if [[ "$SKIP_VULN" != true ]]; then
        run_module "11_response_diff.py" || log WARN "Response diff had warnings"
    fi
    
    # ========== PHASE 12: VALIDATION (Validates all findings before reporting) ==========
    if [[ "$SKIP_VULN" != true ]]; then
        run_module "09_validate.py" || log WARN "Validation had warnings"
    fi
    
    # ========== PHASE 13: REPORTING ==========
    run_module "13_reporting.sh" || log WARN "Reporting module had errors"
    
    [[ "$ONLY_REPORTING" == true ]] && {
        log SUCCESS "Reporting completed (--only-reporting)"
        exit 0
    }
    
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
    
    # v2.0 additions
    local high_conf=$(cat "${OUTPUT_BASE}/vulns/validated_high.json" 2>/dev/null | jq length 2>/dev/null || echo "0")
    local secrets=$(cat "${OUTPUT_BASE}/intel/js_secrets.json" 2>/dev/null | jq length 2>/dev/null || echo "0")
    echo "  - HIGH confidence vulns: ${high_conf}"
    echo "  - Secrets found (JS): ${secrets}"
    echo ""
    echo "  📊 Full report: ${OUTPUT_BASE}/reports/report.html"
    
    # Scan completed successfully - mark checkpoint as complete
    checkpoint_clear
}

# ============================================================================
# ENTRY POINT
# ============================================================================
main "$@"
