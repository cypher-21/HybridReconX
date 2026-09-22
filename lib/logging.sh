#!/usr/bin/env bash
# ============================================================================
# LIB: LOGGING - Standardized Logging for HybridRecon X
# ============================================================================
# Provides consistent logging functions for all modules.
# Source this file in modules for standardized output.
# ============================================================================

# Colors
export LOG_GREEN='\033[0;32m'
export LOG_YELLOW='\033[1;33m'
export LOG_CYAN='\033[0;36m'
export LOG_RED='\033[0;31m'
export LOG_MAGENTA='\033[0;35m'
export LOG_NC='\033[0m'

# Current module name (set by each module)
CURRENT_MODULE="${CURRENT_MODULE:-HYBRID}"

# Set the module name for log prefix
set_log_module() {
    CURRENT_MODULE="$1"
}

# Standard logging function
log() {
    local level="$1"
    shift
    local timestamp
    timestamp=$(date '+%H:%M:%S')
    
    case "$level" in
        INFO)
            echo -e "${LOG_GREEN}[${CURRENT_MODULE}]${LOG_NC} $*"
            ;;
        WARN)
            echo -e "${LOG_YELLOW}[${CURRENT_MODULE}]${LOG_NC} $*"
            ;;
        ERROR)
            echo -e "${LOG_RED}[${CURRENT_MODULE} ERROR]${LOG_NC} $*" >&2
            ;;
        TASK)
            echo -e "${LOG_CYAN}[${CURRENT_MODULE}]${LOG_NC} $*"
            ;;
        CRITICAL|ALERT)
            echo -e "${LOG_RED}[!!! ${CURRENT_MODULE}]${LOG_NC} $*"
            ;;
        DEBUG)
            if [[ "${DEBUG_MODE:-false}" == true ]]; then
                echo -e "${LOG_MAGENTA}[${CURRENT_MODULE} DBG]${LOG_NC} $*"
            fi
            ;;
        SUCCESS)
            echo -e "${LOG_GREEN}[${CURRENT_MODULE} ✓]${LOG_NC} $*"
            ;;
        *)
            echo -e "[${CURRENT_MODULE}] $*"
            ;;
    esac
}

# Helper functions
log_info() { log INFO "$@"; }
log_warn() { log WARN "$@"; }
log_error() { log ERROR "$@"; }
log_task() { log TASK "$@"; }
log_critical() { log CRITICAL "$@"; }
log_debug() { log DEBUG "$@"; }
log_success() { log SUCCESS "$@"; }

# Count lines in a file (common utility)
count_lines() {
    [[ -f "$1" ]] && wc -l < "$1" | tr -d ' ' || echo "0"
}

# Get threads based on mode
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

# Get rate limit based on mode
get_rate_limit() {
    if [[ -n "${RATE_LIMIT:-}" ]]; then
        echo "$RATE_LIMIT"
    elif [[ "${STEALTH_MODE:-false}" == true ]]; then
        echo "10"
    else
        echo "150"
    fi
}
