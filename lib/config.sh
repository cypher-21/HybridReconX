#!/usr/bin/env bash
# ============================================================================
# LIB: CONFIG - Configuration Management
# ============================================================================
# Provides functions to load, validate, and read config.yaml settings.
# Ensures enabled/disabled flags and tool settings are properly applied.
# ============================================================================

# Config state
CONFIG_LOADED=false
CONFIG_FILE="${CONFIG_FILE:-${SCRIPT_DIR:-$(pwd)}/config.yaml}"

# ============================================================================
# INIT & VALIDATION
# ============================================================================

config_init() {
    # Initialize and validate configuration
    if [[ "$CONFIG_LOADED" == true ]]; then
        return 0
    fi
    
    if [[ ! -f "$CONFIG_FILE" ]]; then
        echo "[WARN] Config file not found: $CONFIG_FILE" >&2
        echo "[INFO] Using default settings" >&2
        CONFIG_LOADED=true
        return 0
    fi
    
    # Check if yq is available
    if ! command -v yq &>/dev/null; then
        echo "[WARN] yq not installed, config parsing limited" >&2
        CONFIG_LOADED=true
        return 0
    fi
    
    # Validate YAML syntax
    if ! yq '.' "$CONFIG_FILE" &>/dev/null; then
        echo "[ERROR] Invalid YAML syntax in $CONFIG_FILE" >&2
        return 1
    fi
    
    CONFIG_LOADED=true
    
    # Export common settings
    config_export_globals
    
    return 0
}

config_export_globals() {
    # Export global config values to environment
    export CFG_THREADS_DEFAULT=$(config_get ".global.threads.default" "50")
    export CFG_THREADS_AGGRESSIVE=$(config_get ".global.threads.aggressive" "100")
    export CFG_THREADS_PASSIVE=$(config_get ".global.threads.passive" "25")
    
    export CFG_RATE_DEFAULT=$(config_get ".global.rate_limit.default" "50")
    export CFG_RATE_SLOW=$(config_get ".global.rate_limit.slow" "10")
    export CFG_RATE_AGGRESSIVE=$(config_get ".global.rate_limit.aggressive" "150")
    
    export CFG_TIMEOUT_HTTP=$(config_get ".global.timeouts.http" "10")
    export CFG_TIMEOUT_DNS=$(config_get ".global.timeouts.dns" "5")
    export CFG_TIMEOUT_TOOL=$(config_get ".global.timeouts.tool_execution" "3600")
    export CFG_TIMEOUT_AMASS=$(config_get ".global.timeouts.amass" "900")
    
    export CFG_USER_AGENT=$(config_get ".global.user_agent" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
}

# ============================================================================
# CONFIG READING FUNCTIONS
# ============================================================================

config_get() {
    # Get a config value with fallback default
    # Usage: config_get ".modules.recon.subfinder.enabled" "true"
    local key="$1"
    local default="${2:-}"
    
    if [[ ! -f "$CONFIG_FILE" ]] || ! command -v yq &>/dev/null; then
        echo "$default"
        return
    fi
    
    local value
    value=$(yq -r "$key // \"$default\"" "$CONFIG_FILE" 2>/dev/null)
    
    # Handle null/empty values
    if [[ "$value" == "null" || -z "$value" ]]; then
        echo "$default"
    else
        echo "$value"
    fi
}

config_get_bool() {
    # Get a boolean config value
    # Returns: "true" or "false"
    local key="$1"
    local default="${2:-true}"
    
    local value
    value=$(config_get "$key" "$default")
    
    # Normalize boolean
    case "${value,,}" in
        true|yes|1|on) echo "true" ;;
        false|no|0|off) echo "false" ;;
        *) echo "$default" ;;
    esac
}

config_get_int() {
    # Get an integer config value
    local key="$1"
    local default="${2:-0}"
    
    local value
    value=$(config_get "$key" "$default")
    
    # Validate integer
    if [[ "$value" =~ ^[0-9]+$ ]]; then
        echo "$value"
    else
        echo "$default"
    fi
}

# ============================================================================
# MODULE/TOOL ENABLED CHECKS
# ============================================================================

config_is_module_enabled() {
    # Check if a top-level module is enabled
    # Usage: config_is_module_enabled "recon"
    local module="$1"
    
    # CLI flags override config
    case "$module" in
        recon)
            [[ "${SKIP_RECON:-false}" == true ]] && echo "false" && return
            ;;
        content)
            [[ "${SKIP_CONTENT:-false}" == true ]] && echo "false" && return
            ;;
        vulnerability|vulns)
            [[ "${SKIP_VULN:-false}" == true ]] && echo "false" && return
            ;;
    esac
    
    config_get_bool ".modules.${module}.enabled" "true"
}

config_is_tool_enabled() {
    # Check if a specific tool is enabled within its module
    # Usage: config_is_tool_enabled "recon" "amass"
    local module="$1"
    local tool="$2"
    
    # First check if the module itself is enabled
    local module_enabled
    module_enabled=$(config_is_module_enabled "$module")
    
    if [[ "$module_enabled" == "false" ]]; then
        echo "false"
        return
    fi
    
    # Check the specific tool
    config_get_bool ".modules.${module}.${tool}.enabled" "true"
}

config_should_run_tool() {
    # Complete check for whether a tool should run
    # Considers: config enabled, CLI flags, fast mode, etc.
    # Usage: config_should_run_tool "recon" "amass"
    local module="$1"
    local tool="$2"
    
    # Check config enabled status
    local enabled
    enabled=$(config_is_tool_enabled "$module" "$tool")
    
    if [[ "$enabled" == "false" ]]; then
        echo "false"
        return
    fi
    
    # Fast mode skips slow tools
    if [[ "${FAST_MODE:-false}" == true ]]; then
        case "$tool" in
            amass|feroxbuster|arjun)
                echo "false"
                return
                ;;
        esac
    fi
    
    echo "true"
}

# ============================================================================
# TOOL-SPECIFIC GETTERS
# ============================================================================

config_get_threads() {
    # Get thread count for a tool, respecting mode
    local tool="${1:-}"
    
    # CLI override takes priority
    if [[ -n "${THREADS:-}" ]]; then
        echo "$THREADS"
        return
    fi
    
    # Try tool-specific config
    if [[ -n "$tool" ]]; then
        local tool_threads
        # Map tool to config path
        case "$tool" in
            ffuf) tool_threads=$(config_get ".modules.content_discovery.ffuf.threads" "") ;;
            arjun) tool_threads=$(config_get ".modules.parameter_mining.arjun.threads" "") ;;
            httpx) tool_threads=$(config_get ".modules.probing.httpx.threads" "") ;;
            *) tool_threads="" ;;
        esac
        
        if [[ -n "$tool_threads" && "$tool_threads" != "null" ]]; then
            echo "$tool_threads"
            return
        fi
    fi
    
    # Use mode-based defaults
    if [[ "${AGGRESSIVE_MODE:-false}" == true ]]; then
        echo "${CFG_THREADS_AGGRESSIVE:-100}"
    elif [[ "${STEALTH_MODE:-false}" == true ]]; then
        echo "${CFG_THREADS_PASSIVE:-25}"
    else
        echo "${CFG_THREADS_DEFAULT:-50}"
    fi
}

config_get_rate_limit() {
    # Get rate limit, respecting mode and WAF detection
    
    # CLI override takes priority
    if [[ -n "${RATE_LIMIT:-}" ]]; then
        echo "$RATE_LIMIT"
        return
    fi
    
    # WAF detected -> use slow rate
    if [[ "${WAF_DETECTED:-false}" == true ]]; then
        echo "${CFG_RATE_SLOW:-10}"
        return
    fi
    
    # Mode-based
    if [[ "${AGGRESSIVE_MODE:-false}" == true ]]; then
        echo "${CFG_RATE_AGGRESSIVE:-150}"
    elif [[ "${STEALTH_MODE:-false}" == true ]]; then
        echo "${CFG_RATE_SLOW:-10}"
    else
        echo "${CFG_RATE_DEFAULT:-50}"
    fi
}

config_get_timeout() {
    # Get timeout for a tool
    local tool="${1:-}"
    local default="${2:-300}"
    
    case "$tool" in
        amass) echo "${CFG_TIMEOUT_AMASS:-900}" ;;
        http|httpx) echo "${CFG_TIMEOUT_HTTP:-10}" ;;
        dns|dnsx) echo "${CFG_TIMEOUT_DNS:-5}" ;;
        *) echo "${CFG_TIMEOUT_TOOL:-$default}" ;;
    esac
}

config_get_wordlist() {
    # Get wordlist path for a tool
    local tool="$1"
    local default="${2:-}"
    
    case "$tool" in
        ffuf)
            config_get ".modules.content_discovery.ffuf.wordlist" "$default"
            ;;
        *)
            echo "$default"
            ;;
    esac
}

# ============================================================================
# API KEY GETTERS
# ============================================================================

config_get_api_key() {
    # Get an API key from config
    local key_name="$1"
    
    config_get ".api_keys.${key_name}" ""
}

config_has_api_key() {
    # Check if an API key is set
    local key_name="$1"
    local value
    value=$(config_get_api_key "$key_name")
    
    [[ -n "$value" && "$value" != "null" ]] && echo "true" || echo "false"
}

# ============================================================================
# EXPORT FOR MODULES
# ============================================================================

config_export_for_module() {
    # Export relevant config for subshell/module execution
    export CONFIG_FILE
    export CONFIG_LOADED
    export CFG_THREADS_DEFAULT
    export CFG_THREADS_AGGRESSIVE
    export CFG_THREADS_PASSIVE
    export CFG_RATE_DEFAULT
    export CFG_RATE_SLOW
    export CFG_RATE_AGGRESSIVE
    export CFG_TIMEOUT_HTTP
    export CFG_TIMEOUT_DNS
    export CFG_TIMEOUT_TOOL
    export CFG_TIMEOUT_AMASS
    export CFG_USER_AGENT
}

# ============================================================================
# DEBUG
# ============================================================================

config_debug() {
    # Print config debug info
    echo "=== CONFIG DEBUG ==="
    echo "CONFIG_FILE: $CONFIG_FILE"
    echo "CONFIG_LOADED: $CONFIG_LOADED"
    echo ""
    echo "Global Settings:"
    echo "  Threads (default): $(config_get_threads)"
    echo "  Rate Limit: $(config_get_rate_limit)"
    echo ""
    echo "Module Status:"
    for module in recon probing fingerprint content_discovery parameter_mining vulnerability; do
        local status=$(config_is_module_enabled "$module")
        echo "  $module: $status"
    done
    echo ""
    echo "Tool Status (recon):"
    for tool in subfinder amass assetfinder findomain; do
        local status=$(config_is_tool_enabled "recon" "$tool")
        echo "  $tool: $status"
    done
    echo "===================="
}
