#!/usr/bin/env bash
# ============================================================================
# CONFIG RESOLVER - Unified Configuration Resolution Layer
# ============================================================================
# Single entry point for all configuration lookups.
# Priority: CLI flags → config.yaml → defaults
# Pre-computes resolved config at startup for consistent behavior.
# ============================================================================

# Resolved configuration cache
declare -A RESOLVED_CONFIG
RESOLVED_CONFIG_READY=false

# ============================================================================
# RESOLUTION FUNCTIONS
# ============================================================================

# Resolve all configuration at startup
config_resolve_all() {
    if [[ "$RESOLVED_CONFIG_READY" == true ]]; then
        return 0
    fi
    
    # Resolve module enabled states
    _resolve_module_states
    
    # Resolve tool enabled states
    _resolve_tool_states
    
    # Resolve runtime parameters
    _resolve_runtime_params
    
    RESOLVED_CONFIG_READY=true
    
    # Log resolution for debugging
    if [[ "${DEBUG:-false}" == true ]]; then
        config_debug_resolved
    fi
}

_resolve_module_states() {
    # Module enabled states (CLI overrides config)
    local modules=("recon" "probing" "fingerprint" "content_discovery" "parameter_mining" "vulnerability" "cloud_git" "cms" "reporting")
    
    for module in "${modules[@]}"; do
        local key="module.${module}.enabled"
        local value="true"  # Default
        
        # Check config file
        if [[ -f "${CONFIG_FILE:-}" ]] && command -v yq &>/dev/null; then
            local cfg_value
            cfg_value=$(yq -r ".modules.${module}.enabled // \"true\"" "$CONFIG_FILE" 2>/dev/null)
            [[ "$cfg_value" == "false" ]] && value="false"
        fi
        
        # CLI flag overrides
        case "$module" in
            recon)
                [[ "${SKIP_RECON:-false}" == true ]] && value="false"
                ;;
            content_discovery)
                [[ "${SKIP_CONTENT:-false}" == true ]] && value="false"
                ;;
            vulnerability)
                [[ "${SKIP_VULN:-false}" == true ]] && value="false"
                ;;
        esac
        
        RESOLVED_CONFIG["$key"]="$value"
    done
}

_resolve_tool_states() {
    # Tool enabled states within modules
    local -A tools=(
        ["recon.subfinder"]="true"
        ["recon.amass"]="true"
        ["recon.assetfinder"]="true"
        ["recon.findomain"]="true"
        ["recon.tlsx"]="true"
        ["recon.gotator"]="true"
        ["recon.dnstake"]="true"
        ["recon.nmap"]="true"
        ["vulnerability.nuclei"]="true"
        ["vulnerability.xss.dalfox"]="true"
        ["vulnerability.xss.xsstrike"]="false"
        ["vulnerability.sqli.ghauri"]="true"
        ["vulnerability.sqli.sqlmap"]="true"
        ["vulnerability.ssti.tplmap"]="true"
        ["vulnerability.command_injection.commix"]="true"
        ["vulnerability.advanced.cors"]="true"
        ["vulnerability.advanced.crlf"]="true"
        ["vulnerability.advanced.ssl_tls"]="true"
        ["vulnerability.advanced.request_smuggling"]="true"
        ["vulnerability.advanced.lfi"]="true"
        ["vulnerability.advanced.ssrf"]="true"
        ["vulnerability.advanced.open_redirect"]="true"
        ["content_discovery.ffuf"]="true"
        ["content_discovery.katana"]="true"
        ["content_discovery.feroxbuster"]="false"
        ["parameter_mining.paramspider"]="true"
        ["parameter_mining.arjun"]="true"
    )
    
    for tool_path in "${!tools[@]}"; do
        local default="${tools[$tool_path]}"
        local key="tool.${tool_path}.enabled"
        local value="$default"
        
        # Check config file
        if [[ -f "${CONFIG_FILE:-}" ]] && command -v yq &>/dev/null; then
            local yaml_path=".modules.${tool_path//./.}.enabled"
            local cfg_value
            cfg_value=$(yq -r "$yaml_path // \"$default\"" "$CONFIG_FILE" 2>/dev/null)
            [[ "$cfg_value" == "false" ]] && value="false"
            [[ "$cfg_value" == "true" ]] && value="true"
        fi
        
        # Fast mode overrides for slow tools
        if [[ "${FAST_MODE:-false}" == true ]]; then
            case "$tool_path" in
                recon.amass|recon.gotator|content_discovery.feroxbuster|parameter_mining.arjun)
                    value="false"
                    ;;
                vulnerability.advanced.ssl_tls|vulnerability.advanced.request_smuggling)
                    value="false"
                    ;;
            esac
        fi
        
        RESOLVED_CONFIG["$key"]="$value"
    done
}

_resolve_runtime_params() {
    # Thread counts
    local threads_default=50
    local threads_aggressive=100
    local threads_passive=25
    
    if [[ -f "${CONFIG_FILE:-}" ]] && command -v yq &>/dev/null; then
        threads_default=$(yq -r '.global.threads.default // 50' "$CONFIG_FILE" 2>/dev/null)
        threads_aggressive=$(yq -r '.global.threads.aggressive // 100' "$CONFIG_FILE" 2>/dev/null)
        threads_passive=$(yq -r '.global.threads.passive // 25' "$CONFIG_FILE" 2>/dev/null)
    fi
    
    # Apply mode
    local effective_threads="$threads_default"
    if [[ "${AGGRESSIVE_MODE:-false}" == true ]]; then
        effective_threads="$threads_aggressive"
    elif [[ "${STEALTH_MODE:-false}" == true ]]; then
        effective_threads="$threads_passive"
    fi
    
    # CLI override
    [[ -n "${THREADS:-}" ]] && effective_threads="$THREADS"
    
    RESOLVED_CONFIG["runtime.threads"]="$effective_threads"
    
    # Rate limits
    local rate_default=50
    local rate_slow=10
    local rate_aggressive=150
    
    if [[ -f "${CONFIG_FILE:-}" ]] && command -v yq &>/dev/null; then
        rate_default=$(yq -r '.global.rate_limit.default // 50' "$CONFIG_FILE" 2>/dev/null)
        rate_slow=$(yq -r '.global.rate_limit.slow // 10' "$CONFIG_FILE" 2>/dev/null)
        rate_aggressive=$(yq -r '.global.rate_limit.aggressive // 150' "$CONFIG_FILE" 2>/dev/null)
    fi
    
    local effective_rate="$rate_default"
    if [[ "${AGGRESSIVE_MODE:-false}" == true ]]; then
        effective_rate="$rate_aggressive"
    elif [[ "${STEALTH_MODE:-false}" == true ]]; then
        effective_rate="$rate_slow"
    fi
    
    [[ -n "${RATE_LIMIT:-}" ]] && effective_rate="$RATE_LIMIT"
    
    RESOLVED_CONFIG["runtime.rate_limit"]="$effective_rate"
    
    # Timeouts
    RESOLVED_CONFIG["runtime.timeout.http"]=$(yq -r '.global.timeouts.http // 10' "${CONFIG_FILE:-/dev/null}" 2>/dev/null || echo "10")
    RESOLVED_CONFIG["runtime.timeout.tool"]=$(yq -r '.global.timeouts.tool_execution // 3600' "${CONFIG_FILE:-/dev/null}" 2>/dev/null || echo "3600")
}

# ============================================================================
# QUERY FUNCTIONS (Use these in modules)
# ============================================================================

# Check if a module is enabled (resolved)
resolved_is_module_enabled() {
    local module="$1"
    local key="module.${module}.enabled"
    
    # Ensure config is resolved
    [[ "$RESOLVED_CONFIG_READY" != true ]] && config_resolve_all
    
    local value="${RESOLVED_CONFIG[$key]:-true}"
    echo "$value"
}

# Check if a tool is enabled (resolved) - considers parent module too
resolved_is_tool_enabled() {
    local tool_path="$1"  # e.g., "vulnerability.sqli.sqlmap"
    
    # Ensure config is resolved
    [[ "$RESOLVED_CONFIG_READY" != true ]] && config_resolve_all
    
    # Extract parent module
    local parent_module="${tool_path%%.*}"
    
    # Check if parent module is enabled
    if [[ "${RESOLVED_CONFIG[module.${parent_module}.enabled]:-true}" == "false" ]]; then
        echo "false"
        return
    fi
    
    # Check tool itself
    local key="tool.${tool_path}.enabled"
    local value="${RESOLVED_CONFIG[$key]:-true}"
    echo "$value"
}

# Get resolved runtime parameter
resolved_get() {
    local key="$1"
    local default="${2:-}"
    
    [[ "$RESOLVED_CONFIG_READY" != true ]] && config_resolve_all
    
    echo "${RESOLVED_CONFIG[$key]:-$default}"
}

# ============================================================================
# STRICT ENFORCEMENT HELPERS
# ============================================================================

# Check tool and log skip reason (use this in modules)
should_run_tool_strict() {
    local module="$1"
    local tool="$2"
    local tool_path="${module}.${tool}"
    
    local enabled
    enabled=$(resolved_is_tool_enabled "$tool_path")
    
    if [[ "$enabled" == "false" ]]; then
        # Log the skip for reporting
        _record_tool_skip "$tool" "disabled_in_config"
        return 1
    fi
    
    return 0
}

# Record tool skip for reporting
_record_tool_skip() {
    local tool="$1"
    local reason="$2"
    
    local skip_file="${OUTPUT_BASE:-/tmp}/logs/skipped_tools.txt"
    mkdir -p "$(dirname "$skip_file")" 2>/dev/null || true
    
    echo "$(date -Iseconds) | $tool | $reason" >> "$skip_file" 2>/dev/null || true
}

# ============================================================================
# DEBUG
# ============================================================================

config_debug_resolved() {
    echo "=== RESOLVED CONFIGURATION ==="
    echo "Config file: ${CONFIG_FILE:-none}"
    echo "Fast mode: ${FAST_MODE:-false}"
    echo "Stealth mode: ${STEALTH_MODE:-false}"
    echo ""
    echo "Module states:"
    for key in "${!RESOLVED_CONFIG[@]}"; do
        if [[ "$key" == module.* ]]; then
            echo "  $key = ${RESOLVED_CONFIG[$key]}"
        fi
    done
    echo ""
    echo "Tool states:"
    for key in "${!RESOLVED_CONFIG[@]}"; do
        if [[ "$key" == tool.* ]]; then
            echo "  $key = ${RESOLVED_CONFIG[$key]}"
        fi
    done
    echo ""
    echo "Runtime:"
    for key in "${!RESOLVED_CONFIG[@]}"; do
        if [[ "$key" == runtime.* ]]; then
            echo "  $key = ${RESOLVED_CONFIG[$key]}"
        fi
    done
    echo "=============================="
}

# Export resolved config to environment (for subprocesses)
config_export_resolved() {
    [[ "$RESOLVED_CONFIG_READY" != true ]] && config_resolve_all
    
    export RESOLVED_THREADS="${RESOLVED_CONFIG[runtime.threads]}"
    export RESOLVED_RATE_LIMIT="${RESOLVED_CONFIG[runtime.rate_limit]}"
    
    # Export key tool states as env vars for shell modules
    export SQLMAP_ENABLED="${RESOLVED_CONFIG[tool.vulnerability.sqli.sqlmap.enabled]:-true}"
    export XSSTRIKE_ENABLED="${RESOLVED_CONFIG[tool.vulnerability.xss.xsstrike.enabled]:-false}"
    export NUCLEI_ENABLED="${RESOLVED_CONFIG[tool.vulnerability.nuclei.enabled]:-true}"
}
