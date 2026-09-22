#!/usr/bin/env bash
# ============================================================================
# CHECKPOINT MANAGER - Robust Resume System
# ============================================================================
# Provides automatic checkpointing and resume functionality
# State is saved inside the output directory as .checkpoint.json
# ============================================================================

# Checkpoint file path (set by checkpoint_init or checkpoint_load)
CHECKPOINT_FILE=""
CHECKPOINT_DATA=""

# ============================================================================
# CORE FUNCTIONS
# ============================================================================

# Initialize a new checkpoint for a fresh scan
checkpoint_init() {
    local output_base="$1"
    local target="$2"
    
    CHECKPOINT_FILE="${output_base}/.checkpoint.json"
    
    local now
    now=$(date -Iseconds)
    
    # Create initial checkpoint with v2.0 format
    cat > "$CHECKPOINT_FILE" << EOF
{
    "version": "2.0",
    "target": "${target}",
    "output_base": "${output_base}",
    "started_at": "${now}",
    "updated_at": "${now}",
    "status": "running",
    "current_phase": {
        "module": "",
        "module_index": 0,
        "tool": "",
        "tool_index": 0,
        "target_index": 0,
        "total_targets": 0
    },
    "completed_modules": [],
    "completed_tools": {},
    "interrupted_modules": {},
    "module_progress": {},
    "config": {
        "fast_mode": ${FAST_MODE:-false},
        "stealth_mode": ${STEALTH_MODE:-false},
        "aggressive_mode": ${AGGRESSIVE_MODE:-false}
    }
}
EOF
    
    log INFO "Checkpoint initialized (v2.0): $CHECKPOINT_FILE"
}

# Find existing checkpoint for a target
# Returns the checkpoint file path or empty string
checkpoint_find() {
    local target_name="$1"
    # Sanitize target name
    target_name=$(echo "$target_name" | sed 's/[^a-zA-Z0-9._-]/_/g')
    
    local checkpoint_file="${SCRIPT_DIR}/output/${target_name}/.checkpoint.json"
    
    if [[ -f "$checkpoint_file" ]]; then
        # Verify it's a valid checkpoint (status != completed)
        local status
        status=$(jq -r '.status // "unknown"' "$checkpoint_file" 2>/dev/null)
        if [[ "$status" != "completed" ]]; then
            echo "$checkpoint_file"
            return 0
        fi
    fi
    
    return 1
}

# Load checkpoint from file
checkpoint_load() {
    local checkpoint_file="$1"
    
    if [[ ! -f "$checkpoint_file" ]]; then
        return 1
    fi
    
    CHECKPOINT_FILE="$checkpoint_file"
    
    # Extract values
    OUTPUT_BASE=$(jq -r '.output_base // ""' "$CHECKPOINT_FILE")
    FAST_MODE=$(jq -r '.config.fast_mode // false' "$CHECKPOINT_FILE")
    STEALTH_MODE=$(jq -r '.config.stealth_mode // false' "$CHECKPOINT_FILE")
    AGGRESSIVE_MODE=$(jq -r '.config.aggressive_mode // false' "$CHECKPOINT_FILE")
    
    log SUCCESS "Checkpoint loaded: $CHECKPOINT_FILE"
    return 0
}

# Save current state (called frequently)
checkpoint_save() {
    local status="${1:-running}"
    
    if [[ -z "$CHECKPOINT_FILE" || ! -f "$CHECKPOINT_FILE" ]]; then
        return 1
    fi
    
    local now
    now=$(date -Iseconds)
    
    # Update the checkpoint file using jq
    local tmp_file="${CHECKPOINT_FILE}.tmp"
    
    jq --arg status "$status" \
       --arg now "$now" \
       --arg module "${CURRENT_MODULE:-}" \
       --arg tool "${CURRENT_TOOL:-}" \
       '.status = $status | .updated_at = $now | .current_phase.module = $module | .current_phase.tool = $tool' \
       "$CHECKPOINT_FILE" > "$tmp_file" && mv "$tmp_file" "$CHECKPOINT_FILE"
    
    if [[ "$status" == "interrupted" ]]; then
        echo ""
        log WARN "═══════════════════════════════════════════════════"
        log WARN "  CHECKPOINT SAVED - Scan can be resumed"
        log WARN "  File: $CHECKPOINT_FILE"
        log WARN "  Module: ${CURRENT_MODULE:-none}"
        log WARN "  Tool: ${CURRENT_TOOL:-none}"
        log WARN "═══════════════════════════════════════════════════"
    fi
}

# Mark module as started
checkpoint_module_start() {
    local module_name="$1"
    local module_index="${2:-0}"
    
    CURRENT_MODULE="$module_name"
    CURRENT_TOOL=""
    
    if [[ -z "$CHECKPOINT_FILE" || ! -f "$CHECKPOINT_FILE" ]]; then
        return
    fi
    
    local tmp_file="${CHECKPOINT_FILE}.tmp"
    jq --arg module "$module_name" \
       --argjson idx "$module_index" \
       '.current_phase.module = $module | .current_phase.module_index = $idx | .current_phase.tool = "" | .current_phase.tool_index = 0' \
       "$CHECKPOINT_FILE" > "$tmp_file" && mv "$tmp_file" "$CHECKPOINT_FILE"
}

# Mark module as completed
checkpoint_module_done() {
    local module_name="$1"
    
    if [[ -z "$CHECKPOINT_FILE" || ! -f "$CHECKPOINT_FILE" ]]; then
        return
    fi
    
    local tmp_file="${CHECKPOINT_FILE}.tmp"
    jq --arg module "$module_name" \
       '.completed_modules += [$module] | .completed_modules = (.completed_modules | unique)' \
       "$CHECKPOINT_FILE" > "$tmp_file" && mv "$tmp_file" "$CHECKPOINT_FILE"
    
    LAST_COMPLETED_MODULE="$module_name"
}

# Mark module as interrupted/partial (still allows next module to run)
checkpoint_mark_interrupted() {
    local module_name="${1:-$CURRENT_MODULE}"
    local status="${2:-partial}"
    
    if [[ -z "$CHECKPOINT_FILE" || ! -f "$CHECKPOINT_FILE" ]]; then
        return
    fi
    
    local now
    now=$(date -Iseconds)
    
    local tmp_file="${CHECKPOINT_FILE}.tmp"
    jq --arg module "$module_name" \
       --arg status "$status" \
       --arg now "$now" \
       '.interrupted_modules = ((.interrupted_modules // {}) + {($module): $status}) | .updated_at = $now | .status = "partial"' \
       "$CHECKPOINT_FILE" > "$tmp_file" && mv "$tmp_file" "$CHECKPOINT_FILE"
    
    log WARN "Module marked as $status: $module_name"
}

# Check if module was interrupted (for resume logic)
checkpoint_is_module_interrupted() {
    local module_name="$1"
    
    if [[ -z "$CHECKPOINT_FILE" || ! -f "$CHECKPOINT_FILE" ]]; then
        return 1
    fi
    
    local status
    status=$(jq -r --arg m "$module_name" '.interrupted_modules[$m] // ""' "$CHECKPOINT_FILE" 2>/dev/null)
    
    [[ -n "$status" && "$status" != "null" ]]
}

# Check if module is already completed
checkpoint_is_module_done() {
    local module_name="$1"
    
    if [[ -z "$CHECKPOINT_FILE" || ! -f "$CHECKPOINT_FILE" ]]; then
        return 1
    fi
    
    local is_done
    is_done=$(jq -r --arg m "$module_name" '.completed_modules | index($m) != null' "$CHECKPOINT_FILE" 2>/dev/null)
    
    [[ "$is_done" == "true" ]]
}

# Mark tool as started
checkpoint_tool_start() {
    local tool_name="$1"
    local tool_index="${2:-0}"
    
    CURRENT_TOOL="$tool_name"
    
    if [[ -z "$CHECKPOINT_FILE" || ! -f "$CHECKPOINT_FILE" ]]; then
        return
    fi
    
    local tmp_file="${CHECKPOINT_FILE}.tmp"
    jq --arg tool "$tool_name" \
       --argjson idx "$tool_index" \
       '.current_phase.tool = $tool | .current_phase.tool_index = $idx' \
       "$CHECKPOINT_FILE" > "$tmp_file" && mv "$tmp_file" "$CHECKPOINT_FILE"
}

# Mark tool as completed
checkpoint_tool_done() {
    local module_name="${1:-$CURRENT_MODULE}"
    local tool_name="${2:-$CURRENT_TOOL}"
    
    if [[ -z "$CHECKPOINT_FILE" || ! -f "$CHECKPOINT_FILE" ]]; then
        return
    fi
    
    local tmp_file="${CHECKPOINT_FILE}.tmp"
    jq --arg module "$module_name" \
       --arg tool "$tool_name" \
       '.completed_tools[$module] = ((.completed_tools[$module] // []) + [$tool] | unique)' \
       "$CHECKPOINT_FILE" > "$tmp_file" && mv "$tmp_file" "$CHECKPOINT_FILE"
    
    CURRENT_TOOL=""
}

# Check if tool is already completed
checkpoint_is_tool_done() {
    local module_name="$1"
    local tool_name="$2"
    
    if [[ -z "$CHECKPOINT_FILE" || ! -f "$CHECKPOINT_FILE" ]]; then
        return 1
    fi
    
    local is_done
    is_done=$(jq -r --arg m "$module_name" --arg t "$tool_name" \
        '(.completed_tools[$m] // []) | index($t) != null' "$CHECKPOINT_FILE" 2>/dev/null)
    
    [[ "$is_done" == "true" ]]
}

# Clear checkpoint on successful completion
checkpoint_clear() {
    if [[ -n "$CHECKPOINT_FILE" && -f "$CHECKPOINT_FILE" ]]; then
        # Mark as completed instead of deleting
        local tmp_file="${CHECKPOINT_FILE}.tmp"
        jq '.status = "completed"' "$CHECKPOINT_FILE" > "$tmp_file" && mv "$tmp_file" "$CHECKPOINT_FILE"
        log INFO "Scan completed successfully - checkpoint marked as complete"
    fi
}

# Get list of completed modules
checkpoint_get_completed_modules() {
    if [[ -z "$CHECKPOINT_FILE" || ! -f "$CHECKPOINT_FILE" ]]; then
        echo ""
        return
    fi
    
    jq -r '.completed_modules[]' "$CHECKPOINT_FILE" 2>/dev/null
}

# Get current module from checkpoint
checkpoint_get_current_module() {
    if [[ -z "$CHECKPOINT_FILE" || ! -f "$CHECKPOINT_FILE" ]]; then
        echo ""
        return
    fi
    
    jq -r '.current_phase.module // ""' "$CHECKPOINT_FILE" 2>/dev/null
}

# ============================================================================
# TARGET-LEVEL TRACKING (v2.0)
# ============================================================================

# Save current position within a module (for resume)
checkpoint_save_position() {
    local module_name="${1:-$CURRENT_MODULE}"
    local tool_name="${2:-$CURRENT_TOOL}"
    local target_index="${3:-0}"
    local total_targets="${4:-0}"
    
    if [[ -z "$CHECKPOINT_FILE" || ! -f "$CHECKPOINT_FILE" ]]; then
        return
    fi
    
    local now
    now=$(date -Iseconds)
    
    local tmp_file="${CHECKPOINT_FILE}.tmp"
    jq --arg module "$module_name" \
       --arg tool "$tool_name" \
       --argjson idx "$target_index" \
       --argjson total "$total_targets" \
       --arg now "$now" \
       '.current_phase.module = $module | 
        .current_phase.tool = $tool | 
        .current_phase.target_index = $idx | 
        .current_phase.total_targets = $total |
        .updated_at = $now |
        .module_progress[$module] = {"tool": $tool, "target_index": $idx, "total": $total}' \
       "$CHECKPOINT_FILE" > "$tmp_file" && mv "$tmp_file" "$CHECKPOINT_FILE"
}

# Get saved position for a module (for resume)
checkpoint_get_position() {
    local module_name="$1"
    
    if [[ -z "$CHECKPOINT_FILE" || ! -f "$CHECKPOINT_FILE" ]]; then
        echo "0"
        return
    fi
    
    jq -r --arg m "$module_name" '.module_progress[$m].target_index // 0' "$CHECKPOINT_FILE" 2>/dev/null || echo "0"
}

# Get saved tool for a module (for resume)
checkpoint_get_tool_position() {
    local module_name="$1"
    
    if [[ -z "$CHECKPOINT_FILE" || ! -f "$CHECKPOINT_FILE" ]]; then
        echo ""
        return
    fi
    
    jq -r --arg m "$module_name" '.module_progress[$m].tool // ""' "$CHECKPOINT_FILE" 2>/dev/null || echo ""
}

# Check if we should skip to a specific index (resume mode)
checkpoint_should_skip_to() {
    local module_name="$1"
    local current_index="$2"
    
    if [[ -z "$CHECKPOINT_FILE" || ! -f "$CHECKPOINT_FILE" ]]; then
        return 1  # Don't skip
    fi
    
    local saved_index
    saved_index=$(checkpoint_get_position "$module_name")
    
    if [[ "$current_index" -lt "$saved_index" ]]; then
        return 0  # Skip this target
    fi
    
    return 1  # Process this target
}

# Update module progress (call periodically during long operations)
checkpoint_update_progress() {
    local module_name="${1:-$CURRENT_MODULE}"
    local current_index="${2:-0}"
    local total="${3:-0}"
    local status="${4:-running}"
    
    if [[ -z "$CHECKPOINT_FILE" || ! -f "$CHECKPOINT_FILE" ]]; then
        return
    fi
    
    local tmp_file="${CHECKPOINT_FILE}.tmp"
    jq --arg m "$module_name" \
       --argjson idx "$current_index" \
       --argjson total "$total" \
       --arg status "$status" \
       '.module_progress[$m].target_index = $idx | 
        .module_progress[$m].total = $total |
        .module_progress[$m].status = $status' \
       "$CHECKPOINT_FILE" > "$tmp_file" && mv "$tmp_file" "$CHECKPOINT_FILE"
}
