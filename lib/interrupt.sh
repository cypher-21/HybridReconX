#!/usr/bin/env bash
# ============================================================================
# INTERRUPT HANDLER - Graceful Ctrl-C Handling
# ============================================================================
# Provides non-terminating interrupt handling for the recon pipeline.
# Ctrl-C stops the current tool but allows pipeline to continue.
# ============================================================================

# ============================================================================
# GLOBAL FLAGS
# ============================================================================
# Main interrupt flag - set when any interrupt occurs
export INTERRUPTED="${INTERRUPTED:-false}"

# Module-level flag - reset between modules
export MODULE_INTERRUPTED="${MODULE_INTERRUPTED:-false}"

# Tool-level flag - reset between tools
export TOOL_INTERRUPTED="${TOOL_INTERRUPTED:-false}"

# Current subprocess PID for targeted killing
export CURRENT_TOOL_PID="${CURRENT_TOOL_PID:-}"

# Interrupt count for double-ctrl-c force exit
export INTERRUPT_COUNT="${INTERRUPT_COUNT:-0}"

# Timestamp for debounce mechanism
export LAST_INTERRUPT_TIME="${LAST_INTERRUPT_TIME:-0}"

# ============================================================================
# INTERRUPT HANDLER (Called on SIGINT)
# ============================================================================
interrupt_handler() {
    local current_time=$(date +%s)
    local time_diff=$((current_time - LAST_INTERRUPT_TIME))
    
    # Debounce: If less than 2 seconds since last interrupt, treat as rapid presses
    if [[ $time_diff -lt 2 ]]; then
        ((INTERRUPT_COUNT++))
    else
        # Reset counter for new interrupt sequence
        INTERRUPT_COUNT=1
    fi
    
    LAST_INTERRUPT_TIME=$current_time
    INTERRUPTED=true
    MODULE_INTERRUPTED=true
    TOOL_INTERRUPTED=true
    
    # Force exit on triple Ctrl-C (within 2 seconds each)
    if [[ "$INTERRUPT_COUNT" -ge 3 ]]; then
        echo ""
        echo -e "\033[0;31m[!!!] Force exit requested (3x Ctrl-C)\033[0m"
        # Save checkpoint before force exit
        if type checkpoint_save &>/dev/null; then
            checkpoint_save "force_interrupted"
        fi
        exit 130
    fi
    
    # Double Ctrl-C warning
    if [[ "$INTERRUPT_COUNT" -ge 2 ]]; then
        echo ""
        echo -e "\033[1;33m[!] Press Ctrl-C once more to force exit entire pipeline\033[0m"
    fi
    
    # Kill current tool process if running
    if [[ -n "$CURRENT_TOOL_PID" ]]; then
        if kill -0 "$CURRENT_TOOL_PID" 2>/dev/null; then
            # Send SIGTERM first for graceful shutdown
            kill -TERM "$CURRENT_TOOL_PID" 2>/dev/null
            sleep 0.5
            # Force kill if still running
            if kill -0 "$CURRENT_TOOL_PID" 2>/dev/null; then
                kill -KILL "$CURRENT_TOOL_PID" 2>/dev/null
            fi
        fi
        CURRENT_TOOL_PID=""
    fi
    
    echo ""
    echo -e "\033[1;33m════════════════════════════════════════════════════════════════\033[0m"
    echo -e "\033[1;33m  INTERRUPT RECEIVED - Stopping current tool\033[0m"
    echo -e "\033[0;36m  • Current tool will be terminated\033[0m"
    echo -e "\033[0;36m  • Remaining items in this module will be skipped\033[0m"
    echo -e "\033[0;32m  • Pipeline will continue to the next module\033[0m"
    echo -e "\033[1;33m════════════════════════════════════════════════════════════════\033[0m"
    echo ""
    
    # Save partial status to checkpoint
    if type checkpoint_save &>/dev/null; then
        checkpoint_save "partial"
    fi
}

# ============================================================================
# MODULE INTERRUPT HANDLER (For use within modules)
# ============================================================================
module_interrupt_handler() {
    MODULE_INTERRUPTED=true
    TOOL_INTERRUPTED=true
    
    # Kill any current subprocess
    if [[ -n "$CURRENT_TOOL_PID" ]] && kill -0 "$CURRENT_TOOL_PID" 2>/dev/null; then
        kill -TERM "$CURRENT_TOOL_PID" 2>/dev/null
        CURRENT_TOOL_PID=""
    fi
    
    echo ""
    echo -e "\033[1;33m[!] Module interrupted - skipping remaining tasks\033[0m"
}

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

# Reset module interrupt flag (call before each module)
reset_module_interrupt() {
    MODULE_INTERRUPTED=false
    TOOL_INTERRUPTED=false
    CURRENT_TOOL_PID=""
    # Don't reset INTERRUPT_COUNT here - keep for force exit detection
}

# Reset tool interrupt flag (call before each tool)
reset_tool_interrupt() {
    TOOL_INTERRUPTED=false
    CURRENT_TOOL_PID=""
}

# Check if module should be skipped
is_module_interrupted() {
    [[ "$MODULE_INTERRUPTED" == "true" ]]
}

# Check if tool should be skipped
is_tool_interrupted() {
    [[ "$TOOL_INTERRUPTED" == "true" ]]
}

# Check if any interrupt has occurred
is_interrupted() {
    [[ "$INTERRUPTED" == "true" || "$MODULE_INTERRUPTED" == "true" ]]
}

# Reset all interrupt flags (use with caution, mainly for testing)
reset_all_interrupts() {
    INTERRUPTED=false
    MODULE_INTERRUPTED=false
    TOOL_INTERRUPTED=false
    CURRENT_TOOL_PID=""
    INTERRUPT_COUNT=0
}

# ============================================================================
# SAFE COMMAND EXECUTION
# ============================================================================
# Run a command with interrupt handling
# Usage: run_interruptible command arg1 arg2 ...
run_interruptible() {
    # Skip if already interrupted
    if is_module_interrupted; then
        return 130
    fi
    
    # Run command in background and capture PID
    "$@" &
    CURRENT_TOOL_PID=$!
    
    # Wait for command to finish
    wait $CURRENT_TOOL_PID
    local exit_code=$?
    
    CURRENT_TOOL_PID=""
    
    # Check if killed by signal
    if [[ $exit_code -eq 130 || $exit_code -eq 137 || $exit_code -eq 143 ]]; then
        TOOL_INTERRUPTED=true
        return $exit_code
    fi
    
    return $exit_code
}

# Execute command with timeout and interrupt support
# Usage: run_with_timeout timeout_seconds command arg1 arg2 ...
run_with_timeout() {
    local timeout="$1"
    shift
    
    if is_module_interrupted; then
        return 130
    fi
    
    # Use timeout command with background process
    timeout --signal=TERM --kill-after=10 "$timeout" "$@" &
    CURRENT_TOOL_PID=$!
    
    wait $CURRENT_TOOL_PID
    local exit_code=$?
    
    CURRENT_TOOL_PID=""
    
    if [[ $exit_code -eq 124 ]]; then
        echo "[TIMEOUT] Command timed out after ${timeout}s"
    fi
    
    return $exit_code
}

# ============================================================================
# LOOP HELPERS
# ============================================================================
# Check before processing each target in a loop
# Usage: should_continue || break
should_continue() {
    ! is_module_interrupted
}

# Get interrupt status for reporting
get_interrupt_status() {
    if [[ "$MODULE_INTERRUPTED" == "true" ]]; then
        echo "interrupted"
    elif [[ "$INTERRUPTED" == "true" ]]; then
        echo "partial"
    else
        echo "complete"
    fi
}

# ============================================================================
# INSTALL HANDLERS
# ============================================================================
# Install the global interrupt handler (call in orchestrator)
install_global_handler() {
    trap 'interrupt_handler' SIGINT
    trap '' SIGPIPE  # Ignore SIGPIPE to prevent broken pipe crashes
}

# Install module-level handler (call at start of each module)
install_module_handler() {
    trap 'module_interrupt_handler' SIGINT
}

# Restore default signal handling
restore_handlers() {
    trap - SIGINT SIGPIPE
}
