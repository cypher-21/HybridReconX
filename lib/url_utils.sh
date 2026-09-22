#!/usr/bin/env bash
# ============================================================================
# URL UTILITIES - Sanitization and normalization for HybridRecon X
# ============================================================================

# Normalize URL - remove dangerous characters, truncate length
normalize_url() {
    local url="$1"
    echo "$url" | \
        sed 's/%0[aAdD]//g' | \
        sed 's/[\r\n]//g' | \
        tr -d '\000-\011\013-\037' | \
        head -c 2000
}

# Escape string for use in sed replacement
# Handles: & / \ [ ] . * ^ $ and backslashes
escape_for_sed() {
    local str="$1"
    # Escape backslash first, then other special characters
    printf '%s\n' "$str" | sed -e 's/\\/\\\\/g' -e 's/[&/\[\].*^$]/\\&/g'
}

# Escape string for use in sed pattern (left side)
escape_for_sed_pattern() {
    local str="$1"
    printf '%s\n' "$str" | sed -e 's/[]\/$*.^[]/\\&/g'
}

# Sanitize URL for use with security tools
# Removes potentially problematic characters that can break tools
sanitize_url_for_tool() {
    local url="$1"
    # Remove CRLF, null bytes, and control characters
    echo "$url" | \
        tr -d '\000-\011\013-\037' | \
        sed 's/%0[aAdD]//g' | \
        sed 's/[\r\n]//g' | \
        head -c 2000
}

# Validate URL format and reachability
validate_url() {
    local url="$1"
    local timeout="${2:-5}"
    
    # Check format
    if [[ ! "$url" =~ ^https?:// ]]; then
        return 1
    fi
    
    # Check reachability (optional - returns 0 even if unreachable for speed)
    if [[ "${VALIDATE_REACHABILITY:-false}" == "true" ]]; then
        local status
        status=$(curl -s -o /dev/null -w "%{http_code}" --max-time "$timeout" "$url" 2>/dev/null)
        [[ "$status" =~ ^[23] ]] || return 2
    fi
    
    return 0
}

# Extract domain from URL
get_domain() {
    local url="$1"
    echo "$url" | sed -E 's|^https?://||' | sed -E 's|/.*||' | sed 's/:.*$//'
}

# Create safe filename from URL
url_to_filename() {
    local url="$1"
    local max_len="${2:-50}"
    echo "$url" | sed 's/[^a-zA-Z0-9]/_/g' | cut -c1-"$max_len"
}

# URL encode special characters
url_encode() {
    local str="$1"
    python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1], safe=''))" "$str" 2>/dev/null || echo "$str"
}

# URL decode
url_decode() {
    local str="$1"
    python3 -c "import urllib.parse,sys; print(urllib.parse.unquote(sys.argv[1]))" "$str" 2>/dev/null || echo "$str"
}

# Clean URL list - remove duplicates, empty lines, invalid entries
clean_url_list() {
    local input_file="$1"
    local output_file="${2:-$input_file}"
    
    if [[ ! -f "$input_file" ]]; then
        return 1
    fi
    
    grep -E '^https?://' "$input_file" 2>/dev/null | \
        sed 's/[\r\n]//g' | \
        sort -u > "${output_file}.tmp"
    
    mv "${output_file}.tmp" "$output_file"
}
