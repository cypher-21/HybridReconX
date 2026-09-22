#!/usr/bin/env bash
# ============================================================================
# HYBRIDRECON X - Local Installation Script
# ============================================================================
# Installs dependencies for running HybridRecon X without Docker.
# For Docker usage, simply run: docker build -t hybridrecon-x .
# ============================================================================
# Made By Parosh
# ============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[INSTALL]${NC} $*"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

error() {
    echo -e "${RED}[ERROR]${NC} $*"
    exit 1
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root (use sudo)"
    fi
}

check_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$ID
        log "Detected OS: $PRETTY_NAME"
    else
        error "Cannot detect OS. This script supports Debian/Ubuntu/Kali."
    fi
}

install_go() {
    if command -v go &>/dev/null; then
        log "Go already installed: $(go version)"
        return
    fi
    
    log "Installing Go 1.22..."
    wget -q https://go.dev/dl/go1.22.4.linux-amd64.tar.gz -O /tmp/go.tar.gz
    tar -C /usr/local -xzf /tmp/go.tar.gz
    rm /tmp/go.tar.gz
    
    # Add to system PATH for all users
    echo 'export GOROOT=/usr/local/go' > /etc/profile.d/go.sh
    echo 'export PATH=$PATH:/usr/local/go/bin:/usr/local/bin:$HOME/go/bin' >> /etc/profile.d/go.sh
    source /etc/profile.d/go.sh
    
    log "Go installed: $(go version)"
}

install_system_deps() {
    log "Installing system dependencies..."
    apt-get update
    apt-get install -y --no-install-recommends \
        git curl wget unzip jq \
        python3 python3-pip python3-dev \
        ruby ruby-dev \
        build-essential \
        dnsutils nmap \
        libpcap-dev libcurl4-openssl-dev libssl-dev
}

install_go_tools() {
    log "Installing Go-based tools..."
    
    export GOPATH=${GOPATH:-$HOME/go}
    export GOBIN=/usr/local/bin
    export PATH=$PATH:/usr/local/go/bin:$GOBIN:$GOPATH/bin
    
    tools=(
        "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        "github.com/projectdiscovery/httpx/cmd/httpx@latest"
        "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        "github.com/projectdiscovery/katana/cmd/katana@latest"
        "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
        "github.com/projectdiscovery/tlsx/cmd/tlsx@latest"
        "github.com/ffuf/ffuf/v2@latest"
        "github.com/tomnomnom/assetfinder@latest"
        "github.com/tomnomnom/waybackurls@latest"
        "github.com/tomnomnom/gf@latest"
        "github.com/tomnomnom/qsreplace@latest"
        "github.com/tomnomnom/anew@latest"
        "github.com/lc/gau/v2/cmd/gau@latest"
        "github.com/hakluke/hakrawler@latest"
        "github.com/hahwul/dalfox/v2@latest"
        "github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest"
        "github.com/pwnesia/dnstake/cmd/dnstake@latest"
        "github.com/Josue87/gotator@latest"
        "github.com/zricethezav/gitleaks/v8@latest"
    )
    
    for tool in "${tools[@]}"; do
        name=$(basename "$tool" | cut -d@ -f1)
        log "  Installing $name..."
        go install -v "$tool" 2>/dev/null || warn "Failed: $name"
    done

    # Ensure all binaries are copied to /usr/local/bin so any non-root user can run them
    if [[ -d "$GOPATH/bin" ]]; then
        cp -f "$GOPATH/bin"/* /usr/local/bin/ 2>/dev/null || true
    fi
}

install_python_tools() {
    log "Installing Python tools..."
    
    pip3 install --break-system-packages \
        wafw00f arjun paramspider ghauri \
        pyyaml requests jinja2 colorama rich \
        2>/dev/null || pip3 install wafw00f arjun pyyaml requests
}

install_wordlists() {
    log "Installing wordlists..."
    
    mkdir -p /opt/wordlists /opt/resolvers
    
    if [[ ! -d /opt/wordlists/SecLists ]]; then
        git clone --depth 1 https://github.com/danielmiessler/SecLists /opt/wordlists/SecLists
    fi
    
    # Resolvers
    wget -q https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt \
        -O /opt/resolvers/trusted.txt || echo "8.8.8.8\n1.1.1.1" > /opt/resolvers/trusted.txt
}

update_nuclei_templates() {
    log "Updating Nuclei templates..."
    nuclei -update-templates -silent || true
}

setup_gf_patterns() {
    log "Setting up GF patterns..."
    mkdir -p ~/.gf
    git clone --depth 1 https://github.com/1ndianl33t/Gf-Patterns /tmp/gf-patterns 2>/dev/null || true
    cp /tmp/gf-patterns/*.json ~/.gf/ 2>/dev/null || true
    rm -rf /tmp/gf-patterns
}

make_executable() {
    log "Making scripts executable..."
    chmod +x hybrid_x.sh 2>/dev/null || true
    chmod +x modules/*.sh 2>/dev/null || true
    chmod +x modules/*.py 2>/dev/null || true
}

print_summary() {
    echo ""
    echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}    HYBRIDRECON X - Installation Complete!${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  Run a scan:  ${YELLOW}./hybrid_x.sh -d target.com${NC}"
    echo -e "  Check tools: ${YELLOW}./hybrid_x.sh --check-tools${NC}"
    echo -e "  Get help:    ${YELLOW}./hybrid_x.sh --help${NC}"
    echo ""
    echo -e "  ${CYAN}Made By Parosh${NC}"
    echo ""
}

main() {
    echo ""
    echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}    HYBRIDRECON X - Local Installer${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
    echo ""
    
    check_root
    check_os
    
    install_system_deps
    install_go
    install_go_tools
    install_python_tools
    install_wordlists
    update_nuclei_templates
    setup_gf_patterns
    make_executable
    
    print_summary
}

# Parse arguments
case "${1:-}" in
    --help|-h)
        echo "Usage: sudo ./install.sh [OPTIONS]"
        echo ""
        echo "Options:"
        echo "  --help        Show this help"
        echo "  --go-only     Install only Go tools"
        echo "  --python-only Install only Python tools"
        exit 0
        ;;
    --go-only)
        install_go
        install_go_tools
        exit 0
        ;;
    --python-only)
        install_python_tools
        exit 0
        ;;
    *)
        main
        ;;
esac
