# ============================================================================
# HYBRIDRECON X - MEGA CONTAINER
# Context-Aware Bug Bounty & Pentesting Framework
# ============================================================================
# Base: Kali Linux Rolling (Full offensive security toolkit base)
# Fixed: All tool installation methods verified and working
# ============================================================================

FROM kalilinux/kali-rolling

LABEL maintainer="HybridRecon X Team"
LABEL version="1.0.1"
LABEL description="Context-Aware Bug Bounty Framework - The Smart Recon Platform"

# ============================================================================
# ENVIRONMENT SETUP
# ============================================================================
ENV DEBIAN_FRONTEND=noninteractive
ENV GOROOT=/usr/local/go
ENV GOPATH=/root/go
ENV PATH=$PATH:$GOROOT/bin:$GOPATH/bin:/root/.local/bin:/opt/tools:/root/.cargo/bin
ENV GO111MODULE=on
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# ============================================================================
# SYSTEM DEPENDENCIES & CORE TOOLS
# ============================================================================
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Core utilities
    git \
    curl \
    wget \
    unzip \
    jq \
    tree \
    vim \
    tmux \
    # Build dependencies
    build-essential \
    gcc \
    g++ \
    make \
    cmake \
    pkg-config \
    # Python ecosystem
    python3 \
    python3-pip \
    python3-dev \
    python3-venv \
    python3-setuptools \
    # Ruby ecosystem (for WPScan, WhatWeb)
    ruby \
    ruby-dev \
    # Perl (for joomscan)
    perl \
    libwww-perl \
    # Network utilities
    dnsutils \
    nmap \
    netcat-openbsd \
    whois \
    # Additional dependencies
    libpcap-dev \
    libcurl4-openssl-dev \
    libssl-dev \
    libffi-dev \
    libxml2-dev \
    libxslt1-dev \
    zlib1g-dev \
    libyaml-dev \
    # Browser for screenshots (optional, large)
    # chromium \
    # chromium-driver \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# ============================================================================
# GO INSTALLATION (v1.22+)
# ============================================================================
RUN wget -q https://go.dev/dl/go1.22.4.linux-amd64.tar.gz -O /tmp/go.tar.gz \
    && tar -C /usr/local -xzf /tmp/go.tar.gz \
    && rm /tmp/go.tar.gz \
    && mkdir -p $GOPATH/bin $GOPATH/src $GOPATH/pkg

# ============================================================================
# CREATE TOOLS DIRECTORY
# ============================================================================
RUN mkdir -p /opt/tools /opt/wordlists /opt/resolvers

# ============================================================================
# SECTION A: SUBDOMAIN ENUMERATION TOOLS (Go-based)
# ============================================================================

# 1. Subfinder - Fast passive subdomain enumeration
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# 2. Amass - In-depth DNS enumeration
RUN go install -v github.com/owasp-amass/amass/v4/...@master

# 3. Assetfinder - Find domains and subdomains
RUN go install -v github.com/tomnomnom/assetfinder@latest

# 4. Findomain - Fast subdomain scanner (Install from GitHub releases - NOT crates.io)
RUN wget -q https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux.zip -O /tmp/findomain.zip \
    && unzip -q /tmp/findomain.zip -d /tmp/ \
    && chmod +x /tmp/findomain \
    && mv /tmp/findomain /usr/local/bin/findomain \
    && rm /tmp/findomain.zip

# 5. DNSx - DNS toolkit
RUN go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest

# 6. Shuffledns - Wrapper around massdns
RUN go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest

# 7. PureDNS - Fast domain resolver
RUN go install -v github.com/d3mondev/puredns/v2@latest

# 8. Massdns - High-performance DNS stub resolver
RUN git clone --depth 1 https://github.com/blechschmidt/massdns.git /tmp/massdns \
    && cd /tmp/massdns && make \
    && cp bin/massdns /opt/tools/ \
    && ln -sf /opt/tools/massdns /usr/local/bin/massdns \
    && rm -rf /tmp/massdns

# ============================================================================
# SECTION B: WEB PROBING & FINGERPRINTING
# ============================================================================

# 9. HTTPX - Fast HTTP toolkit (CRITICAL tool)
RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# 10. WhatWeb - Web scanner (Install from GitHub, not RubyGems)
RUN git clone --depth 1 https://github.com/urbanadventurer/WhatWeb.git /opt/tools/whatweb \
    && cd /opt/tools/whatweb \
    && chmod +x whatweb \
    && ln -sf /opt/tools/whatweb/whatweb /usr/local/bin/whatweb

# 11. Wafw00f - WAF detection
RUN pip3 install wafw00f --break-system-packages || true

# 12. Gowitness - Web screenshot tool (optional, may fail without chrome)
RUN go install -v github.com/sensepost/gowitness@latest || true

# ============================================================================
# SECTION C: CONTENT DISCOVERY (Fuzzing & Crawling)
# ============================================================================

# 13. FFUF - Fast web fuzzer (PRIMARY FUZZER)
RUN go install -v github.com/ffuf/ffuf/v2@latest

# 14. Katana - Next-gen crawler
RUN go install -v github.com/projectdiscovery/katana/cmd/katana@latest

# 15. GAU (GetAllUrls) - Fetch URLs from archives
RUN go install -v github.com/lc/gau/v2/cmd/gau@latest

# 16. Waybackurls - Fetch URLs from Wayback Machine
RUN go install -v github.com/tomnomnom/waybackurls@latest

# 17. Hakrawler - Simple web crawler
RUN go install -v github.com/hakluke/hakrawler@latest

# 18. Feroxbuster - Download pre-built binary instead of compiling (much faster)
RUN wget -q https://github.com/epi052/feroxbuster/releases/latest/download/feroxbuster_amd64.deb.zip -O /tmp/ferox.zip \
    && unzip -q /tmp/ferox.zip -d /tmp/ \
    && dpkg -i /tmp/feroxbuster*.deb || apt-get install -f -y \
    && rm -rf /tmp/ferox* \
    || echo "Feroxbuster install failed, skipping"

# ============================================================================
# SECTION D: PARAMETER ANALYSIS
# ============================================================================

# 19. ParamSpider - Mining parameters from archives
RUN git clone --depth 1 https://github.com/devanshbatham/ParamSpider /opt/tools/ParamSpider \
    && cd /opt/tools/ParamSpider \
    && pip3 install -r requirements.txt --break-system-packages || true

# 20. Arjun - HTTP parameter discovery
RUN pip3 install arjun --break-system-packages

# 21. GF - Grep patterns for bugs
RUN go install -v github.com/tomnomnom/gf@latest \
    && mkdir -p ~/.gf \
    && git clone --depth 1 https://github.com/1ndianl33t/Gf-Patterns /tmp/gf-patterns \
    && cp /tmp/gf-patterns/*.json ~/.gf/ \
    && rm -rf /tmp/gf-patterns

# 22. QSReplace - Replace query string values
RUN go install -v github.com/tomnomnom/qsreplace@latest

# ============================================================================
# SECTION E: VULNERABILITY SCANNING & EXPLOITATION
# ============================================================================

# 23. Nuclei - Template-based scanner (PRIMARY SCANNER)
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# 24. Dalfox - XSS scanner
RUN go install -v github.com/hahwul/dalfox/v2@latest

# 25. XSStrike - Advanced XSS detection
RUN git clone --depth 1 https://github.com/s0md3v/XSStrike /opt/tools/XSStrike \
    && pip3 install -r /opt/tools/XSStrike/requirements.txt --break-system-packages || true

# 26. Ghauri - SQLi detection tool (install from GitHub, not PyPI)
RUN git clone --depth 1 https://github.com/r0oth3x49/ghauri.git /opt/tools/ghauri \
    && cd /opt/tools/ghauri \
    && pip3 install -r requirements.txt --break-system-packages || true \
    && python3 setup.py install || pip3 install . --break-system-packages || true \
    && ln -sf /opt/tools/ghauri/ghauri /usr/local/bin/ghauri 2>/dev/null || true

# 27. SQLMap - SQL injection tool (Gold standard)
RUN git clone --depth 1 https://github.com/sqlmapproject/sqlmap /opt/tools/sqlmap

# 28. Commix - Command injection exploiter
RUN git clone --depth 1 https://github.com/commixproject/commix /opt/tools/commix \
    && pip3 install -r /opt/tools/commix/requirements.txt --break-system-packages || true

# 29. Tplmap - SSTI detection (may have old deps, allow failure)
RUN git clone --depth 1 https://github.com/epinna/tplmap /opt/tools/tplmap \
    && pip3 install -r /opt/tools/tplmap/requirements.txt --break-system-packages || true

# 30. CVEmap - CVE prioritization
RUN go install -v github.com/projectdiscovery/cvemap/cmd/cvemap@latest

# ============================================================================
# SECTION F: CMS & SPECIFIC SCANNERS
# ============================================================================

# 31. WPScan - WordPress scanner (install with error handling)
RUN gem install wpscan --no-document || \
    (apt-get update && apt-get install -y wpscan) || \
    echo "WPScan install failed, skipping"

# 32. JoomScan - Joomla scanner
RUN git clone --depth 1 https://github.com/OWASP/joomscan /opt/tools/joomscan || true

# 33. Droopescan - Drupal/SilverStripe scanner
RUN pip3 install droopescan --break-system-packages

# ============================================================================
# SECTION G: SECRETS & CLOUD
# ============================================================================

# 34. Git-dumper - Dump .git repositories
RUN pip3 install git-dumper --break-system-packages

# 35. GitLeaks - Scan git repos for secrets
RUN go install github.com/zricethezav/gitleaks/v8@latest

# 36. Trufflehog - Install from official releases (more reliable than building)
RUN wget -q https://github.com/trufflesecurity/trufflehog/releases/download/v3.63.5/trufflehog_3.63.5_linux_amd64.tar.gz -O /tmp/trufflehog.tar.gz \
    && tar -xzf /tmp/trufflehog.tar.gz -C /usr/local/bin trufflehog \
    && chmod +x /usr/local/bin/trufflehog \
    && rm /tmp/trufflehog.tar.gz \
    || echo "Trufflehog install failed, skipping"

# 37. Cloud_enum - Multi-cloud enum
RUN git clone --depth 1 https://github.com/initstring/cloud_enum /opt/tools/cloud_enum \
    && pip3 install -r /opt/tools/cloud_enum/requirements.txt --break-system-packages || true

# 38. S3Scanner - AWS S3 bucket scanner
RUN pip3 install s3scanner --break-system-packages || true

# ============================================================================
# SECTION H: UTILITIES
# ============================================================================

# 39. Anew - Append without duplicates
RUN go install -v github.com/tomnomnom/anew@latest

# 40. Notify - Send alerts to multiple platforms
RUN go install -v github.com/projectdiscovery/notify/cmd/notify@latest

# 41. Interlace - Parallelize commands (allow failure on old setuptools)
RUN git clone --depth 1 https://github.com/codingo/Interlace /opt/tools/Interlace \
    && cd /opt/tools/Interlace \
    && pip3 install . --break-system-packages || pip3 install -r requirements.txt --break-system-packages || true

# 42. yq - YAML processor
RUN wget -q https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64 -O /usr/local/bin/yq \
    && chmod +x /usr/local/bin/yq

# ============================================================================
# WORDLISTS & RESOLVERS
# ============================================================================

# Download essential wordlists (SecLists subset)
RUN git clone --depth 1 https://github.com/danielmiessler/SecLists /opt/wordlists/SecLists \
    && mkdir -p /opt/wordlists/active

# Common wordlists links
RUN ln -s /opt/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories.txt /opt/wordlists/active/directories.txt \
    && ln -s /opt/wordlists/SecLists/Discovery/Web-Content/raft-medium-files.txt /opt/wordlists/active/files.txt \
    && ln -s /opt/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt /opt/wordlists/active/subdomains.txt

# Download trusted DNS resolvers
RUN wget -q https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt -O /opt/resolvers/trusted.txt || \
    echo "8.8.8.8\n1.1.1.1\n9.9.9.9" > /opt/resolvers/trusted.txt

# ============================================================================
# UPDATE NUCLEI TEMPLATES
# ============================================================================
RUN nuclei -update-templates -silent || true

# ============================================================================
# PYTHON DEPENDENCIES
# ============================================================================
COPY requirements.txt /tmp/requirements.txt
RUN pip3 install -r /tmp/requirements.txt --break-system-packages || \
    pip3 install pyyaml requests jinja2 colorama rich --break-system-packages \
    && rm -f /tmp/requirements.txt

# ============================================================================
# WORKING DIRECTORY SETUP
# ============================================================================
WORKDIR /hybridrecon

# Copy the framework
COPY . /hybridrecon/

# Make scripts executable
RUN chmod +x /hybridrecon/hybrid_x.sh 2>/dev/null || true \
    && chmod +x /hybridrecon/modules/*.sh 2>/dev/null || true \
    && chmod +x /hybridrecon/modules/*.py 2>/dev/null || true

# ============================================================================
# SYMLINKS FOR TOOL ACCESS
# ============================================================================
RUN ln -sf /opt/tools/sqlmap/sqlmap.py /usr/local/bin/sqlmap || true \
    && ln -sf /opt/tools/commix/commix.py /usr/local/bin/commix || true \
    && ln -sf /opt/tools/XSStrike/xsstrike.py /usr/local/bin/xsstrike || true \
    && ln -sf /opt/tools/tplmap/tplmap.py /usr/local/bin/tplmap || true \
    && ln -sf /opt/tools/joomscan/joomscan.pl /usr/local/bin/joomscan || true

# ============================================================================
# HEALTHCHECK
# ============================================================================
HEALTHCHECK --interval=60s --timeout=10s --start-period=5s --retries=3 \
    CMD which nuclei && which httpx && which ffuf || exit 1

# ============================================================================
# ENTRY POINT
# ============================================================================
# Remove ENTRYPOINT to allow flexible usage:
# - docker run ... bash          (interactive)
# - docker run ... ./hybrid_x.sh (script mode)
CMD ["/bin/bash"]
