# HybridRecon X

> **Context-Aware Bug Bounty & Pentesting Framework**  
> *The Smart Recon Platform that thinks before it attacks.*

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![Docker](https://img.shields.io/badge/docker-ready-green)
![License](https://img.shields.io/badge/license-MIT-yellow)

## 🎯 What Makes HybridRecon X Different?

Unlike traditional "spray-and-pray" tools, **HybridRecon X** implements **Context-Aware Intelligence**:

1. **Fingerprint First** - Identifies tech stack, CMS, WAF, and OS before attacking
2. **Smart Routing** - Routes targets to specialized scanners based on detected technologies
3. **WAF-Aware** - Automatically adjusts rate limits when Cloudflare/Akamai detected
4. **Stateful** - Tracks scans over time, enables diffing for new asset detection

## 🚀 Quick Start

### Docker (Recommended)

```bash
# Build the mega-container
docker build -t hybridrecon-x .

# Run a scan
docker run -it --rm -v $(pwd)/output:/hybridrecon/output hybridrecon-x ./hybrid_x.sh -d target.com

# Interactive mode
docker run -it --rm -v $(pwd)/output:/hybridrecon/output hybridrecon-x bash
```

### Direct Execution

```bash
# Make executable
chmod +x hybrid_x.sh modules/*.sh

# Run
./hybrid_x.sh -d target.com
```

## 📋 Command Reference

```
USAGE:
    ./hybrid_x.sh [OPTIONS] -d <domain>
    ./hybrid_x.sh [OPTIONS] -l <domain_list>

TARGET OPTIONS:
    -d, --domain <domain>       Single target domain
    -l, --list <file>           File containing list of domains
    --exclude <pattern>         Exclude pattern (regex)

MODE OPTIONS:
    -f, --fast                  Skip slow tools (amass, feroxbuster)
    -a, --aggressive            Higher threads, deeper scans
    --stealth                   Low rate limits for WAF bypass
    --dry-run                   Show what would run without executing

SKIP OPTIONS:
    --skip-recon                Skip subdomain enumeration
    --skip-content              Skip content discovery
    --skip-vuln                 Skip vulnerability scanning
    --only-recon                Only run reconnaissance
    --only-fingerprint          Only run fingerprinting
```

## 🏗️ Architecture

```
HybridRecon-X/
├── hybrid_x.sh              # Main orchestrator
├── config.yaml              # Central configuration
├── Dockerfile               # Mega-container (40+ tools)
├── modules/
│   ├── 00_preflight.sh      # Network & tool checks
│   ├── 01_recon_subs.sh     # Subdomain discovery
│   ├── 02_filter_probe.sh   # HTTPX probing
│   ├── 03_fingerprint.sh    # Tech detection
│   ├── 04_content_disc.sh   # FFUF + Katana
│   ├── 05_param_mining.sh   # GF patterns
│   ├── 06_vuln_smart.py     # THE BRAIN - Smart Router
│   ├── 07_exploits_specific.sh
│   ├── 08_cloud_git.sh
│   └── 09_reporting.sh      # HTML dashboard
└── output/
    └── <target>/
        └── <timestamp>/
            ├── recon/
            ├── probed/
            ├── fingerprint/
            ├── content/
            ├── params/
            ├── vulns/
            ├── exploits/
            ├── cloud/
            └── reports/
```

## 🧠 The Smart Router

The Python-based Smart Router (`06_vuln_smart.py`) is the brain:

| Detection | Action |
|-----------|--------|
| WordPress | → WPScan + Nuclei wordpress/ |
| Joomla | → JoomScan + Nuclei joomla/ |
| Drupal | → Droopescan |
| Spring Boot | → Nuclei springboot,java |
| IIS/ASP.NET | → Nuclei iis,aspnet + exclude Linux paths |
| Cloudflare WAF | → Reduce rate to 10 req/s |
| .git exposed | → git-dumper + Gitleaks |

## 🔧 Configuration

Edit `config.yaml` to customize:

```yaml
api_keys:
  shodan: "YOUR_KEY"
  github_token: "ghp_xxx"

modules:
  vulnerability:
    allow_destructive: false  # Enable for SQLMap exploitation
    
smart_router:
  waf_handling:
    cloudflare:
      rate_limit: 10
```

## 🛠️ Tool Arsenal (40+)

| Category | Tools |
|----------|-------|
| Subdomain | subfinder, amass, assetfinder, findomain |
| DNS | puredns, dnsx, shuffledns, massdns |
| Probing | httpx, whatweb, wafw00f, gowitness |
| Fuzzing | ffuf, katana, feroxbuster, hakrawler |
| Params | paramspider, arjun, gf, qsreplace |
| Vuln Scan | nuclei, dalfox, ghauri, sqlmap |
| CMS | wpscan, joomscan, droopescan |
| Secrets | gitleaks, trufflehog, git-dumper |
| Cloud | cloud_enum, s3scanner |

## 📊 Output

After a scan, find results in `output/<target>/<timestamp>/`:

- **reports/report.html** - Beautiful HTML dashboard
- **vulns/** - All vulnerability findings
- **fingerprint/consolidated.json** - Tech fingerprints
- **cloud/git_dumps/** - Dumped .git repos
- **params/gf_*.txt** - Categorized parameters

## ⚠️ Legal Disclaimer

This tool is for **authorized security testing only**. Always obtain proper permission before scanning any target. The authors are not responsible for misuse.

## 📝 License

MIT License - Use responsibly.
