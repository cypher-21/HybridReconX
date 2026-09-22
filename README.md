# HybridRecon X

> **Context-Aware Bug Bounty & Pentesting Intelligence Framework**  
> *The smart reconnaissance platform that thinks, clusters, and validates before reporting.*  
> **Created by Parosh • Modernized for 2026 Recon Standards**

![Version](https://img.shields.io/badge/version-2.3.0-blue)
![Release](https://img.shields.io/badge/release-September_2026-brightgreen)
![Docker](https://img.shields.io/badge/docker-ready-green)
![License](https://img.shields.io/badge/license-MIT-yellow)

---

## 🎯 The Raw Reality: Why Use This Over a Simple Bash Script?

Most bug bounty hunters run a simple 3-line bash pipe:
```bash
subfinder -d target.com | httpx -silent | nuclei -t cves/
```

### The Breakdown of Naive Recon Scripts

1. **The Parking Lot & Noise Trap**: On wildcard scopes with 2,000+ subdomains, 85% of hosts are identical parked domains, dead AWS S3 buckets, or generic Cloudflare 521 pages. Naive scripts blast every tool against all 2,000 hosts. Your fuzzer runs for 120 hours fuzzing parked domains.
2. **False Positive Fatigue**: Naive scripts flag reflections or regex matches on static blog pages (like a tutorial quoting `/etc/passwd` or discussing SQL syntax) as critical bugs. You waste hours triaging non-issues or get penalized on platforms for spam.
3. **SPA & Client-Side Blindness**: 80% of modern applications are Single Page Applications (Next.js, Vite, React, Vue). Simple crawlers see an empty `index.html` with a `<div id="root">` and find almost nothing, completely blind to exposed `.js.map` source maps containing the original unminified source code, internal admin panels, and backend GraphQL schemas.
4. **Crash & State Fragility**: If your 14-hour scan drops its network connection or hits an unhandled error, a simple pipe dies with zero state. You start over at 0.

---

## ⚡ What HybridRecon X Solves

HybridRecon X is designed around **context, deduplication, and causal verification**:

| Capability | What It Does & Why It Matters |
|---|---|
| **64-bit SimHash Archetype Clustering** | Groups thousands of probed responses into structural archetypes (Hamming distance $\le 3$). It isolates unique applications from 1,800 identical parked domains, reducing fuzzing time by up to 90%. |
| **SourceMap Reconstruction Engine** | Automatically detects `//# sourceMappingURL=` and `.map` endpoints, unpacking unminified developer source trees (`sourcesContent`). Recovers internal routes, hidden parameters, and secrets hidden inside React/Vue/Next.js bundles. |
| **Dual-Probe Causal Validation Gate** | Re-tests findings using a 3-way check ($R_0 \text{ Baseline} \text{ vs } R_{\text{inj}} \text{ Injected} \text{ vs } R_{\text{ctrl}} \text{ Control}$). Ensures reflections break out into executable contexts, time-based delays revert on control probes, and patterns are not pre-existing static text. |
| **Unified Checkpoint & Resume Engine** | State is preserved in `.checkpoint.json` across all 17 phases. If interrupted, `--resume` picks up at the exact step without repeating hours of DNS enumeration. |
| **Public Suffix List (PSL) Scope Safety** | Uses `tldextract` to safely resolve multi-part TLDs (e.g. `api.target.co.uk` $\rightarrow$ `target.co.uk`) and prevents false-scope S3 bucket enumeration. |
| **Safe RoE Compliance** | Eliminated destructive test vectors (`DROP TABLE`). Differential testing uses safe, non-destructive boolean and arithmetic canary probes. |
| **Bounded, Adaptive Content Discovery** | Prioritizes live 2xx and content-rich hosts. Dynamically caps fuzzing queues and limits job times (`-maxtime 300`) to prevent WAF tar-pits from locking scans. |

---

## 🏗️ 17-Phase Unified Architecture

The framework coordinates specialized tools and custom Python intelligence engines in a strict pipeline:

```
[00] Preflight Checks & Dependency Verification
  │
[01] Subdomain Enumeration (Multi-Engine + PSL + ANEW Incremental)
  │
[02] HTTP Probing & URO Deduplication
  │
[03] Response Archetype Clustering (64-bit SimHash & Outlier Detection) ───► intel/unique_archetypes.txt
  │
[04] Fingerprinting & WAF Detection (Cloudflare, Akamai, Technologies)
  │
[05] Bounded Content Discovery (Adaptive FFUF + HTTPX Quick Paths)
  │
[06] Parameter Mining & Historical Extraction (Katana, GAU, Wayback)
  │
[07] Machine Parameter Scoring (Critical Risk Param Prioritization) ────────► params/prioritized_critical.txt
  │
[08] Smart Vulnerability Routing (Nuclei Automatic Tech Scan)
  │
[09] Targeted Exploit Engine (Nuclei v3 SSTI + Dalfox Deep XSS)
  │
[10] Escalation Engine (Heuristic Anomaly Correlation & Probing)
  │
[11] Advanced Attack Surface (CORS, CRLF, SSL Misconfigurations)
  │
[12] Cloud & Git Enumeration (Safe PSL Bucket Matching + Git Leaks)
  │
[13] JavaScript Analysis & SourceMap Reconstructor ───────────────────────► intel/sourcemap_endpoints.txt
  │
[14] Differential Response Analysis (Non-Destructive Boolean Probes)
  │
[15] Dual-Probe Causal Validation Gate (3-Way Verification Model) ────────► vulns/validated_high.json
  │
[16] Comprehensive Visual Reporting (HTML Dashboard + Real-Time Alerts)
```

---

## 🚀 Quick Start

### Docker (Recommended)

```bash
# Build the container
docker build -t hybridrecon-x .

# Run a scan
docker run -it --rm --network=host \
    -v $(pwd)/output:/hybridrecon/output \
    hybridrecon-x ./hybrid_x.sh -d target.com

# Run in fast mode
docker run -it --rm --network=host \
    -v $(pwd)/output:/hybridrecon/output \
    hybridrecon-x ./hybrid_x.sh -d target.com --fast
```

### Local Installation

```bash
# Clone the repository
git clone https://github.com/cypher-21/HybridRecon-X.git
cd HybridRecon-X

# Install system dependencies, Go tools, and Python packages
chmod +x install.sh
./install.sh

# Run scan
./hybrid_x.sh -d target.com
```

---

## 📋 Command Reference

```
USAGE:
    ./hybrid_x.sh [OPTIONS] -d <domain>
    ./hybrid_x.sh [OPTIONS] -l <domain_list>

TARGET OPTIONS:
    -d, --domain <domain>   Target domain (e.g. target.com)
    -l, --list <file>       File containing target domain list
    --exclude <pattern>     Regex pattern to exclude subdomains

WORKFLOW MODES:
    --all                   Run complete 17-stage pipeline (default)
    --recon                 Run reconnaissance only (Phases 0-4)
    --passive               Passive mode only (no active network probes)

SCAN TUNING:
    -f, --fast              Fast mode: skips heavy tools, selects common.txt wordlists
    -a, --aggressive        Aggressive mode: higher threads, deeper discovery queues
    --stealth               Stealth mode: strict low rate limits for strict WAFs
    --dry-run               Simulate complete pipeline without sending network traffic

PERFORMANCE:
    -t, --threads <n>       Concurrency thread limit (default: 50)
    -r, --rate-limit <n>    Requests per second rate limit (default: 50)

CHECKPOINT & STATE:
    --resume                Resume interrupted scan from .checkpoint.json
    -o, --output <dir>      Custom output directory (default: ./output/<domain>)
```

---

## 🧠 Core Intelligence Modules

### 1. SourceMap Reconstructor (`modules/10_js_analysis.py`)
Modern applications bundle source maps that leak the developer's original filesystem:
```bash
python3 modules/10_js_analysis.py -o ./output/target.com
```
- Locates `//# sourceMappingURL=` comments and `.map` files.
- Extracts `sourcesContent` to reconstruct original TypeScript, React, and Vue source files.
- Discovers hidden API routes (`createBrowserRouter`, `axios.create`), unreferenced parameters, and client-side route guards.
- Outputs: `intel/sourcemap_assets.json`, `intel/sourcemap_files.txt`, `intel/sourcemap_endpoints.txt`.

### 2. SimHash Response Clustering (`lib/anomaly_detector.py`)
```bash
python3 lib/anomaly_detector.py -o ./output/target.com
```
- Computes 64-bit SimHash fingerprints over HTTP response structures and tokens.
- Clusters responses into distinct archetypes; automatically distinguishes singletons from mass-parked templates.
- Outputs: `intel/response_clusters.json`, `intel/unique_archetypes.txt`.

### 3. Dual-Probe Causal Validation Gate (`modules/09_validate.py`)
```bash
python3 modules/09_validate.py -o ./output/target.com
```
- **SQLi**: Confirms time-based injection only if $T_{\text{inj}} \ge T_0 + \text{delay}$ and control probe $T_{\text{ctrl}} \le T_0 + 2.0\text{s}$.
- **XSS**: Uses paired canary injection (`hx<canary_a>` vs `hx<canary_b>`) to verify unescaped context breakouts against baseline reflections.
- **SSTI**: Mathematically confirms template injection via arithmetic evaluation (${{773 \times 773}} \rightarrow 597529$ vs ${{773 \times 772}} \rightarrow 596756$).
- **LFI / SSRF**: Verifies file and cloud metadata signatures are absent in baseline $R_0$ and revert on control probes.
- Outputs: `vulns/validated_high.json`, `vulns/validated_medium.json`, `vulns/needs_review.json`.

### 4. Parameter Scorer (`lib/param_scorer.py`)
```bash
python3 lib/param_scorer.py -o ./output/target.com
```
- Analyzes discovered query and body parameters.
- Assigns heuristic risk scores based on vulnerability classes (e.g. `redirect`, `url` = SSRF/Redirect; `file`, `path` = LFI; `id`, `user` = IDOR).
- Outputs: `params/prioritized_critical.txt`, `params/scored_params.json`.

---

## 📊 Output Directory Structure

```
output/<target>/
├── .checkpoint.json           # Resume state machine
├── recon/                     # Subdomain data
│   ├── all_subdomains.txt
│   └── new_subdomains.txt     # Incremental discoveries via ANEW
├── probed/                    # Live hosts and probing
│   ├── live_hosts.txt
│   ├── live_2xx.txt
│   └── httpx_output.json
├── content/                   # Web discovery
│   ├── katana_output.txt
│   ├── all_urls.txt
│   └── ffuf_discovered.txt
├── params/                    # Parameter intelligence
│   ├── urls_with_params.txt
│   ├── prioritized_critical.txt
│   └── scored_params.json
├── intel/                     # Intelligence & archetypes
│   ├── response_clusters.json # SimHash archetype breakdown
│   ├── unique_archetypes.txt  # Deduplicated representative targets
│   ├── sourcemap_assets.json  # Reconstructed source maps
│   ├── sourcemap_files.txt    # Unpacked source file tree
│   ├── sourcemap_endpoints.txt# Hidden routes found in source maps
│   ├── js_secrets.json        # Leaked credentials & tokens
│   └── anomalies.json         # Statistical & structural anomalies
├── vulns/                     # Vulnerability assessment
│   ├── nuclei_results.json
│   ├── validated_high.json    # Causally confirmed high-confidence findings
│   └── validated_medium.json
└── reports/
    └── report.html            # Visual interactive HTML dashboard
```

---

## ⚖️ When to Use HybridRecon X vs. Other Approaches

| Scenario | Best Tool | Why |
|---|---|---|
| **Large Wildcard BBP Scope** (`*.domain.com`) | **HybridRecon X** | Checkpointing, SimHash deduplication, and automated parameter prioritization handle scope scale without choking or losing state. |
| **Modern SPA / API Target** (React/Next.js/GraphQL) | **HybridRecon X** | JavaScript analysis and SourceMap reconstruction extract hidden routes and internal endpoints invisible to standard scanners. |
| **Quick Single-Host Triage** (`app.domain.com`) | Targeted Tools / Burp Suite | For a single web app, manual proxying with Burp Suite and targeted fuzzer runs are faster than running a full multi-stage recon pipeline. |
| **Deep Business Logic / Auth Testing** | Manual Testing / Burp | No automated recon scanner replaces manual session analysis, privilege escalation, or multi-step logic flaw testing. |

---

## ⚠️ Legal & Ethical Disclaimer

This software is designed solely for **authorized security testing, bug bounty programs, and educational vulnerability research** on systems where you have explicit, written authorization. Scanning systems without permission is illegal. The author and contributors assume no liability for misuse.

---

## 📝 License

Distributed under the **MIT License**.

**Created by Parosh**
