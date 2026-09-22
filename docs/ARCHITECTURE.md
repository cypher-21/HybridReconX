# HybridRecon X — System Architecture

> Version 2.2.0 | Production-Ready Architecture Documentation

---

## Overview

HybridRecon X is a modular, context-aware bug bounty and penetration testing framework. This document describes the actual system behavior as implemented.

---

## Module Pipeline

### Execution Order (Strict)

The pipeline controller enforces this exact execution order:

```
┌─────────────────────────────────────────────────────────────────┐
│                    HYBRIDRECON X PIPELINE                       │
├─────────────────────────────────────────────────────────────────┤
│  00_preflight.sh       │ System checks, tool availability       │
│  01_recon_subs.sh      │ Subdomain enumeration                  │
│  02_filter_probe.sh    │ DNS resolution, HTTP probing           │
│  03_fingerprint.sh     │ Technology detection, WAF detection    │
│  04_content_disc.sh    │ URL crawling, content discovery        │
│  05_param_mining.sh    │ Parameter extraction, GF patterns      │
│  06_vuln_smart.py      │ Smart vulnerability routing            │
│  07_exploits_specific.sh│ Deep exploitation (SQLMap, XSStrike)  │
│  08_cloud_git.sh       │ Cloud/Git enumeration                  │
│  09_validate.py        │ Finding validation, PoC generation     │
│  10_js_analysis.py     │ JavaScript secret/endpoint extraction  │
│  11_response_diff.py   │ Response difference analysis           │
│  12_advanced_vulns.py  │ CORS, CRLF, SSL, smuggling, etc.       │
│  13_reporting.sh       │ Report generation (ALWAYS LAST)        │
└─────────────────────────────────────────────────────────────────┘
```

> **CRITICAL**: Reporting (13) ALWAYS runs last, after all modules complete.

### Data Flow

```
                        ┌──────────────┐
                        │   TARGET     │
                        └──────┬───────┘
                               │
                    ┌──────────▼──────────┐
                    │   01_recon_subs     │
                    │  → recon/subdomains │
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │   02_filter_probe   │
                    │  → probed/live_hosts│
                    └──────────┬──────────┘
                               │
        ┌──────────────────────┼──────────────────────┐
        │                      │                      │
┌───────▼───────┐    ┌─────────▼─────────┐   ┌───────▼───────┐
│ 03_fingerprint│    │  04_content_disc  │   │ 08_cloud_git  │
│ → fingerprint/│    │   → content/      │   │   → cloud/    │
└───────┬───────┘    └─────────┬─────────┘   └───────────────┘
        │                      │
        │            ┌─────────▼─────────┐
        │            │  05_param_mining  │
        │            │    → params/      │
        │            └─────────┬─────────┘
        │                      │
        └──────────┬───────────┘
                   │
        ┌──────────▼──────────┐
        │   06_vuln_smart     │
        │   07_exploits       │
        │   11_js_analysis    │
        │   12_response_diff  │
        │   13_advanced_vulns │
        │      → vulns/       │
        │      → intel/       │
        └──────────┬──────────┘
                   │
        ┌──────────▼──────────┐
        │    10_validate      │
        │ → vulns/validated_* │
        └──────────┬──────────┘
                   │
        ┌──────────▼──────────┐
        │    09_reporting     │
        │    → reports/       │
        └─────────────────────┘
```

---

## Configuration System

### Resolution Priority

```
CLI FLAGS  →  config.yaml  →  DEFAULTS
(highest)                     (lowest)
```

### Config Resolution Flow

```bash
# At startup, before any module runs:
config_resolve_all        # Build complete resolved state
config_export_resolved    # Export for modules

# Within modules:
resolved_is_module_enabled "vulnerability"  # Returns "true" or "false"
resolved_is_tool_enabled "vulnerability.sqli.sqlmap"
should_run_tool_strict "vulnerability" "sqlmap"  # Returns 0/1, logs skip
```

### Key Config Paths

| Purpose | YAML Path | CLI Override |
|---------|-----------|--------------|
| Disable SQLMap | `.modules.vulnerability.sqli.sqlmap.enabled` | N/A |
| Disable XSStrike | `.modules.vulnerability.xss.xsstrike.enabled` | N/A |
| Skip Recon | `.modules.recon.enabled` | `--skip-recon` |
| Skip Vulns | `.modules.vulnerability.enabled` | `--skip-vuln` |
| Fast Mode | N/A | `--fast` |
| Thread Count | `.global.threads.default` | `-t/--threads` |

### Tool Skip Behavior

When a tool is disabled:
1. Config check returns `false`
2. Tool execution is skipped
3. Skip is logged to `logs/skipped_tools.txt`
4. Skip appears in final report

---

## Resume System

### Checkpoint Format (v2.0)

```json
{
  "version": "2.0",
  "target": "example.com",
  "status": "running",
  "current_phase": {
    "module": "07_exploits_specific",
    "tool": "sqlmap",
    "target_index": 15,
    "total_targets": 30
  },
  "completed_modules": ["01_recon_subs", "02_filter_probe"],
  "module_progress": {
    "07_exploits_specific": {
      "tool": "sqlmap",
      "target_index": 15,
      "total": 30
    }
  }
}
```

### Interrupt Behavior

| Action | Result |
|--------|--------|
| 1× Ctrl+C | Stop current tool, continue to next module |
| 2× Ctrl+C | Warning, one more to force exit |
| 3× Ctrl+C | Force exit, save checkpoint |

### Resume Flow

1. On start, check for existing checkpoint
2. If found with `status != completed`, offer resume
3. Load checkpoint, restore state
4. Skip completed modules
5. For interrupted module, resume from `target_index`

---

## Reporting System

### Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  data_aggregator│────▶│  aggregated_data │────▶│ report_generator│
│       .py       │     │      .json       │     │       .py       │
└─────────────────┘     └──────────────────┘     └─────────────────┘
         │                                                │
         ▼                                                ▼
   Parse all module                                  Generate
   outputs, normalize                                report.html
```

### Report Sections

1. **Executive Summary** — Risk level, key stats
2. **Attack Surface** — Hosts, subdomains, technologies
3. **Vulnerabilities** — Grouped by severity, validated findings
4. **JS Intelligence** — Secrets, endpoints, DOM XSS
5. **Technology Stack** — Detected technologies
6. **Scan Metadata** — Skipped modules, errors, runtime

### Data Sources

| Section | Source Files |
|---------|--------------|
| Subdomains | `recon/clean_subdomains.txt` |
| Hosts | `probed/live_hosts.txt`, `probed/httpx_full.json` |
| URLs | `content/all_urls.txt` |
| Params | `params/urls_with_params.txt` |
| Findings | `vulns/*.json`, `exploits/**/*` |
| JS Intel | `intel/js_secrets.json`, `intel/js_endpoints.txt` |
| Validation | `vulns/validated_*.json` |

---

## Output Directory Structure

```
output/<target>/
├── .checkpoint.json          # Resume state
├── .target                   # Target identifier
├── recon/
│   ├── all_subdomains.txt
│   └── clean_subdomains.txt
├── probed/
│   ├── live_hosts.txt
│   ├── httpx_full.json
│   └── historical_urls.txt
├── fingerprint/
│   ├── tech_summary.txt
│   └── waf_results.txt
├── content/
│   ├── all_urls.txt
│   └── katana_output.txt
├── params/
│   ├── urls_with_params.txt
│   └── gf_*.txt
├── vulns/
│   ├── nuclei_*.txt
│   ├── validated_high.json
│   ├── validated_medium.json
│   └── advanced/
├── intel/
│   ├── js_secrets.json
│   ├── js_endpoints.txt
│   └── dom_xss_vectors.json
├── exploits/
│   ├── sqlmap/
│   └── xsstrike/
├── logs/
│   ├── hybridrecon.log
│   ├── skipped_modules.json
│   └── skipped_tools.txt
└── reports/
    ├── report.html
    ├── report.json
    └── aggregated_data.json
```

---

## Tool Dependencies

### Required (Core)

- `yq` — YAML parsing
- `jq` — JSON parsing
- `python3` — Python modules
- `httpx` — HTTP probing
- `nuclei` — Vulnerability scanning

### Optional (Module-Specific)

| Tool | Module | Purpose |
|------|--------|---------|
| subfinder | 01_recon | Subdomain enum |
| amass | 01_recon | Deep subdomain enum |
| katana | 04_content | Crawling |
| ffuf | 04_content | Fuzzing |
| dalfox | 06_vuln | XSS |
| sqlmap | 07_exploits | SQLi |
| xsstrike | 07_exploits | XSS (disabled by default) |
| corsy | 13_advanced | CORS |
| testssl | 13_advanced | SSL/TLS |

---

## Troubleshooting

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| "0 JS files analyzed" | No JS discovered | Check content discovery ran |
| SQLMap errors | Python env | Use `python3 -u` unbuffered |
| Tplmap not working | Python 3.12+ | telnetlib removed, use 3.11 |
| Report empty | Ran before modules | Ensure 09 runs last |
| Resume not working | Old checkpoint | Delete `.checkpoint.json` |

### Debug Mode

```bash
DEBUG=true ./hybrid_x.sh -d example.com
```

---

*Last updated: April 2026*
