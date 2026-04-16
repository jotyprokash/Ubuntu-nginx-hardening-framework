# Ubuntu NGINX Hardening Framework

![NGINX](https://img.shields.io/badge/NGINX-009639?style=flat-square&logo=nginx&logoColor=white)
![Ubuntu](https://img.shields.io/badge/Ubuntu-E95420?style=flat-square&logo=ubuntu&logoColor=white)
![Shell](https://img.shields.io/badge/Shell_Script-121011?style=flat-square&logo=gnu-bash&logoColor=white)
![Security](https://img.shields.io/badge/Security-Hardened-success?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)

A deterministic, idempotent hardening framework for NGINX reverse-proxy environments on Ubuntu. Designed for operational transparency and phased security rollouts.

## Core Capabilities
- **Idempotent Execution**: Automatically detects and synchronizes managed security directives with zero configuration drift.
- **Phased CSP Rollout**: Implements Content Security Policy in four granular "Report-Only" phases to ensure zero-downtime security upgrades.
- **Rate & Connection Hardening**: Domain-scoped shared memory zones for surgical traffic control (DDoS/Brute-force mitigation).
- **Surface Area Reduction**: Prevents direct IP access via a dedicated catch-all block with automated logging.
- **Transparent Verification**: Unified diff-based dry-runs show exact configuration changes before they affect production.

## Operations

### Installation / Synchronization
Applies hardening or synchronizes existing configs. Idempotent: safe to run multiple times.
```bash
sudo bash scripts/install.sh \
  --domain vapt.backoffice.saafir.co \
  --upstream http://localhost:1001 \
  --csp-phase 3 \
  --hsts-max-age 300
```

### Transparent Verification (Dry-Run)
Generates a `diff -u` of exactly what will change in your vhost without touching production files.
```bash
sudo bash scripts/install.sh --domain vapt.backoffice.saafir.co --dry-run
```

### Recovery (Rollback)
Restores the most recent backup and removes all framework-generated artifacts.
```bash
sudo bash scripts/install.sh --domain vapt.backoffice.saafir.co --rollback
```

## Security Profiles
### CSP Phases (Report-Only)
- **Phase 0**: Baseline (No CSP)
- **Phase 1**: Permissive (Allows legacy inline/eval for initial auditing)
- **Phase 2**: Strict Logic (Blocks `unsafe-eval`)
- **Phase 3**: Maximum Security (Blocks `unsafe-inline`)

### Configuration Paths
- **Snippets**: `/etc/nginx/snippets/<domain>.security.conf` (Headers & CSP)
- **Zones**: `/etc/nginx/conf.d/<domain>.ratelimit.conf` (Shared memory definitions)
- **Logs**: `/var/log/nginx-hardening.log` (Internal audit trail)

## License
MIT (See LICENSE)
