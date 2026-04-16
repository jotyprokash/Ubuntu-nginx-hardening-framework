# Ubuntu NGINX Hardening Framework

![Build Status](https://img.shields.io/badge/Build-Passing-brightgreen?style=flat-square)
![NGINX](https://img.shields.io/badge/NGINX-009639?style=flat-square&logo=nginx&logoColor=white)
![Ubuntu](https://img.shields.io/badge/Ubuntu-E95420?style=flat-square&logo=ubuntu&logoColor=white)
![Security](https://img.shields.io/badge/Security-Hardened-success?style=flat-square)
![DDoS Protection](https://img.shields.io/badge/DDoS-Protected-orange?style=flat-square)
![CSP](https://img.shields.io/badge/CSP-Validated-blueviolet?style=flat-square)
![OpenSSL](https://img.shields.io/badge/OpenSSL-Certified-blue?style=flat-square&logo=openssl&logoColor=white)
![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg?style=flat-square)

A deterministic, idempotent hardening framework for NGINX reverse-proxy environments on Ubuntu. Designed for operational transparency and phased security rollouts.

## Core Capabilities
- **Idempotent Execution**: Automatically detects and synchronizes managed security directives with zero configuration drift.
- **Phased CSP Rollout**: Implements Content Security Policy in four granular "Report-Only" phases to ensure zero-downtime security upgrades.
- **Rate & Connection Hardening**: Domain-scoped shared memory zones for surgical traffic control (DDoS/Brute-force mitigation).
- **Surface Area Reduction**: Prevents direct IP access via a dedicated catch-all block with automated logging.
- **Transparent Verification**: Unified diff-based dry-runs show exact configuration changes before they affect production.

## Operational Workflow

### Phase 1: Verification (Dry-Run)
Generate a `diff -u` of exactly what will change in your vhost without touching production files. This ensures your configuration remains valid after hardening.
```bash
sudo bash scripts/install.sh --domain app.example.com --upstream http://localhost:8080 --dry-run
```

### Phase 2: Deployment (Hardening)
Applies hardening or synchronizes existing configs. Atomic execution: only replaces files if NGINX syntax validation passes.
```bash
sudo bash scripts/install.sh \
  --domain app.example.com \
  --upstream http://localhost:8080 \
  --csp-phase 3 \
  --hsts-max-age 300 \
  --warning-page on
```

### Phase 3: Deterministic Reset (Cleanup)
Surgically removes all framework-managed hardening lines and associated architecture files.
```bash
# Preview what will be cleaned up
sudo bash scripts/install.sh --domain app.example.com --cleanup --dry-run

# Perform full cleanup
sudo bash scripts/install.sh --domain app.example.com --cleanup
```

---

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
