# Ubuntu NGINX Reverse Proxy Hardening Framework (v1.1.0)

Production-grade, **domain-scoped** NGINX hardening for Ubuntu reverse-proxy hosts.

## What it does (per-domain / per-vhost)
- Creates **rate-limit zones** (HTTP context) in `/etc/nginx/conf.d/`
- Creates **host-only security snippet** in `/etc/nginx/snippets/`
- Injects the snippet into the target vhost (by `server_name`)
- Adds safe **HSTS** rollout (default `max-age=300`)
- Adds **CSP Report-Only** in phases (0→1→2→3)
- Adds **/csp-report** endpoint (204) for CSP reports
- Adds **default catch-all** for direct IP access: serves a warning page + logs hits
- Logs to: `/var/log/nginx-hardening.log`
- Supports `--dry-run` and `--rollback`

## Scope & Assumptions
- OS: **Ubuntu**
- NGINX: system package (e.g. `nginx/1.24.0`)
- Setup: **reverse proxy** (you provide `--upstream`)
- TLS: Certbot-managed or standard LE layout
- **Host-only**: will not change ports or upstream behavior beyond safe headers / limits

---

## Quickstart

### Install (apply)
```bash
sudo bash scripts/install.sh \
  --domain vapt.backoffice.saafir.co \
  --upstream http://localhost:1001 \
  --hsts-max-age 300 \
  --csp-phase 3 \
  --warning-page on
```

### Dry-run
```bash
sudo bash scripts/install.sh --domain vapt.backoffice.saafir.co --upstream http://localhost:1001 --dry-run
```

### Rollback (restores latest backup for domain)
```bash
sudo bash scripts/install.sh --domain vapt.backoffice.saafir.co --rollback
```

---

## CSP Phases (Report-Only)
- Phase 0: no CSP
- Phase 1: permissive (may include unsafe-inline/eval)
- Phase 2: remove `unsafe-eval`
- Phase 3: remove `unsafe-inline` (strictest Report-Only)

You should start with Phase 1, verify the app, review CSP reports, then tighten.

---

## Files created/modified
Created:
- `/etc/nginx/conf.d/<domain>.ratelimit.conf`
- `/etc/nginx/snippets/<domain>.security.conf`
- `/etc/nginx/sites-available/00-default-ip-block.conf` (optional)
- `/var/www/security-warning/index.html` (optional)
- `/var/log/nginx/ip_access_attempts.log` (optional)

Modified:
- `/etc/nginx/sites-available/<vhost>` for the domain (injects include + limits + CSP endpoint + HSTS)

Backups:
- `/var/backups/nginx-hardening/<domain>/<timestamp>/...`

---

## Architecture (high level)

```
Internet
  |
  v
NGINX (443)
  |-- vhost for <domain>  ---> proxy_pass to upstream
  |-- security snippet     ---> headers, method allowlist, timeouts
  |-- ratelimit zones      ---> limit_req_zone / limit_conn_zone (http context)
  |
  |-- default_server (IP hits) ---> warning page + access_log
```

---

## Notes
- OCSP stapling depends on certificate containing an OCSP URI. If LE chain lacks it in your build, NGINX warns and ignores stapling.
- This framework keeps changes domain-scoped to avoid impacting other sites on the same host.

---

## License
MIT (see LICENSE)
