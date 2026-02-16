# POC Runbook (Quick)

> This doc mirrors the automated behavior of `scripts/install.sh` in manual steps.

## 0) Root + baseline
```bash
sudo -i
nginx -t
nginx -v
```

## 1) Confirm include order
```bash
grep -nE 'include\s+/etc/nginx/conf\.d/\*\.conf|include\s+/etc/nginx/sites-enabled/\*' /etc/nginx/nginx.conf
```

## 2) Rate-limit zones (http context)
```bash
nano /etc/nginx/conf.d/<domain>.ratelimit.conf
nginx -t
```

## 3) Security snippet (server context)
```bash
nano /etc/nginx/snippets/<domain>.security.conf
nginx -t
```

## 4) Patch vhost (443 server)
- include snippet
- add CSP report endpoint
- add limit_conn + limit_req inside location /
- add HSTS header

```bash
nano /etc/nginx/sites-available/<your-vhost-file>
nginx -t && systemctl reload nginx
```

## 5) Default IP warning page + logging
```bash
mkdir -p /var/www/security-warning
nano /var/www/security-warning/index.html

nano /etc/nginx/sites-available/00-default-ip-warning.conf
ln -s /etc/nginx/sites-available/00-default-ip-warning.conf /etc/nginx/sites-enabled/
nginx -t && systemctl reload nginx
```

## 6) Verify
```bash
curl -I https://<domain>
curl http://<public-ip>
tail -f /var/log/nginx/ip_access_attempts.log
```
