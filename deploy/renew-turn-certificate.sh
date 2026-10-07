#!/usr/bin/env bash
set -euo pipefail
domain=${1:?SIP domain required}
[[ $domain =~ ^[A-Za-z0-9.-]+$ ]] || exit 1
[[ $(id -u) = 0 ]] || exit 1
source_dir=/var/lib/caddy/.local/share/caddy/certificates/acme-v02.api.letsencrypt.org-directory/$domain
openssl x509 -in "$source_dir/$domain.crt" -noout -checkend 86400 >/dev/null
if cmp -s "$source_dir/$domain.crt" /etc/simson-turn/server.crt; then exit 0; fi
install -m 644 "$source_dir/$domain.crt" /etc/simson-turn/server.crt
install -m 640 -o root -g turnserver "$source_dir/$domain.key" /etc/simson-turn/server.key
systemctl restart coturn
