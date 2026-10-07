#!/usr/bin/env bash
set -euo pipefail
domain=${1:?SIP domain required}
public_ip=${2:?Public IP required}
private_ip=${3:?Private interface IP required}
[[ $domain =~ ^[A-Za-z0-9.-]+$ ]] || exit 1
[[ $public_ip =~ ^[0-9.]+$ && $private_ip =~ ^[0-9.]+$ ]] || exit 1
[[ $(id -u) = 0 ]] || exit 1
command -v turnserver >/dev/null
backup=/opt/simson/backups/turn-$(date -u +%Y%m%dT%H%M%SZ)
mkdir -m 700 -p "$backup"
cp -p /etc/turnserver.conf "$backup/turnserver.conf"
cert_dir=/var/lib/caddy/.local/share/caddy/certificates/acme-v02.api.letsencrypt.org-directory/$domain
openssl x509 -in "$cert_dir/$domain.crt" -noout -checkend 86400 >/dev/null
install -d -m 750 -o root -g turnserver /etc/simson-turn
install -m 644 "$cert_dir/$domain.crt" /etc/simson-turn/server.crt
install -m 640 -o root -g turnserver "$cert_dir/$domain.key" /etc/simson-turn/server.key
python3 - "$domain" "$public_ip" "$private_ip" <<'PY'
import json,secrets,sys,os
from pathlib import Path
domain,public,private=sys.argv[1:]
pending=Path('/opt/simson/turn-relay.pending.json')
secret=json.loads(pending.read_text())['turn_auth_secret'] if pending.exists() else secrets.token_urlsafe(48)
urls=['turn:'+domain+':3478?transport=udp','turn:'+domain+':3478?transport=tcp']
if os.environ.get('TURN_TLS_READY')=='1':urls.append('turns:'+domain+':5349?transport=tcp')
pending.write_text(json.dumps({'turn_enabled':True,'stun_servers':['stun:'+domain+':3478'],
 'turn_urls':urls,
 'turn_auth_secret':secret}))
os.chmod(pending,0o600)
config=f'''listening-port=3478
tls-listening-port=5349
listening-ip={private}
relay-ip={private}
external-ip={public}/{private}
realm={domain}
server-name={domain}
fingerprint
use-auth-secret
static-auth-secret={secret}
min-port=49160
max-port=49259
user-quota=16
total-quota=512
max-bps=8000000
bps-capacity=64000000
stale-nonce=600
no-cli
no-tcp-relay
no-multicast-peers
no-tlsv1
no-tlsv1_1
cert=/etc/simson-turn/server.crt
pkey=/etc/simson-turn/server.key
denied-peer-ip=0.0.0.0-0.255.255.255
denied-peer-ip=10.0.0.0-10.255.255.255
denied-peer-ip=127.0.0.0-127.255.255.255
denied-peer-ip=169.254.0.0-169.254.255.255
denied-peer-ip=172.16.0.0-172.31.255.255
denied-peer-ip=192.168.0.0-192.168.255.255
denied-peer-ip=224.0.0.0-255.255.255.255
denied-peer-ip=::1
denied-peer-ip=fc00::-fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff
allowed-peer-ip={private}
log-file=syslog
no-stdout-log
'''
Path('/etc/turnserver.conf').write_text(config)
PY
chown root:turnserver /etc/turnserver.conf
chmod 640 /etc/turnserver.conf
sed -i 's/^#TURNSERVER_ENABLED=1/TURNSERVER_ENABLED=1/' /etc/default/coturn
ufw allow 3478/udp comment 'Simson authenticated TURN UDP'
ufw allow 3478/tcp comment 'Simson authenticated TURN TCP'
ufw allow 5349/tcp comment 'Simson authenticated TURN TLS'
ufw allow 49160:49259/udp comment 'Simson bounded TURN relay media'
systemctl enable coturn
systemctl restart coturn
systemctl is-active coturn
printf 'TURN configuration ready; pending ICE config private. Backup: %s\n' "$backup"
