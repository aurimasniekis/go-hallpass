#!/bin/sh
# Decorates a fictional destination by its hostname (web1, db1, ci-runner), then starts sshd. Demo content only.
set -e
host=$(hostname)
case "$host" in
  web1)
    printf '%s\n' "web1.example.internal  -  nginx front end (docs demo)" >/etc/motd
    mkdir -p /var/log/nginx /srv/app/releases/1.4.2 /srv/app/releases/1.4.3
    head -c 188743680 /dev/zero >/var/log/nginx/access.log.1   # 180 MiB of real bytes, so ls -lh shows the size
    cat >/var/log/nginx/error.log <<'EOF'
2026/10/24 04:31:07 [error] 31#31: *88412 upstream timed out (110: Operation timed out) while reading response header from upstream, upstream: "http://10.0.2.15:8080/cart"
2026/10/24 04:31:52 [error] 31#31: *88519 upstream timed out (110: Operation timed out) while reading response header from upstream, upstream: "http://10.0.2.15:8080/cart"
2026/10/24 04:40:13 [warn] 31#31: *90127 an upstream response is buffered to a temporary file
EOF
    chown -R deploy:deploy /srv/app
    ;;
  db1)
    printf '%s\n' "db1.example.internal  -  PostgreSQL primary for the shop (docs demo)" >/etc/motd
    mkdir -p /var/log/postgresql
    cat >/var/log/postgresql/postgresql-16-main.log <<'EOF'
2026-10-24 04:12:44 UTC [212] LOG:  checkpoint complete: wrote 1832 buffers (11.2%); 0 WAL file(s) added
2026-10-24 04:30:02 UTC [5121] LOG:  automatic vacuum of table "shop.public.cart_items": index scans: 1
2026-10-24 04:44:17 UTC [212] LOG:  checkpoint starting: time
EOF
    ;;
  *)
    printf '%s\n' "$host.example.internal  -  build runner (docs demo)" >/etc/motd
    ;;
esac
ssh-keygen -q -t ed25519 -N "" -f /etc/ssh/ssh_host_ed25519_key
ssh-keygen -q -t ecdsa -b 256 -N "" -f /etc/ssh/ssh_host_ecdsa_key
exec /usr/sbin/sshd -D -e
