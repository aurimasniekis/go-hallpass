#!/usr/bin/env bash
# Regenerates the documentation screenshots in site/public/screenshots (README and website). Everything shown is
# fictional: a fresh development instance (scripts/e2e.sh), four throwaway sshd containers named web1, db1, ci-runner
# and forge (a git server) on loopback ports 2431-2434, agents with keys generated at run time, and invented requests and sessions.
# Never point this at a real instance.
#
# API calls and backups go to fakes on a private Docker network: a TLS front (nginx) answering as api.github.com with
# canned JSON and as s3.example.com in front of a throwaway SeaweedFS, under a CA generated for this run. The gateway
# runs in a container whose /etc/hosts points those names at the front (E2E_ADD_HOSTS), so nothing reaches the real
# services and this machine's resolver is untouched.
#
# Usage: scripts/screenshots.sh [OUT_DIR]   (default site/public/screenshots)
#   SKIP_BUILD=1  reuse the binary and web/dist from a previous run in $WORK (see scripts/e2e.sh)
#   DOCS_SUBNET   private subnet for the fakes (default 172.30.231.0/24; the front gets .10)
#
# Needs Docker, Go, pnpm, git, gh, ssh, ssh-keygen and openssl. Review every image before committing it.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
out=$(cd "${1:-$root/site/public/screenshots}" && pwd)
image=hallpass-docs-dest:local
nginx_image=nginx:1.28.0-alpine
s3_image=chrislusf/seaweedfs@sha256:bb05d66d2963b1cc48073190781c3dd29e2c4c88a2ae2986bf58e38c86d89c6e # 3.97
subnet=${DOCS_SUBNET:-172.30.231.0/24}
front_ip="${subnet%.*}.10"
network=hallpass-docs-net
containers=()
ctx=$(mktemp -d)

cleanup() {
  for c in ${containers[@]+"${containers[@]}"}; do docker rm -f "$c" >/dev/null 2>&1 || true; done
  docker network rm "$network" >/dev/null 2>&1 || true
  rm -rf "$ctx"
}
trap cleanup EXIT

# Own build context: the repository's .dockerignore excludes test/ and scripts/.
cp "$root/test/openssh/sshd_config" "$root/scripts/screenshots/dest-entrypoint.sh" "$ctx/"
docker build -q -t "$image" -f "$root/scripts/screenshots/Dockerfile.dest" "$ctx" >/dev/null
port=2431
for host in web1 db1 ci-runner forge; do
  name="hallpass-docs-$host"
  docker rm -f "$name" >/dev/null 2>&1 || true
  docker run -d --name "$name" --hostname "$host" -p "127.0.0.1:$port:22" "$image" >/dev/null
  containers+=("$name")
  port=$((port + 1))
done

# ---- Fake upstreams ------------------------------------------------------------------------------------------------
mkdir -p "$ctx/tls" "$ctx/nginx" "$ctx/s3" "$ctx/bin"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 -subj "/CN=HallPass docs fake upstream CA" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign" \
  -keyout "$ctx/tls/ca.key" -out "$ctx/tls/ca.pem" 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -subj "/CN=api.github.com" \
  -keyout "$ctx/tls/front.key" -out "$ctx/tls/front.csr" 2>/dev/null
printf 'subjectAltName=DNS:api.github.com,DNS:s3.example.com\nextendedKeyUsage=serverAuth\n' >"$ctx/tls/ext.cnf"
openssl x509 -req -in "$ctx/tls/front.csr" -CA "$ctx/tls/ca.pem" -CAkey "$ctx/tls/ca.key" -CAcreateserial -days 2 \
  -extfile "$ctx/tls/ext.cnf" -out "$ctx/tls/front.pem" 2>/dev/null
chmod 0644 "$ctx/tls/"*

s3_access=hallpassdocs
s3_secret=$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')
cat >"$ctx/s3/s3.json" <<JSON
{"identities":[{"name":"hallpass","credentials":[{"accessKey":"$s3_access","secretKey":"$s3_secret"}],"actions":["Admin","Read","List","Write"]}]}
JSON
chmod 0644 "$ctx/s3/s3.json"

# Canned, invented GitHub responses for the calls the spec makes; everything else is 404. The gateway refuses
# disallowed calls before they get here.
cat >"$ctx/nginx/default.conf" <<'NGINX'
server {
  listen 443 ssl;
  server_name api.github.com;
  ssl_certificate /etc/nginx/tls/front.pem;
  ssl_certificate_key /etc/nginx/tls/front.key;
  default_type application/json;
  location = /repos/acme/shop/issues {
    return 200 '[{"number":412,"title":"Cart times out under load","state":"open"},{"number":409,"title":"Checkout button overlaps the footer on mobile","state":"open"},{"number":405,"title":"Upgrade the PostgreSQL client to 16","state":"open"}]';
  }
  location = /repos/acme/shop/issues/412/comments {
    return 201 '{"id":2190,"html_url":"https://github.com/acme/shop/issues/412#issuecomment-2190"}';
  }
  location / {
    return 404 '{"message":"Not Found"}';
  }
}
server {
  listen 443 ssl;
  server_name s3.example.com;
  ssl_certificate /etc/nginx/tls/front.pem;
  ssl_certificate_key /etc/nginx/tls/front.key;
  client_max_body_size 0;
  location / {
    proxy_pass http://hallpass-docs-s3:8333;
    proxy_set_header Host $host;
    proxy_request_buffering off;
  }
}
NGINX
chmod 0644 "$ctx/nginx/default.conf"

# Leftovers of an interrupted run first: the network cannot be removed while containers use it.
for c in hallpass-docs-s3 hallpass-docs-front; do docker rm -f "$c" >/dev/null 2>&1 || true; done
docker network rm "$network" >/dev/null 2>&1 || true
docker network create --subnet "$subnet" "$network" >/dev/null
docker run -d --name hallpass-docs-s3 --network "$network" -v "$ctx/s3:/cfg:ro" "$s3_image" \
  server -dir=/data -s3 -s3.port=8333 -s3.config=/cfg/s3.json >/dev/null
containers+=(hallpass-docs-s3)
docker run -d --name hallpass-docs-front --network "$network" --ip "$front_ip" \
  -v "$ctx/nginx:/etc/nginx/conf.d:ro" -v "$ctx/tls:/etc/nginx/tls:ro" "$nginx_image" >/dev/null
containers+=(hallpass-docs-front)
for _ in $(seq 1 60); do
  if echo "s3.bucket.create -name hallpass-backups" | docker exec -i hallpass-docs-s3 weed shell 2>/dev/null | grep -q "created bucket"; then
    break
  fi
  sleep 1
done

(cd "$root" && CGO_ENABLED=0 go build -o "$ctx/bin/hallpass-api" ./cmd/hallpass-api)

# The spec scans host keys first; web1 writes a large demo log before its sshd starts.
for port in 2431 2432 2433 2434; do
  for _ in $(seq 1 120); do
    if banner=$(timeout 2 bash -c "exec 3<>/dev/tcp/127.0.0.1/$port && head -c 4 <&3" 2>/dev/null) && [[ $banner == SSH- ]]; then
      break
    fi
    sleep 0.5
  done
done

# Long reauthentication window: the spec seeds everything through the API right after signing in. The API proxy may
# reach the fakes' private subnet; backups opt in per target ("Allow a private network").
HP_SCREENSHOTS_OUT=$out E2E_SOURCE_ADDRESS=192.0.2.10 \
  E2E_EXTRA_CONFIG=$'auth:\n  reauth_window: 1h\napi_proxy:\n  allow_special_cidrs: ['"$subnet"']' \
  E2E_ADD_HOSTS="api.github.com:$front_ip s3.example.com:$front_ip" E2E_CA_FILE="$ctx/tls/ca.pem" \
  HP_DOCS_HALLPASS_API="$ctx/bin/hallpass-api" HP_DOCS_CA_PEM="$ctx/tls/ca.pem" \
  HP_DOCS_S3_ACCESS_KEY="$s3_access" HP_DOCS_S3_SECRET_KEY="$s3_secret" \
  "$root/scripts/e2e.sh" --project=screenshots
echo "screenshots written to $out"
