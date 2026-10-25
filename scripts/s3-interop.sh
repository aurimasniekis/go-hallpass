#!/usr/bin/env bash
# Run the object storage client against a real S3-compatible server (SeaweedFS in Docker): signatures, keys with
# spaces and '+', list, head, get, delete. Used by `make test-s3-interop` and nightly CI.
set -euo pipefail

IMAGE="${S3_INTEROP_IMAGE:-chrislusf/seaweedfs@sha256:bb05d66d2963b1cc48073190781c3dd29e2c4c88a2ae2986bf58e38c86d89c6e}" # 3.97
NAME="hallpass-s3-interop-$$"
PORT="${S3_INTEROP_PORT:-18333}"
ACCESS="hallpassinterop"
SECRET="$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')"
CFG="$(mktemp -d)"
trap 'docker rm -f "$NAME" >/dev/null 2>&1 || true; rm -rf "$CFG"' EXIT

cat >"$CFG/s3.json" <<JSON
{"identities":[{"name":"hallpass","credentials":[{"accessKey":"$ACCESS","secretKey":"$SECRET"}],"actions":["Admin","Read","List","Write"]}]}
JSON
chmod 0644 "$CFG/s3.json"
docker run -d --name "$NAME" -p "127.0.0.1:$PORT:8333" -v "$CFG:/cfg:ro" "$IMAGE" \
  server -dir=/data -s3 -s3.port=8333 -s3.config=/cfg/s3.json >/dev/null
for _ in $(seq 1 60); do
  if echo "s3.bucket.create -name hp-interop" | docker exec -i "$NAME" weed shell 2>/dev/null | grep -q "created bucket"; then
    break
  fi
  sleep 1
done

HALLPASS_TEST_S3_ENDPOINT="http://127.0.0.1:$PORT" HALLPASS_TEST_S3_BUCKET=hp-interop HALLPASS_TEST_S3_ACCESS_KEY="$ACCESS" \
  HALLPASS_TEST_S3_SECRET_KEY="$SECRET" HALLPASS_TEST_S3_PATH_STYLE=1 \
  go test -count=1 -run TestInterop -v ./internal/s3client/
