#!/usr/bin/env bash
# PostureHound - start the read-only web app.
#   HOST / PORT override the bind address (default 127.0.0.1:31013).
#   WORKERS sets uvicorn worker count (default 1).
#   PH_MAX_UPLOAD_MB  per-file upload cap   (default 512)
#   PH_MAX_TOTAL_MB   combined upload cap   (default 1024)
# Keep it bound to localhost unless you have placed it behind your own
# authenticated, TLS-terminating reverse proxy.
set -euo pipefail
cd "$(dirname "$0")"

# A stale corporate-TLS CA bundle in the environment breaks every HTTPS client
# here (pip, git, httpx, the Anthropic SDK) with a bare "invalid path" error.
# These vars survive uninstalling the proxy, so drop any that name a file that
# is no longer on disk and fall back to the system trust store.
scrub_stale_ca_env() {
  local var path dropped=""
  for var in SSL_CERT_FILE SSL_CERT_DIR REQUESTS_CA_BUNDLE CURL_CA_BUNDLE \
             PIP_CERT GIT_SSL_CAINFO NODE_EXTRA_CA_CERTS AWS_CA_BUNDLE \
             CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE HOMEBREW_CACERT; do
    path="${!var:-}"
    [ -n "$path" ] || continue
    [ -e "$path" ] && continue
    unset "$var"
    dropped="$dropped $var"
  done
  if [ -n "$dropped" ]; then
    echo "[PostureHound] Ignoring CA-bundle variable(s) pointing at a missing file:$dropped"
    echo "[PostureHound] Using the system trust store instead."
  fi
}
scrub_stale_ca_env

if [ ! -x ./.venv/bin/python ]; then
  echo "[PostureHound] .venv not found - run ./setup.sh first." >&2
  exit 1
fi

HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-31013}"
WORKERS="${WORKERS:-1}"
export PYTHONPATH="$(pwd)/src"

echo "[PostureHound] Serving on http://${HOST}:${PORT}  (Ctrl-C to stop)"
exec ./.venv/bin/python -m uvicorn posturehound.api:app \
  --host "$HOST" --port "$PORT" --workers "$WORKERS"
