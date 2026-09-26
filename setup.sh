#!/usr/bin/env bash
# PostureHound - one-time setup: create a virtual environment and install deps.
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

PYTHON="${PYTHON:-python3}"

if ! command -v "$PYTHON" >/dev/null 2>&1; then
  echo "[PostureHound] '$PYTHON' not found. Install Python 3.10+ and retry." >&2
  exit 1
fi

echo "[PostureHound] Creating virtual environment (.venv) ..."
"$PYTHON" -m venv .venv

echo "[PostureHound] Upgrading pip ..."
./.venv/bin/pip install --quiet --upgrade pip

echo "[PostureHound] Installing dependencies (includes the AI finding-generation library) ..."
./.venv/bin/pip install --quiet -r requirements.txt

echo "[PostureHound] Installing test dependencies ..."
./.venv/bin/pip install --quiet -r requirements-dev.txt

# weasyprint renders the shareable PDF report but needs native libraries
# (pango/cairo). The pip package installs regardless; without the libs the app
# still runs and serves a printable HTML report instead. Try to install them so
# the PDF works out of the box. Best-effort and non-fatal.
install_pdf_libs() {
  if ./.venv/bin/python -c "import weasyprint" >/dev/null 2>&1; then
    return 0   # native libs already present
  fi
  echo "[PostureHound] Installing PDF-report native libraries (pango/cairo) ..."
  if [ "$(uname)" = "Darwin" ] && command -v brew >/dev/null 2>&1; then
    brew install pango >/dev/null 2>&1 || true
  elif command -v apt-get >/dev/null 2>&1; then
    sudo apt-get install -y libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf-2.0-0 \
         libffi-dev libcairo2 >/dev/null 2>&1 || true
  fi
  if ! ./.venv/bin/python -c "import weasyprint" >/dev/null 2>&1; then
    echo "[PostureHound] Note: PDF libraries not installed. The report still works -"
    echo "[PostureHound]   the Export button will serve a printable HTML page instead."
    echo "[PostureHound]   To enable direct PDF export: 'brew install pango' (macOS) or the"
    echo "[PostureHound]   distro equivalent, then re-run ./setup.sh."
  fi
}
install_pdf_libs

echo "[PostureHound] Setup complete. Start the app with:  ./start.sh"
