#!/usr/bin/env bash
# HACKERADE scanner launcher for Linux / macOS (the .bat version is Windows-only).
set -uo pipefail

cd "$(dirname "$0")" || exit 1

PORT="${PORT:-3000}"
URL="http://localhost:${PORT}"
OPEN_BROWSER=1

for arg in "$@"; do
  case "$arg" in
    --no-browser|-n) OPEN_BROWSER=0 ;;
    -h|--help)
      echo "Usage: ./start.sh [--no-browser]"
      echo "  --no-browser, -n   Start the server without opening a browser"
      exit 0
      ;;
    *)
      echo "[error] Unknown option: $arg (try --help)"
      exit 1
      ;;
  esac
done

# True when something is already listening on the port.
is_up() {
  (exec 3<>"/dev/tcp/127.0.0.1/${PORT}") >/dev/null 2>&1
}

open_url() {
  if command -v xdg-open >/dev/null 2>&1; then
    xdg-open "$URL" >/dev/null 2>&1 &
  elif command -v open >/dev/null 2>&1; then
    open "$URL" >/dev/null 2>&1 &
  elif command -v gio >/dev/null 2>&1; then
    gio open "$URL" >/dev/null 2>&1 &
  else
    echo "[web] Open $URL in your browser."
  fi
}

# A server is already up: no Node.js needed, just open the page.
if is_up; then
  echo "[info] Scanner is already running at $URL"
  if [ "$OPEN_BROWSER" -eq 1 ]; then
    open_url
    echo "[web] Opened it in your browser."
  else
    echo "[info] Browser skipped because --no-browser was passed."
  fi
  exit 0
fi

node_ok() {
  command -v node >/dev/null 2>&1 &&
    node -e 'process.exit(Number(process.versions.node.split(".")[0]) >= 20 ? 0 : 1)' >/dev/null 2>&1
}

load_nvm() {
  export NVM_DIR="${NVM_DIR:-$HOME/.nvm}"
  # shellcheck disable=SC1091
  [ -s "$NVM_DIR/nvm.sh" ] && . "$NVM_DIR/nvm.sh"
}

install_node() {
  echo "[setup] Node.js 20+ was not found."
  load_nvm

  if ! command -v nvm >/dev/null 2>&1; then
    echo "[setup] Installing nvm (user-level, no root required)..."
    if command -v curl >/dev/null 2>&1; then
      curl -fsSL https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash
    elif command -v wget >/dev/null 2>&1; then
      wget -qO- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash
    else
      echo "[error] curl or wget is required to install Node.js automatically."
      return 1
    fi
    load_nvm
  fi

  command -v nvm >/dev/null 2>&1 || return 1

  echo "[setup] Installing Node.js 22 LTS (this happens once)..."
  nvm install 22 && nvm use 22 >/dev/null
}

if ! node_ok; then
  if ! install_node; then
    cat <<'EOF'

[error] Node.js 20+ is required to run this app, and the automatic install failed.

Options:
  1. Install Node.js yourself from https://nodejs.org/en/download, or with nvm:
       curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash
       nvm install 22
  2. Run the scanner on another machine (e.g. your Windows host with start.bat)
     and open http://<host-ip>:3000 from this machine's browser. No Node.js is
     needed on this machine for that.

EOF
    exit 1
  fi
  node_ok || { echo "[error] Node.js install did not complete."; exit 1; }
fi

if [ ! -d "node_modules" ]; then
  echo "[setup] node_modules missing, installing dependencies..."
  if ! npm install; then
    echo "[error] npm install failed. Check your internet connection and try again."
    exit 1
  fi
fi

if [ ! -f ".env.local" ]; then
  echo "[warn] .env.local not found - VIRUSTOTAL_API_KEY is required for scans."
fi

if [ "$OPEN_BROWSER" -eq 1 ]; then
  (
    for _ in $(seq 1 240); do
      if is_up; then
        open_url
        break
      fi
      sleep 0.5
    done
  ) &
  echo "[web] Browser will open automatically when the server is ready."
fi

echo "[info] Starting HACKERADE scanner on $URL"
echo "[info] Press Ctrl+C in this terminal to stop it."
echo

attempts=0
while :; do
  # stdin from /dev/null keeps Next.js from opening its interactive upgrade menu.
  npm run dev -- -p "$PORT" < /dev/null
  status=$?

  [ "$status" -eq 0 ] && break
  is_up && break

  attempts=$((attempts + 1))
  if [ "$attempts" -ge 3 ]; then
    echo
    echo "[error] Could not start the scanner. Scroll up for the error output."
    exit 1
  fi

  echo
  echo "[info] Next.js exited early, retrying (${attempts}/3)..."
  sleep 2
done

echo
echo "[info] Scanner stopped."
