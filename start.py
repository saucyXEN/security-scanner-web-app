#!/usr/bin/env python3
"""Start the HACKERADE scanner.

The app itself is a Next.js project, so it needs Node.js. This launcher makes
that painless: if Node.js is missing on Linux or macOS it downloads a private
copy into ~/.cache/hackerade-node (no root, no nvm) and uses it only for this
project. On Windows it expects Node.js to be installed already.

Usage:
    python3 start.py                  start + open the browser
    python3 start.py --no-browser     start without opening a browser
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import urllib.request
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PORT = int(os.environ.get("PORT", "3000"))
URL = f"http://localhost:{PORT}"
CACHE = Path.home() / ".cache" / "hackerade-node"
MIN_NODE_MAJOR = 20
PREFERRED_NODE_MAJOR = 22
IS_WINDOWS = os.name == "nt"


def wants_browser(argv: list[str]) -> bool:
    return "--no-browser" not in argv and "-n" not in argv


def port_open() -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.5)
        return sock.connect_ex(("127.0.0.1", PORT)) == 0


def open_browser() -> None:
    try:
        webbrowser.open(URL)
    except Exception:
        print(f"[web] Open {URL} in your browser.")


def open_when_ready() -> None:
    for _ in range(240):
        if port_open():
            open_browser()
            return
        time.sleep(0.5)


def node_major(binary: Path) -> int:
    try:
        result = subprocess.run([str(binary), "-v"], capture_output=True, text=True, timeout=10)
    except OSError:
        return 0
    if result.returncode != 0:
        return 0
    try:
        return int(result.stdout.strip().lstrip("v").split(".")[0])
    except ValueError:
        return 0


def find_node() -> Path | None:
    found = shutil.which("node")
    if found:
        directory = Path(found).parent
        if node_major(Path(found)) >= MIN_NODE_MAJOR:
            return directory

    if not IS_WINDOWS and CACHE.is_dir():
        for entry in sorted(CACHE.glob("node-*"), reverse=True):
            directory = entry / "bin"
            if (directory / "node").is_file() and node_major(directory / "node") >= MIN_NODE_MAJOR:
                return directory
    return None


def platform_suffix() -> str | None:
    system = platform.system().lower()
    if system not in ("linux", "darwin"):
        return None
    arch = {
        "x86_64": "x64",
        "amd64": "x64",
        "aarch64": "arm64",
        "arm64": "arm64",
    }.get(platform.machine().lower())
    return f"{system}-{arch}" if arch else None


def latest_node_version() -> str:
    with urllib.request.urlopen("https://nodejs.org/dist/index.json", timeout=30) as response:
        releases = json.load(response)
    for release in releases:
        if release["version"].startswith(f"v{PREFERRED_NODE_MAJOR}."):
            return release["version"]
    return releases[0]["version"]


def download_node() -> Path | None:
    suffix = platform_suffix()
    if not suffix:
        return None

    print("[setup] Node.js was not found. Downloading a private copy (no root needed)...")
    try:
        version = latest_node_version()
        name = f"node-{version}-{suffix}"
        url = f"https://nodejs.org/dist/{version}/{name}.tar.gz"
        CACHE.mkdir(parents=True, exist_ok=True)

        with tempfile.TemporaryDirectory(dir=CACHE) as temp:
            archive = Path(temp) / "node.tar.gz"
            with urllib.request.urlopen(url, timeout=300) as response, archive.open("wb") as target:
                shutil.copyfileobj(response, target)
            with tarfile.open(archive, "r:gz") as tar:
                try:
                    tar.extractall(CACHE, filter="data")
                except TypeError:  # Python < 3.12
                    tar.extractall(CACHE)

        bindir = CACHE / name / "bin"
        if (bindir / "node").is_file():
            return bindir
    except Exception as error:
        print(f"[error] Could not download Node.js: {error}")
    return None


def npm_command(env: dict[str, str]) -> str | None:
    return shutil.which("npm", path=env.get("PATH"))


def run_npm(npm: str, args: list[str], env: dict[str, str]) -> int:
    # stdin from DEVNULL keeps Next.js from opening its interactive upgrade menu.
    return subprocess.call([npm, *args], cwd=ROOT, env=env, stdin=subprocess.DEVNULL)


def main(argv: list[str]) -> int:
    if "-h" in argv or "--help" in argv:
        print(__doc__.strip())
        return 0

    if port_open():
        print(f"[info] Scanner is already running at {URL}")
        if wants_browser(argv):
            open_browser()
            print("[web] Opened it in your browser.")
        else:
            print("[info] Browser skipped because --no-browser was passed.")
        return 0

    bindir = find_node() or download_node()
    if not bindir:
        print(
            "\n[error] Node.js 20+ is required to run this app and could not be prepared.\n"
            "\nOptions:\n"
            "  1. Install Node.js from https://nodejs.org/en/download and run this again.\n"
            f"  2. Run the scanner on another machine and open {URL} from this one\n"
            "     (no Node.js needed here just to use the app).\n"
        )
        return 1

    env = os.environ.copy()
    env["PATH"] = str(bindir) + os.pathsep + env.get("PATH", "")

    npm = npm_command(env)
    if not npm:
        print("[error] npm was not found next to Node.js.")
        return 1

    if not (ROOT / "node_modules").is_dir():
        print("[setup] node_modules missing, installing dependencies...")
        if run_npm(npm, ["install"], env) != 0:
            print("[error] npm install failed. Check your internet connection and try again.")
            return 1

    if not (ROOT / ".env.local").is_file():
        print("[warn] .env.local not found - VIRUSTOTAL_API_KEY is required for scans.")

    if wants_browser(argv):
        threading.Thread(target=open_when_ready, daemon=True).start()
        print("[web] Browser will open automatically when the server is ready.")

    print(f"[info] Starting HACKERADE scanner on {URL}")
    print("[info] Press Ctrl+C in this terminal to stop it.\n", flush=True)

    attempts = 0
    while True:
        try:
            code = run_npm(npm, ["run", "dev", "--", "-p", str(PORT)], env)
        except KeyboardInterrupt:
            break

        if code == 0 or port_open():
            break

        attempts += 1
        if attempts >= 3:
            print("\n[error] Could not start the scanner. Scroll up for the error output.")
            return 1
        print(f"\n[info] Next.js exited early, retrying ({attempts}/3)...")
        time.sleep(2)

    print("\n[info] Scanner stopped.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
