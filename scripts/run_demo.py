from __future__ import annotations

import socket
import subprocess
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def port_available(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        return s.connect_ex(("127.0.0.1", port)) != 0


def pick_port(preferred: int = 8000) -> int:
    if port_available(preferred):
        return preferred
    for port in range(8001, 8011):
        if port_available(port):
            return port
    raise RuntimeError("No free port in 8000-8010")


def run() -> int:
    python = sys.executable

    print("[1/2] Initializing demo DB...")
    init_cmd = [python, str(BASE_DIR / "scripts" / "init_demo.py")]
    init_proc = subprocess.run(init_cmd, cwd=BASE_DIR)
    if init_proc.returncode != 0:
        return init_proc.returncode

    port = pick_port(8000)
    print("[2/2] Starting demo server...")
    print(f"Open this URL in browser: http://127.0.0.1:{port}/")
    print("(Press Ctrl+C to stop)")

    app_cmd = [python, str(BASE_DIR / "webapp" / "app.py"), "--port", str(port)]
    return subprocess.call(app_cmd, cwd=BASE_DIR)


if __name__ == "__main__":
    raise SystemExit(run())
