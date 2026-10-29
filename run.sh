#!/usr/bin/env bash
# Start the mail-send door. WHERE it listens is the deployment's, never a default:
#   MAIL_SEND_UDS   a unix socket path, behind the proxy — only the proxy's user may enter its
#                   directory; no TCP port is opened
#   MAIL_SEND_PORT  a loopback port (a developer's box)
# Neither placed: refused by name. Both placed: refused — a deployment listens one way.
set -euo pipefail
cd "$(dirname "$0")"
PY=${MAIL_SEND_PYTHON:-python3}
uds=${MAIL_SEND_UDS:-}; port=${MAIL_SEND_PORT:-}
if [ -n "$uds" ] && [ -n "$port" ]; then
  echo "mail-send: both MAIL_SEND_UDS and MAIL_SEND_PORT are set — a deployment listens one way" >&2; exit 2
elif [ -n "$uds" ]; then
  exec "$PY" -m uvicorn mailsend.app:app --uds "$uds" --proxy-headers
elif [ -n "$port" ] && [ "${MAIL_SEND_ENV:-}" = production ]; then
  echo "mail-send: MAIL_SEND_PORT has no proxy in front, so no verified identity — production listens on MAIL_SEND_UDS" >&2; exit 2
elif [ -n "$port" ]; then
  exec "$PY" -m uvicorn mailsend.app:app --host 127.0.0.1 --port "$port"
fi
echo "mail-send: neither MAIL_SEND_UDS nor MAIL_SEND_PORT is set in this deployment" >&2
exit 2
