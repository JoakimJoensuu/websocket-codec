#!/usr/bin/env bash
# Run Autobahn fuzzingclient against the wsio echo server.
# HTTP upgrade lives only in examples/echo_server.c; this script is I/O glue.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PORT="${PORT:-9001}"
IMAGE="${AUTOBAHN_IMAGE:-crossbario/autobahn-testsuite}"

if [[ ! -x "$ROOT/build/echo_server" ]]; then
  echo "build echo_server first: cmake -B build && cmake --build build --target echo_server" >&2
  exit 1
fi

SERVER="$ROOT/build/echo_server"

mkdir -p "$ROOT/autobahn/reports/servers"

"$SERVER" "$PORT" &
SPID=$!
cleanup() {
  kill "$SPID" 2>/dev/null || true
  wait "$SPID" 2>/dev/null || true
}
trap cleanup EXIT

for i in $(seq 1 50); do
  if (echo >/dev/tcp/127.0.0.1/"$PORT") >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done

if command -v docker >/dev/null 2>&1; then
  docker run --rm \
    --network host \
    -v "$ROOT/autobahn/fuzzingclient.docker.json:/config/fuzzingclient.json:ro" \
    -v "$ROOT/autobahn/reports:/reports" \
    "$IMAGE" \
    wstest -m fuzzingclient -s /config/fuzzingclient.json
elif command -v wstest >/dev/null 2>&1; then
  (cd "$ROOT/autobahn" && wstest -m fuzzingclient -s fuzzingclient.json)
else
  echo "install docker (image $IMAGE) or wstest from autobahn-testsuite" >&2
  exit 1
fi

REPORT="$ROOT/autobahn/reports/servers/index.json"
if [[ -f "$REPORT" ]]; then
  python3 - "$REPORT" <<'PY'
import json, sys
path = sys.argv[1]
data = json.load(open(path))
failed = []
for agent, cases in data.items():
    for case, info in cases.items():
        behavior = info.get("behavior") or info.get("behaviorClose")
        # Autobahn uses OK / INFORMATIONAL / UNIMPLEMENTED / FAILED / NON-STRICT
        b = info.get("behavior", "")
        if b not in ("OK", "INFORMATIONAL", "NON-STRICT"):
            failed.append((agent, case, b, info.get("behaviorClose", "")))
if failed:
    print("failed cases:")
    for row in failed:
        print("  ", row)
    sys.exit(1)
print("all reported cases passed (%s)" % path)
PY
fi
