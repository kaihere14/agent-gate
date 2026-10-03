#!/usr/bin/env bash
# Keeps Kev's prefix cache warm by POSTing the exact gate request shape every
# 15 s. Only sends requests; never starts, stops or changes the Kev server.
#
# Start:  ./scripts/keepwarm.sh &        (or: nohup ./scripts/keepwarm.sh >/dev/null 2>&1 &)
# Stop:   kill %1   (or the PID it prints)
set -u
cd "$(dirname "$0")/.."
INTERVAL="${KEEPWARM_INTERVAL:-15}"
BODY="$(mktemp)"
trap 'rm -f "$BODY"' EXIT
# Built by the same code as the gate, so the instructions are byte-identical.
bun -e '
import { buildQuestions, buildState } from "./plugin/kev.ts"
const state = buildState({ tool: "run_commands", commands: ["git status --short"] })
process.stdout.write(JSON.stringify({ state, questions: buildQuestions() }))
' > "$BODY" || exit 1
URL="${KEV_URL:-http://localhost:8008/v1/systemone}"
echo "keepwarm: pid $$, POST $URL every ${INTERVAL}s"
while true; do
  t=$(curl -s -o /dev/null -w '%{http_code} %{time_total}s' -X POST -H 'content-type: application/json' --data @"$BODY" "$URL" || echo "fail")
  echo "$(date +%H:%M:%S) $t"
  sleep "$INTERVAL"
done
