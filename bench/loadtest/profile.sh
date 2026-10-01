#!/usr/bin/env bash
# Profile the packaged service under load with Java Flight Recorder: one
# recording per scenario, then the hot methods, allocation sites, GC and lock
# contention of each, so a change is aimed at where the time goes.
#
# Boots the same throwaway Postgres, Redis and JWKS endpoint as run.sh (MODE=serve),
# starts a recording per scenario with `jcmd`, drives wrk, and dumps it.
#
# Usage:
#   bench/loadtest/profile.sh                    # all scenarios, 30 s each
#   SCENARIOS="bearer" DURATION=60s bench/loadtest/profile.sh
#   OUT=/tmp/jfr bench/loadtest/profile.sh
#
# Scenarios (SCENARIOS, space separated):
#   bearer       20 000 distinct Bearer tokens: verified-token cache + revocation
#                cache + Redis, the common production path
#   bearer-cold  the same with the verified-token cache off: every request
#                verifies an RS256 signature
#   dpop         DPoP, no server nonce: ES256 proof verification + a Redis write
#
# Results in $OUT (default target/jfr): <scenario>.jfr plus <scenario>.txt with
# the summary. Open a .jfr in JDK Mission Control for the full picture.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
OUT=${OUT:-$ROOT/target/jfr}
DURATION=${DURATION:-30s}
SCENARIOS=${SCENARIOS:-"bearer bearer-cold dpop"}
THREADS=${THREADS:-4}
CONNS=${CONNS:-48}
WORK=${WORK:-$(mktemp -d)}
PROOFS=${PROOFS:-150000}
HTTP_PORT=18080
BASE="http://127.0.0.1:$HTTP_PORT"
ISSUER="https://as.load.test"
AUDIENCE="https://api.load.test"
HTU="https://127.0.0.1:$HTTP_PORT/me"

# Linux: SERVER_CPUS / LOAD_CPUS pin the service (via run.sh) and wrk to separate
# cores, as in run.sh.
LOAD_CPUS=${LOAD_CPUS:-}
LOAD_PIN=()
[[ -n "$LOAD_CPUS" ]] && LOAD_PIN=(taskset -c "$LOAD_CPUS")

# jfr ships with the JDK but is often off PATH (on macOS `java` is a shim), and
# JAVA_HOME may name a JDK that is gone: take the first candidate that exists.
JFR=""
for candidate in \
  "$(command -v jfr || true)" \
  "${JAVA_HOME:+$JAVA_HOME/bin/jfr}" \
  "$([[ -x /usr/libexec/java_home ]] && /usr/libexec/java_home 2>/dev/null)/bin/jfr" \
  "$(dirname "$(readlink -f "$(command -v java)")")/jfr"; do
  if [[ -n "$candidate" && -x "$candidate" ]]; then JFR=$candidate; break; fi
done
[[ -n "$JFR" ]] || { echo "jfr not found; it ships with the JDK (bin/jfr)" >&2; exit 1; }

mkdir -p "$OUT"
RUN_PID=""
BOOT=0
MATERIAL_DIR=""
cleanup() {
  set +e
  [[ -n "$RUN_PID" ]] && kill -TERM "$RUN_PID" 2>/dev/null && wait "$RUN_PID" 2>/dev/null
}
trap cleanup EXIT
trap 'exit 143' INT TERM HUP

# Boot with the verified-token cache as configured; the cold scenario restarts
# the service with it off. `profile` settings sample at 10 ms, and the extra
# options keep method names resolvable in the recording.
JFR_OPTS="-XX:+UnlockDiagnosticVMOptions -XX:+DebugNonSafepoints"

boot() { # extra server options
  [[ -n "$RUN_PID" ]] && { kill -TERM "$RUN_PID" 2>/dev/null; wait "$RUN_PID" 2>/dev/null || true; RUN_PID=""; }
  # run.sh in serve mode holds everything up until it is killed. Its Redis and
  # Postgres must be gone before the next boot; wait for the ports.
  for _ in $(seq 1 30); do
    lsof -nP -iTCP:"$HTTP_PORT" -iTCP:6379 -iTCP:55432 -iTCP:8443 -sTCP:LISTEN -t >/dev/null 2>&1 || break
    sleep 1
  done
  # A fresh directory per boot: run.sh refuses to initdb over an old one.
  BOOT=$((BOOT + 1))
  MATERIAL_DIR="$WORK/boot-$BOOT"
  MODE=serve WORK="$MATERIAL_DIR" SERVER_OPTS="$JFR_OPTS $1" TOKENS=20000 \
    bash "$HERE/run.sh" >"$OUT/serve-$BOOT.log" 2>&1 &
  RUN_PID=$!
  for _ in $(seq 1 180); do
    curl -fs "$BASE/ready" >/dev/null 2>&1 && return 0
    sleep 1
  done
  echo "service did not become ready; see $OUT/serve-$BOOT.log" >&2
  exit 1
}

server_pid() { lsof -nP -iTCP:"$HTTP_PORT" -sTCP:LISTEN -t | head -1; }

# Warm up (JIT, caches), then record exactly the measured window.
record() { # scenario, wrk args...
  local name=$1
  shift
  local pid
  pid=$(server_pid)
  echo "[$(date +%H:%M:%S)] $name: warm-up"
  ${LOAD_PIN[@]+"${LOAD_PIN[@]}"} wrk -t"$THREADS" -c"$CONNS" -d15s "$@" >/dev/null
  echo "[$(date +%H:%M:%S)] $name: recording $DURATION"
  jcmd "$pid" JFR.start name="$name" settings=profile >/dev/null
  ${LOAD_PIN[@]+"${LOAD_PIN[@]}"} wrk -t"$THREADS" -c"$CONNS" -d"$DURATION" --latency "$@" | tee "$OUT/$name.wrk.txt" | grep -E 'Requests/sec|99%'
  jcmd "$pid" JFR.dump name="$name" filename="$OUT/$name.jfr" >/dev/null
  jcmd "$pid" JFR.stop name="$name" >/dev/null
  summarize "$name"
}

summarize() { # scenario
  local f="$OUT/$1.jfr"
  {
    echo "=== $1: hot methods (top frame, by samples)"
    "$JFR" view --width 160 hot-methods "$f" 2>/dev/null | head -28
    echo
    echo "=== $1: allocation by site (sampled)"
    "$JFR" view --width 160 allocation-by-site "$f" 2>/dev/null | head -22
    echo
    echo "=== $1: GC"
    "$JFR" view --width 160 gc "$f" 2>/dev/null | head -12
    echo
    echo "=== $1: lock contention"
    "$JFR" view --width 160 contention-by-site "$f" 2>/dev/null | head -14
  } >"$OUT/$1.txt"
  echo "  summary: $OUT/$1.txt"
}

for scenario in $SCENARIOS; do
  case "$scenario" in
    bearer)
      boot ""
      record bearer -s "$HERE/bearer.lua" "$BASE/me" -- "$MATERIAL_DIR/material/tokens.txt"
      ;;
    bearer-cold)
      boot "-Dapp.auth.cache.verified-tokens=0"
      record bearer-cold -s "$HERE/bearer.lua" "$BASE/me" -- "$MATERIAL_DIR/material/tokens.txt"
      ;;
    dpop)
      boot ""
      (cd "$ROOT" && sbt --client "bench/runMain bench.MintLoadTokens $MATERIAL_DIR/material $ISSUER $AUDIENCE $HTU 0 $PROOFS" |
        grep -E "Wrote|error") || true
      record dpop -s "$HERE/dpop.lua" "$BASE/me" -- "$MATERIAL_DIR/material/dpop.txt" "$THREADS"
      ;;
    *) echo "unknown scenario '$scenario' (bearer, bearer-cold, dpop)" >&2; exit 1 ;;
  esac
done

echo
echo "Recordings and summaries in $OUT"
