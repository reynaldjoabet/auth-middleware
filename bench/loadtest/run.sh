#!/usr/bin/env bash
# End-to-end load test of the packaged service (the output of `sbt stage`), run
# against throwaway local dependencies: Postgres, Redis, and an HTTPS JWKS
# endpoint serving a freshly minted issuer key. Everything lives in $WORK and
# is torn down on exit.
#
# Requires: postgres (initdb/pg_ctl), redis-server, wrk, openssl, keytool,
# python3. Usage:
#
#   bench/loadtest/run.sh                       # defaults below
#   DURATION=30s CONNS=32 bench/loadtest/run.sh
#   MODE=serve bench/loadtest/run.sh            # start everything, then hold
#                                                 (for profiling; kill to stop)
#   SERVER_OPTS="-Dcats.effect.tracing.mode=none" bench/loadtest/run.sh
#   SERVICE=zio bench/loadtest/run.sh           # the ZIO build (module zio);
#                                                 Bearer only, so no DPoP scenarios
#   OTEL_SDK_DISABLED=true bench/loadtest/run.sh  # OpenTelemetry off (the ZIO
#                                                 build has none; use for A/B)
#   STORE=postgres bench/loadtest/run.sh        # shared auth state (denylist,
#                                                 DPoP jtis and nonces) in
#                                                 Postgres instead of Redis
#   STORE=postgres STORE_PG_MAX_BATCH=1 ...     # ...one statement per call
#   ROOT=/path/to/other/checkout bench/loadtest/run.sh  # test another tree
#                                                 with this harness
#   SERVER_CPUS=0-2 LOAD_CPUS=3 THREADS=1 ...   # Linux: service and wrk on
#                                                 separate cores
#
# CONNS stays below 50 on purpose. fs2 binds the listening socket with the
# JDK's default backlog of 50, so opening more connections than that at once
# overflows the accept queue: the kernel resets the extras, the client
# reconnects, and the reconnects overflow it again. Throughput does not
# improve past a few dozen connections anyway.
#
# The load generator shares the machine with the server, so absolute numbers
# are a floor for the hardware, not a production capacity figure.
set -euo pipefail

# The harness (this directory) can drive another checkout: ROOT is the tree
# built and tested, SCRIPTS always this copy of the Lua scripts. That is how
# compare.sh runs two versions under the same harness.
SCRIPTS=$(cd "$(dirname "$0")" && pwd)
ROOT=${ROOT:-$(cd "$SCRIPTS/../.." && pwd)}
WORK=${WORK:-$(mktemp -d)}
DURATION=${DURATION:-20s}
DPOP_DURATION=${DPOP_DURATION:-15s}
THREADS=${THREADS:-4}
CONNS=${CONNS:-48}
MODE=${MODE:-run}
SERVER_OPTS=${SERVER_OPTS:-}
TOKENS=${TOKENS:-20000}
PROOFS=${PROOFS:-150000}
SERVICE=${SERVICE:-http4s}
OTEL_SDK_DISABLED=${OTEL_SDK_DISABLED:-false}
NONCE_HARVEST=${NONCE_HARVEST:-10s}
STORE=${STORE:-redis}
# Linux only: CPU lists for taskset, e.g. SERVER_CPUS=0-2 LOAD_CPUS=3. The
# service and its dependencies (Postgres, Redis, JWKS) run on SERVER_CPUS and
# wrk on LOAD_CPUS, so the load generator does not take CPU from what it
# measures. Unset (the default) runs everything unpinned.
SERVER_CPUS=${SERVER_CPUS:-}
LOAD_CPUS=${LOAD_CPUS:-}
SERVER_PIN=()
LOAD_PIN=()
[[ -n "$SERVER_CPUS" ]] && SERVER_PIN=(taskset -c "$SERVER_CPUS")
[[ -n "$LOAD_CPUS" ]] && LOAD_PIN=(taskset -c "$LOAD_CPUS")

HTTP_PORT=18080
JWKS_PORT=8443
PG_PORT=55432
REDIS_PORT=6379
ISSUER="https://as.load.test"
AUDIENCE="https://api.load.test"
BASE="http://127.0.0.1:$HTTP_PORT"
# The server rebuilds htu as https (TLS assumed terminated in front of it).
HTU="https://127.0.0.1:$HTTP_PORT/me"

# DPoP nonce setup of the running server; the DPoP scenarios switch these.
NONCE_ENABLED=false
NONCE_MODE=stateless
NONCE_KEY=$(openssl rand -base64 32)

MATERIAL="$WORK/material"
RESULTS="$WORK/results.txt"
SERVER_PID=""
SERVER_RUN=0
JWKS_PID=""

log() { printf '\n[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }

cleanup() {
  set +e
  [[ -n "$SERVER_PID" ]] && kill "$SERVER_PID" 2>/dev/null && wait "$SERVER_PID" 2>/dev/null
  [[ -n "$JWKS_PID" ]] && kill "$JWKS_PID" 2>/dev/null
  redis-cli -p "$REDIS_PORT" shutdown nosave >/dev/null 2>&1
  [[ -d "$WORK/pg" ]] && pg_ctl -D "$WORK/pg" -m fast stop >/dev/null 2>&1
}
trap cleanup EXIT
trap 'exit 143' INT TERM HUP

mint() { # tokens proofs [nonce-file]
  (cd "$ROOT" && sbt --client "bench/runMain bench.MintLoadTokens $MATERIAL $ISSUER $AUDIENCE $HTU $1 $2 ${3:-}") |
    grep -E "Wrote|error" || true
}

start_server() { # extra JAVA_OPTS
  SERVER_RUN=$((SERVER_RUN + 1))
  SERVER_LOG="$WORK/server-$SERVER_RUN.log"
  ${SERVER_PIN[@]+"${SERVER_PIN[@]}"} env HTTP_HOST=127.0.0.1 HTTP_PORT=$HTTP_PORT \
    DB_HOST=127.0.0.1 DB_PORT=$PG_PORT DB_NAME=auth DB_USER=auth DB_PASSWORD=unused \
    AUTH_ISSUER=$ISSUER AUTH_AUDIENCE=$AUDIENCE AUTH_JWKS_URI="https://localhost:$JWKS_PORT/jwks.json" \
    STORE_BACKEND=$STORE \
    DPOP_NONCE_ENABLED=$NONCE_ENABLED DPOP_NONCE_MODE=$NONCE_MODE DPOP_NONCE_KEY=$NONCE_KEY \
    OTEL_SERVICE_NAME=auth-middleware OTEL_SDK_DISABLED=$OTEL_SDK_DISABLED \
    OTEL_TRACES_SAMPLER=parentbased_traceidratio OTEL_TRACES_SAMPLER_ARG=0.01 \
    OTEL_TRACES_EXPORTER=none OTEL_METRICS_EXPORTER=none OTEL_LOGS_EXPORTER=none \
    JAVA_OPTS="-Xms2g -Xmx2g -Djavax.net.ssl.trustStore=$WORK/tls/truststore.p12 -Djavax.net.ssl.trustStorePassword=changeit -Djavax.net.ssl.trustStoreType=PKCS12 $SERVER_OPTS ${1:-}" \
    "$STAGE_BIN" >"$SERVER_LOG" 2>&1 &
  SERVER_PID=$!
  for _ in $(seq 1 60); do
    if curl -fs "$BASE/ready" >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  echo "server did not become ready; last log lines:" >&2
  tail -30 "$SERVER_LOG" >&2
  exit 1
}

stop_server() {
  kill "$SERVER_PID" && wait "$SERVER_PID" 2>/dev/null || true
  SERVER_PID=""
}

run() { # name, wrk args...
  local name=$1
  shift
  log "$name" | tee -a "$RESULTS"
  ${LOAD_PIN[@]+"${LOAD_PIN[@]}"} wrk -t"$THREADS" -c"$CONNS" --latency "$@" | tee -a "$RESULTS"
}

log "work dir: $WORK"

log "Building the packaged service and the token minter"
# Only the service under test: an older tree may not have the other module.
case "$SERVICE" in
  zio) BUILD="zio/stage; bench/compile" ;;
  *) BUILD="stage; bench/compile" ;;
esac
(cd "$ROOT" && sbt --client "$BUILD") | grep -E "error|success" | tail -2

# `stage` writes to target/out/jvm/scala-*/auth-middleware/universal/stage on
# sbt 2 and target/universal/stage on sbt 1. Take the newest, so a stale tree
# from the other layout can never be the one under test.
case "$SERVICE" in
  http4s) APP=auth-middleware MODULE_DIR="" ;;
  zio) APP=auth-middleware-zio MODULE_DIR=zio/ ;;
  *) echo "SERVICE must be http4s or zio" >&2; exit 1 ;;
esac
STAGE_BIN=$(ls -t "$ROOT"/target/out/jvm/scala-*/"$APP"/universal/stage/bin/"$APP" \
  "$ROOT/${MODULE_DIR}target/universal/stage/bin/$APP" 2>/dev/null | head -1 || true)
[[ -x "$STAGE_BIN" ]] || { echo "no staged service found; run: sbt --client stage" >&2; exit 1; }
log "Service under test: $STAGE_BIN"

log "TLS for the JWKS endpoint (self-signed, trusted only by the server under test)"
mkdir -p "$WORK/tls" "$WORK/jwks"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  -keyout "$WORK/tls/key.pem" -out "$WORK/tls/cert.pem" 2>/dev/null
keytool -importcert -noprompt -alias jwks -file "$WORK/tls/cert.pem" \
  -keystore "$WORK/tls/truststore.p12" -storetype PKCS12 -storepass changeit >/dev/null

log "Minting $TOKENS access tokens"
mint "$TOKENS" 0
cp "$MATERIAL/jwks.json" "$WORK/jwks/jwks.json"

log "Starting the JWKS endpoint on :$JWKS_PORT"
${SERVER_PIN[@]+"${SERVER_PIN[@]}"} python3 - "$WORK/jwks" "$WORK/tls" "$JWKS_PORT" <<'PY' &
import functools, http.server, ssl, sys
directory, tls, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
class Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass
server = http.server.ThreadingHTTPServer(("127.0.0.1", port), functools.partial(Quiet, directory=directory))
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(f"{tls}/cert.pem", f"{tls}/key.pem")
server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
PY
JWKS_PID=$!

log "Starting Postgres on :$PG_PORT and Redis on :$REDIS_PORT"
initdb -D "$WORK/pg" -U auth -A trust -E UTF8 --no-sync >/dev/null
${SERVER_PIN[@]+"${SERVER_PIN[@]}"} pg_ctl -D "$WORK/pg" -l "$WORK/pg.log" -w \
  -o "-p $PG_PORT -c listen_addresses=127.0.0.1 -c unix_socket_directories=''" start >/dev/null
createdb -h 127.0.0.1 -p "$PG_PORT" -U auth auth
${SERVER_PIN[@]+"${SERVER_PIN[@]}"} redis-server --port "$REDIS_PORT" --bind 127.0.0.1 --save "" --appendonly no \
  --daemonize yes --logfile "$WORK/redis.log"

log "Starting the service (verified-token cache on)"
start_server
TOKEN=$(head -1 "$MATERIAL/tokens.txt")

if [[ "$MODE" == "serve" ]]; then
  log "Serving on $BASE (pid $SERVER_PID); tokens in $MATERIAL/tokens.txt. Kill this script to stop."
  wait "$SERVER_PID"
  exit 0
fi

log "Warm-up (JIT, caches): 15s, not recorded"
${LOAD_PIN[@]+"${LOAD_PIN[@]}"} wrk -t"$THREADS" -c"$CONNS" -d15s -s "$SCRIPTS/bearer.lua" "$BASE/me" -- "$MATERIAL/tokens.txt" >/dev/null

run "1. GET /health — HTTP stack only, no auth (ceiling)" -d"$DURATION" "$BASE/health"
run "2. Bearer, one token reused (verified-token cache hit)" -d"$DURATION" \
  -H "Authorization: Bearer $TOKEN" "$BASE/me"
run "3. Bearer, $TOKENS distinct tokens (cache + revocation cache + $STORE)" -d"$DURATION" \
  -s "$SCRIPTS/bearer.lua" "$BASE/me" -- "$MATERIAL/tokens.txt"

log "Restarting with the revocation cache off: one $STORE read per request"
stop_server
start_server "-Dapp.auth.cache.revocation-ttl=0"
${LOAD_PIN[@]+"${LOAD_PIN[@]}"} wrk -t"$THREADS" -c"$CONNS" -d10s -s "$SCRIPTS/bearer.lua" "$BASE/me" -- "$MATERIAL/tokens.txt" >/dev/null
run "3b. Bearer, $TOKENS distinct tokens, revocation cache OFF ($STORE read every request)" \
  -d"$DURATION" -s "$SCRIPTS/bearer.lua" "$BASE/me" -- "$MATERIAL/tokens.txt"
stop_server
start_server

dpop_run() { # label
  run "$1" -d"$DPOP_DURATION" -s "$SCRIPTS/dpop.lua" "$BASE/me" -- "$MATERIAL/dpop.txt" "$THREADS"
}

restart_with_nonces() { # enabled mode
  NONCE_ENABLED=$1 NONCE_MODE=$2
  stop_server
  start_server
}

if [[ "$SERVICE" == "http4s" ]]; then
log "Minting $PROOFS single-use DPoP proofs (valid for 60 s)"
mint 0 "$PROOFS"
dpop_run "4a. DPoP, no server nonce (ES256 verify + $STORE single-use write on the jti)"

log "Restarting with stateless nonces (shared AES key; $STORE holds only spent jtis)"
restart_with_nonces true stateless
mint 0 1
curl -s -o /dev/null -D - -H "Authorization: DPoP $(sed -n 1p "$MATERIAL/dpop.txt")" \
  -H "DPoP: $(sed -n 2p "$MATERIAL/dpop.txt")" "$BASE/me" |
  awk 'tolower($1) == "dpop-nonce:" { sub(/\r$/, "", $2); print $2 }' >"$WORK/nonces.txt"
log "Minting $PROOFS proofs carrying the one stateless nonce"
mint 0 "$PROOFS" "$WORK/nonces.txt"
dpop_run "4b. DPoP, stateless nonce (AES-GCM check + mint, $STORE single-use write on the jti)"

log "Restarting with $STORE single-use nonces (consumed on use, minted per response)"
restart_with_nonces true redis
mint 0 1
rm -f "$WORK"/nonces.txt*
${LOAD_PIN[@]+"${LOAD_PIN[@]}"} wrk -t"$THREADS" -c"$CONNS" -d"$NONCE_HARVEST" -s "$SCRIPTS/nonces.lua" "$BASE/me" -- \
  "$MATERIAL/dpop.txt" "$WORK/nonces.txt" >/dev/null
cat "$WORK"/nonces.txt.* >"$WORK/nonces.txt"
HARVESTED=$(wc -l <"$WORK/nonces.txt" | tr -d ' ')
log "Harvested $HARVESTED single-use nonces; minting one proof per nonce (up to $PROOFS)"
mint 0 "$((HARVESTED < PROOFS ? HARVESTED : PROOFS))" "$WORK/nonces.txt"
dpop_run "4c. DPoP, $STORE single-use nonce (consume + mint per request, in-memory jti)"

restart_with_nonces false stateless
fi

log "Restarting the service with the verified-token cache off"
stop_server
start_server "-Dapp.auth.cache.verified-tokens=0"
${LOAD_PIN[@]+"${LOAD_PIN[@]}"} wrk -t"$THREADS" -c"$CONNS" -d10s -s "$SCRIPTS/bearer.lua" "$BASE/me" -- "$MATERIAL/tokens.txt" >/dev/null
run "5. Bearer, $TOKENS distinct tokens, cache OFF (RS256 verify every request)" -d"$DURATION" \
  -s "$SCRIPTS/bearer.lua" "$BASE/me" -- "$MATERIAL/tokens.txt"

log "WARN/ERROR lines logged by the server:"
grep -hE " (ERROR|WARN) " "$WORK"/server-*.log | sort | uniq -c | sort -rn | head -10 || true
log "Results: $RESULTS"
