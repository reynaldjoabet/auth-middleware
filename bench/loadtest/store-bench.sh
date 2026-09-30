#!/usr/bin/env bash
# The shared-state stores on their own (bench.StoreThroughput): Redis against
# Postgres, unbatched, batched, and batched with UNLOGGED DPoP tables. Starts a
# throwaway Postgres and Redis in $WORK and removes them on exit.
#
# Requires: postgres (initdb/pg_ctl), redis-server. Usage:
#
#   bench/loadtest/store-bench.sh                 # 5 s runs, 3 rounds, 48 callers
#   SECONDS_PER_RUN=10 ROUNDS=5 FIBERS=96 bench/loadtest/store-bench.sh
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
WORK=${WORK:-$(mktemp -d)}
SECONDS_PER_RUN=${SECONDS_PER_RUN:-5}
ROUNDS=${ROUNDS:-3}
FIBERS=${FIBERS:-48}
PG_PORT=${PG_PORT:-55434}
REDIS_PORT=${REDIS_PORT:-6380}

cleanup() {
  set +e
  redis-cli -p "$REDIS_PORT" shutdown nosave >/dev/null 2>&1
  [[ -d "$WORK/pg" ]] && pg_ctl -D "$WORK/pg" -m fast stop >/dev/null 2>&1
}
trap cleanup EXIT
trap 'exit 143' INT TERM HUP

initdb -D "$WORK/pg" -U auth -A trust -E UTF8 --no-sync >/dev/null
pg_ctl -D "$WORK/pg" -l "$WORK/pg.log" -w \
  -o "-p $PG_PORT -c listen_addresses=127.0.0.1 -c unix_socket_directories=''" start >/dev/null
createdb -h 127.0.0.1 -p "$PG_PORT" -U auth auth
redis-server --port "$REDIS_PORT" --bind 127.0.0.1 --save "" --appendonly no \
  --daemonize yes --logfile "$WORK/redis.log"

cd "$ROOT"
sbt --client "bench/runMain bench.StoreThroughput $PG_PORT $REDIS_PORT $SECONDS_PER_RUN $ROUNDS $FIBERS"
