#!/usr/bin/env bash
# A/B load test: this checkout ("head") against another commit ("base"), on the
# same machine, with the same harness, rounds alternating between the two.
#
# Comparing against a number from another day or another machine mostly
# measures the machine: shared CI runners differ by 10-20% from run to run.
# Running both builds here, interleaved (base->head, then head->base, ...),
# puts any drift on both sides, and the report compares medians.
#
# Usage:
#   bench/loadtest/compare.sh [base-ref]          # default: origin/main
#   ROUNDS=3 DURATION=20s bench/loadtest/compare.sh HEAD~1
#
# Everything run.sh reads passes through (DURATION, CONNS, STORE, ...); STORE
# defaults to redis. Output in $OUT (default target/bench-compare):
#   comparison.md    per-scenario table, base vs head
#   benchmark.json   head's req/s, github-action-benchmark format
#   results/         each run's wrk output; logs/ each run's full log
#
# The base is checked out with `git worktree add --detach` (no branch) in a
# temporary directory, and removed at the end.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
HEAD_TREE=$(cd "$HERE/../.." && pwd)
BASE_REF=${1:-origin/main}
ROUNDS=${ROUNDS:-2}
OUT=${OUT:-$HEAD_TREE/target/bench-compare}
THRESHOLD=${THRESHOLD:-10}
export STORE=${STORE:-redis}

BASE_SHA=$(git -C "$HEAD_TREE" rev-parse --verify "$BASE_REF^{commit}")
HEAD_SHA=$(git -C "$HEAD_TREE" rev-parse HEAD)
BASE_TREE=$(mktemp -d)/base

cleanup() {
  set +e
  (cd "$BASE_TREE" 2>/dev/null && sbt --client shutdown >/dev/null 2>&1)
  git -C "$HEAD_TREE" worktree remove --force "$BASE_TREE" >/dev/null 2>&1
}
trap cleanup EXIT

rm -rf "$OUT" && mkdir -p "$OUT/results" "$OUT/logs"
echo "base $BASE_REF ($BASE_SHA)"
echo "head $(git -C "$HEAD_TREE" rev-parse --abbrev-ref HEAD) ($HEAD_SHA)"
[[ -n "$(git -C "$HEAD_TREE" status --porcelain)" ]] && echo "head has uncommitted changes; they are included"
git -C "$HEAD_TREE" worktree add --detach "$BASE_TREE" "$BASE_SHA" >/dev/null

run_side() { # side round
  local side=$1 round=$2 tree
  [[ "$side" == base ]] && tree=$BASE_TREE || tree=$HEAD_TREE
  echo "[$(date +%H:%M:%S)] round $round: $side"
  if ! ROOT="$tree" WORK="$OUT/work-$side-$round" bash "$HERE/run.sh" >"$OUT/logs/$side-$round.log" 2>&1; then
    echo "run.sh failed for $side (round $round); last lines:" >&2
    tail -30 "$OUT/logs/$side-$round.log" >&2
    exit 1
  fi
  cp "$OUT/work-$side-$round/results.txt" "$OUT/results/$side-$round.txt"
  rm -rf "$OUT/work-$side-$round"
}

for round in $(seq 1 "$ROUNDS"); do
  if ((round % 2 == 1)); then order="base head"; else order="head base"; fi
  for side in $order; do run_side "$side" "$round"; done
done

python3 "$HERE/summarize.py" \
  --base "$OUT"/results/base-*.txt --head "$OUT"/results/head-*.txt \
  --base-label "${BASE_REF} (${BASE_SHA:0:7})" --head-label "${HEAD_SHA:0:7}" \
  --threshold "$THRESHOLD" --markdown "$OUT/comparison.md" --json "$OUT/benchmark.json"
cat "$OUT/comparison.md"
