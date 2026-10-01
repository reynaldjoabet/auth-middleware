#!/usr/bin/env python3
"""Compare load-test results (results.txt files written by run.sh) of two builds.

    summarize.py --base base-1.txt base-2.txt --head head-1.txt head-2.txt \
        --markdown comparison.md --json benchmark.json [--threshold 10]

Each side may have several rounds; a scenario's value is the median over them.
The Markdown is a per-scenario table (base, head, change) for a job summary or
a PR comment. The JSON is the head's figures in github-action-benchmark's
customBiggerIsBetter format, for anyone who wants to track history.

Exits 0 whatever the numbers: shared CI runners are too noisy for a hard gate,
so regressions are flagged in the table, not enforced.
"""

import argparse
import json
import re
import statistics
import sys

HEADER = re.compile(r"^\[\d\d:\d\d:\d\d\] (\S+?)\. (.*)$")
RPS = re.compile(r"^Requests/sec:\s+([\d.]+)")
P99 = re.compile(r"^\s+99%\s+([\d.]+)(us|ms|s)\b")
NON_2XX = re.compile(r"Non-2xx or 3xx responses: (\d+)")
SOCKET = re.compile(r"Socket errors: connect (\d+), read (\d+), write (\d+), timeout (\d+)")
UNIT_MS = {"us": 0.001, "ms": 1.0, "s": 1000.0}


def parse(path):
    """{scenario id: {title, rps, p99_ms, errors}} from one results.txt."""
    scenarios, current = {}, None
    with open(path, encoding="utf-8") as f:
        for line in f:
            if m := HEADER.match(line):
                current = m.group(1)
                scenarios[current] = {"title": m.group(2).strip(), "rps": None, "p99_ms": None, "errors": 0}
            elif current is None:
                continue
            elif m := RPS.match(line):
                scenarios[current]["rps"] = float(m.group(1))
            elif m := P99.match(line):
                scenarios[current]["p99_ms"] = float(m.group(1)) * UNIT_MS[m.group(2)]
            elif m := NON_2XX.search(line):
                scenarios[current]["errors"] += int(m.group(1))
            elif m := SOCKET.search(line):
                scenarios[current]["errors"] += sum(int(g) for g in m.groups())
    return {k: v for k, v in scenarios.items() if v["rps"] is not None}


def combine(paths):
    """Median rps and p99 per scenario over rounds; errors summed."""
    runs = [parse(p) for p in paths]
    combined = {}
    for key in dict.fromkeys(k for run in runs for k in run):  # first-seen order
        seen = [run[key] for run in runs if key in run]
        p99s = [s["p99_ms"] for s in seen if s["p99_ms"] is not None]
        combined[key] = {
            "title": seen[0]["title"],
            "rps": statistics.median(s["rps"] for s in seen),
            "p99_ms": statistics.median(p99s) if p99s else None,
            "errors": sum(s["errors"] for s in seen),
            "rounds": len(seen),
        }
    return combined


def fmt_rps(v):
    return "–" if v is None else f"{v:,.0f}"


def fmt_ms(v):
    return "–" if v is None else (f"{v:.2f}" if v < 10 else f"{v:.0f}")


def change(base, head):
    if base is None or head is None or base == 0:
        return None
    return (head - base) / base * 100


def markdown(base, head, threshold, base_label, head_label):
    lines = [
        f"### Benchmark: `{head_label}` vs `{base_label}`",
        "",
        "| Scenario | Base req/s | Head req/s | Change | Base p99 ms | Head p99 ms | Errors (base / head) |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    flagged = []
    for key in dict.fromkeys(list(base) + list(head)):
        b, h = base.get(key), head.get(key)
        title = (h or b)["title"]
        delta = change(b and b["rps"], h and h["rps"])
        if delta is None:
            mark = "–"
        elif delta <= -threshold:
            mark = f"🔻 {delta:+.1f}%"
            flagged.append(key)
        elif delta >= threshold:
            mark = f"🟢 {delta:+.1f}%"
        else:
            mark = f"{delta:+.1f}%"
        errors = f"{b['errors'] if b else '–'} / {h['errors'] if h else '–'}"
        if h and h["errors"] and not (b and b["errors"]):
            errors += " ⚠️"
            flagged.append(key)
        lines.append(
            f"| {key}. {title} | {fmt_rps(b and b['rps'])} | {fmt_rps(h and h['rps'])} | {mark} "
            f"| {fmt_ms(b and b['p99_ms'])} | {fmt_ms(h and h['p99_ms'])} | {errors} |"
        )
    rounds = max((s["rounds"] for s in list(base.values()) + list(head.values())), default=0)
    lines += [
        "",
        f"Median of {rounds} round(s) per side, base and head alternating on the same runner. "
        f"🔻 marks a drop of {threshold:g}% or more, ⚠️ errors the base did not have.",
        "",
        "Shared CI runners vary by 10–20% between runs, and the load generator shares the "
        "runner with the service. Treat single-digit changes as noise and confirm a flagged "
        "one by re-running before acting on it.",
    ]
    return "\n".join(lines) + "\n", sorted(set(flagged))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", nargs="+", required=True)
    ap.add_argument("--head", nargs="+", required=True)
    ap.add_argument("--base-label", default="base")
    ap.add_argument("--head-label", default="head")
    ap.add_argument("--threshold", type=float, default=10.0, help="percent drop to flag")
    ap.add_argument("--markdown")
    ap.add_argument("--json")
    args = ap.parse_args()

    base, head = combine(args.base), combine(args.head)
    if not head:
        sys.exit("no scenarios found in the head results")
    text, flagged = markdown(base, head, args.threshold, args.base_label, args.head_label)

    if args.markdown:
        with open(args.markdown, "w", encoding="utf-8") as f:
            f.write(text)
    else:
        print(text)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(
                [
                    {"name": f"{k}. {v['title']}", "unit": "req/s", "value": round(v["rps"], 1)}
                    for k, v in head.items()
                ],
                f,
                indent=2,
            )
    if flagged:
        print(f"flagged scenarios: {', '.join(flagged)}", file=sys.stderr)


if __name__ == "__main__":
    main()
