

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import requests

BATCH_DIR = Path(__file__).resolve().parent.parent / "data" / "seeds" / "batch"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:8102")
    ap.add_argument("--key", default="")
    ap.add_argument("--ingest-url", default=None,
                    help="override ingest endpoint (default <base>/api/v1/telemetry/ingest)")
    args = ap.parse_args()

    if not args.key:
        print("error: --key required (x-api-key)", file=sys.stderr)
        return 2
    ingest_url = args.ingest_url or f"{args.base.rstrip('/')}/api/v1/telemetry/ingest"
    headers = {"x-api-key": args.key}

    manifest = json.loads((BATCH_DIR / "manifest.json").read_text(encoding="utf-8"))
    ok = 0
    bad = 0
    print(f"== Seeding + verifying {manifest['count']} scenarios vs {args.base} ==\n")
    for s in manifest["scenarios"]:
        files = s["files"]
        last = None
        errs = []
        for i, fname in enumerate(files, start=1):
            payload = json.loads((BATCH_DIR / fname).read_text(encoding="utf-8"))
            r = requests.post(ingest_url, json=payload, headers=headers, timeout=20)
            if r.status_code not in (200, 201):
                errs.append(f"ingest#{i} HTTP {r.status_code}: {r.text[:200]}")
                break
            last = r.json()
        if last is None:
            print(f"[FAIL] {s['id']} {s['name']}: {errs}")
            bad += 1
            continue

        exp_status = s["expected"]["status"]
        exp_findings = set(s["expected"]["findings"])
        got_status = last.get("status")
        got_findings = set(last.get("findings", []))
        problems = []
        if got_status != exp_status:
            problems.append(f"status {got_status!r} != expected {exp_status!r}")
        missing = exp_findings - got_findings
        if missing:
            problems.append(f"missing findings {sorted(missing)}")

        if problems:
            print(f"[FAIL] {s['id']} {s['name']}: {'; '.join(problems)} "
                  f"(got findings={sorted(got_findings)})")
            bad += 1
        else:
            ok += 1
            print(f"[PASS] {s['id']} {s['name']:<20} {got_status:<8} tis={last.get('tis'):<6} "
                  f"findings={sorted(got_findings)}")

    print(f"\n== BATCH RESULT: {ok} passed, {bad} failed ==")
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
