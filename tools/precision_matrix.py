#!/usr/bin/env python3
"""
precision_matrix.py - does each rule stay silent on attacks it does NOT claim to catch?

run_tests.py proves recall: each rule fires on the capture of the attack it claims.
This proves precision: every rule runs, unchanged, against EVERY recorded capture in
the repository. A rule that fires on a capture of an unrelated technique is either

    tp   the capture genuinely contains the behaviour (Empire stages its implant with
         an encoded PowerShell launcher in almost every capture, for example), or
    fp   a false positive: the rule is wrong, and the cell is a bug to fix.

Nobody can decide that automatically, so each cross-capture hit is written to
docs/precision_review.yml and reviewed by a human, with a reason. Unreviewed hits
show as "review" and never count as passes. A rule that returns everything fails
this matrix on sight.

A capture is every fixture folder recorded from the same source dataset, merged
table by table (fixtures were converted to the tables each rule reads, so merging
gives each capture the widest view the repository holds). A cell whose capture has
none of the tables a rule reads is "no data", never "silent".

    python tools/precision_matrix.py                    # run, write docs/precision.json + docs/precision.md
    python tools/precision_matrix.py --strict           # also exit 1 on any fp or unreviewed hit
    python tools/precision_matrix.py --docs-only        # rebuild docs from the last docs/precision.json
"""
import argparse
import datetime
import json
import os
import re
import sys

import yaml

import kql_testkit as tk
import run_tests as rt

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOCS = os.path.join(ROOT, "docs")
RESULTS = os.path.join(DOCS, "precision.json")
REVIEW = os.path.join(DOCS, "precision_review.yml")
PAGE = os.path.join(DOCS, "precision.md")
README = os.path.join(ROOT, "README.md")
START, END = "<!-- PRECISION:START -->", "<!-- PRECISION:END -->"

# columns worth showing a reviewer, first match wins per slot
_SUMMARY = [
    ("what", ["ProcessCommandLine", "CommandLine", "Cmd", "RegistryKey", "FolderPath", "FileName", "RemoteUrl", "RemoteIP"]),
    ("by", ["InitiatingProcessFileName", "InitiatingProcessCommandLine", "ParentProcess", "Actor"]),
    ("score", ["RiskScore", "Score", "RiskLevel", "Severity"]),
]


def capture_key(source):
    """'OTRF empire_psexec_dcerpc_tcp_svcctl' -> 'empire_psexec_dcerpc_tcp_svcctl'"""
    s = str(source).strip().strip("'\"")
    s = re.sub(r"^OTRF\s+", "", s)
    return s.split()[0] if s else s


def row_id(row):
    return json.dumps(row, sort_keys=True, default=str)


def collect():
    """detections: {name: {rule_text, rule, tactic, own: set(capture)}}; captures: {key: {table: [rows]}}"""
    detections, captures, sources = {}, {}, {}
    for case_file, rel, tactic, detection in rt.discover("detections"):
        with open(case_file, encoding="utf-8") as fh:
            case = yaml.safe_load(fh)
        source = str(case.get("source", ""))
        if "synthetic" in source.lower():          # a real capture with an added row: the real one is enough
            continue
        key = capture_key(source)
        rule_path = rt.resolve(case_file, case["rule"])
        with open(rule_path, encoding="utf-8-sig") as fh:
            rule_text = fh.read()
        d = detections.setdefault(detection, {"rule": os.path.basename(rule_path), "rule_text": rule_text,
                                              "tactic": tactic, "own": set()})
        expect = case.get("expect", {}) or {}
        if expect.get("row_count") != 0:           # a test that expects silence is a precision test, not a claim
            d["own"].add(key)
        sources[key] = source.strip().strip("'\"")
        merged = captures.setdefault(key, {})
        for table, rows in rt.load_fixture(rt.resolve(case_file, case.get("fixture", "fixtures"))).items():
            seen = {row_id(r) for r in merged.setdefault(table, [])}
            merged[table].extend(r for r in rows if row_id(r) not in seen)
    return detections, captures, sources


def summarise(row):
    out = {}
    for slot, cols in _SUMMARY:
        for c in cols:
            v = row.get(c)
            if v not in (None, "", []):
                out[slot] = str(v)[:220]
                break
    return out


def load_review():
    if not os.path.exists(REVIEW):
        return {}
    with open(REVIEW, encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    return data.get("reviews", {}) or {}


def run(args):
    detections, captures, sources = collect()
    cells = []
    for det, d in sorted(detections.items()):
        reads = tk.referenced_tables(d["rule_text"])
        for cap in sorted(captures):
            tables = captures[cap]
            cell = {"detection": det, "capture": cap, "own": cap in d["own"], "tables": reads}
            if not any(tables.get(t) for t in reads):
                cell.update(status="nodata", rows=0)
            else:
                try:
                    rows, _ = tk.run_rule(d["rule_text"], tables, cluster=args.cluster, db=args.db)
                    cell.update(status="fires" if rows else "silent", rows=len(rows),
                                sample=[summarise(r) for r in rows[:3]])
                except Exception as e:                 # an engine outage must not look like silence
                    msg = str(e)
                    if msg.startswith("connection error"):
                        print(f"engine unreachable: {msg}")
                        sys.exit(2)
                    cell.update(status="error", rows=0, error=msg[:300])
            cells.append(cell)
            tag = {"fires": "FIRES ", "silent": "silent", "nodata": "nodata", "error": "ERROR "}[cell["status"]]
            print(f"{tag} {'OWN ' if cell['own'] else '    '}{det:<42} x {cap}  ({cell['rows']} rows)")
    out = {"run_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
           "engine": "Kustainer (Azure Data Explorer emulator)",
           "captures": {k: {"source": sources[k], "tables": {t: len(r) for t, r in captures[k].items() if r}}
                        for k in sorted(captures)},
           "detections": {k: {"rule": v["rule"], "tactic": v["tactic"], "own": sorted(v["own"])}
                          for k, v in sorted(detections.items())},
           "cells": cells}
    os.makedirs(DOCS, exist_ok=True)
    with open(RESULTS, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=1)
    print(f"\nresults written to {os.path.relpath(RESULTS, ROOT)}")
    return out


def verdict(cell, reviews):
    """own | silent | nodata | error | tp | fp | review"""
    if cell["own"]:
        return "own"
    if cell["status"] != "fires":
        return cell["status"]
    v = reviews.get(cell["detection"], {}).get(cell["capture"])
    if isinstance(v, dict) and str(v.get("verdict", "")).lower() in ("tp", "fp"):
        return str(v["verdict"]).lower()
    return "review"


CELL = {"own": None, "silent": "·", "nodata": "–", "error": "💥", "tp": "🎯", "fp": "❌", "review": "🔍"}


def build_docs(data):
    reviews = load_review()
    caps = list(data["captures"])
    dets = list(data["detections"])
    grid = {(c["detection"], c["capture"]): c for c in data["cells"]}
    counts = {k: 0 for k in CELL}
    for c in data["cells"]:
        counts[verdict(c, reviews)] += 1
    cross = sum(counts[k] for k in ("silent", "tp", "fp", "review", "error"))

    def own_mark(c):
        return f"✅ {c['rows']}" if c["status"] == "fires" else ("⚠️ 0" if c["status"] == "silent" else CELL[c["status"]])

    L = ["# Precision matrix", "",
         "<!-- Generated by tools/precision_matrix.py from docs/precision.json and docs/precision_review.yml. Edit those, not this file. -->", "",
         "The test suite proves each rule **fires** on the attack it claims. This matrix proves the other half: "
         "every rule runs, unchanged, against **every** recorded capture in the repository, and must stay silent on "
         "attacks it does not claim, unless the capture genuinely contains its behaviour. "
         "A rule that returned every event would fill this page with ❌.", "",
         f"Last run: **{data['run_utc']}** on {data['engine']}. "
         f"{len(dets)} detections × {len(caps)} captures = {len(data['cells'])} runs.", "",
         "| Result | Count | Meaning |", "|---|---|---|",
         f"| · silent | {counts['silent']} | ran on another technique's capture and returned nothing |",
         f"| 🎯 true positive | {counts['tp']} | fired on another capture that genuinely contains the behaviour (reviewed, reason below) |",
         f"| ❌ false positive | {counts['fp']} | fired where it should not: a rule bug, tracked below |",
         f"| 🔍 to review | {counts['review']} | fired on another capture, not yet classified |",
         f"| – no data | {counts['nodata']} | the capture has none of the tables the rule reads; proves nothing either way |",
         f"| ✅ own capture | {counts['own']} | the capture the rule's own tests use (see the README coverage table) |", ""]
    if cross:
        pending = f" ({counts['review']} still to review)" if counts["review"] else ""
        L.append(f"**Cross-capture precision: {counts['silent'] + counts['tp']} of {cross - counts['error']} "
                 f"runs with data were silent or genuine hits{pending}.**")
        L.append("")
    # matrix: detections as rows, captures as numbered columns
    L += ["## Matrix", "", "Columns are captures (key below). Cell = result; for fires, the row count.", ""]
    L.append("| Detection | " + " | ".join(f"C{i+1}" for i in range(len(caps))) + " |")
    L.append("|---|" + "---|" * len(caps))
    for det in dets:
        row = []
        for cap in caps:
            c = grid.get((det, cap))
            if not c:
                row.append(" ")
                continue
            v = verdict(c, reviews)
            row.append(own_mark(c) if v == "own" else (f"{CELL[v]} {c['rows']}" if v in ("tp", "fp", "review") else CELL[v]))
        L.append(f"| `{det}` | " + " | ".join(row) + " |")
    L += ["", "### Capture key", "", "| | Capture | Tables (rows) |", "|---|---|---|"]
    for i, cap in enumerate(caps):
        meta = data["captures"][cap]
        tables = ", ".join(f"{t.replace('Device', '').replace('Events', '')} {n}" for t, n in meta["tables"].items())
        L.append(f"| C{i+1} | `{meta['source']}` | {tables} |")
    # every cross-capture hit, with the evidence and the verdict
    hits = [c for c in data["cells"] if not c["own"] and c["status"] == "fires"]
    if hits:
        L += ["", "## Cross-capture hits", "",
              "Each hit on a capture the rule does not claim, with what it returned and the reviewed verdict.", ""]
        for c in hits:
            v = verdict(c, reviews)
            rv = reviews.get(c["detection"], {}).get(c["capture"]) or {}
            label = {"tp": "🎯 true positive", "fp": "❌ false positive", "review": "🔍 not yet reviewed"}[v]
            L.append(f"### `{c['detection']}` on `{c['capture']}`: {label}")
            L.append("")
            if rv.get("reason"):
                L.append(f"**Why:** {rv['reason']}")
                L.append("")
            for s in c.get("sample", []):
                bits = [f"**{k}:** `{s[k]}`" for k in ("what", "by", "score") if k in s]
                L.append("- " + " · ".join(bits) if bits else "- (row without summary columns)")
            if c["rows"] > len(c.get("sample", [])):
                L.append(f"- … {c['rows'] - len(c.get('sample', []))} more")
            L.append("")
    L += ["## Limits", "",
          "- Captures are attack recordings, not a day of normal enterprise activity. Silence here proves the rule does not "
          "fire on *other attacks' surrounding activity*; precision on a real estate is proven in a tenant, in hunt or "
          "triage mode first (see [lifecycle](lifecycle.md)).",
          "- Fixtures were converted to the tables each rule reads, so some captures are partial. Cells marked – are excluded "
          "from the precision figure rather than counted as silent.", ""]
    with open(PAGE, "w", encoding="utf-8") as fh:
        fh.write("\n".join(L))

    # README summary block
    block = (f"**Precision:** every rule also runs against every *other* recorded capture "
             f"({len(dets)} × {len(caps)}). Last run: {counts['silent']} silent · {counts['tp']} genuine hits · "
             f"{counts['fp']} false positives · {counts['review']} to review · {counts['nodata']} no data. "
             f"[Precision matrix](docs/precision.md)")
    if os.path.exists(README):
        with open(README, encoding="utf-8") as fh:
            text = fh.read()
        if START in text and END in text:
            text = re.sub(re.escape(START) + r".*?" + re.escape(END), lambda _: f"{START}\n{block}\n{END}", text, flags=re.S)
            with open(README, "w", encoding="utf-8") as fh:
                fh.write(text)
        else:
            print(f"README.md has no {START}/{END} markers - summary not written")
    print(f"wrote {os.path.relpath(PAGE, ROOT)}: " + ", ".join(f"{k} {n}" for k, n in counts.items()))
    return counts


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cluster", default=os.environ.get("ADX_CLUSTER", "http://localhost:8080"))
    ap.add_argument("--db", default=os.environ.get("ADX_DB", "NetDefaultDB"))
    ap.add_argument("--docs-only", action="store_true", help="rebuild docs from the last docs/precision.json")
    ap.add_argument("--strict", action="store_true", help="exit 1 on any false positive or unreviewed hit")
    args = ap.parse_args()
    if args.docs_only:
        if not os.path.exists(RESULTS):
            print("no docs/precision.json yet - run without --docs-only first")
            return 1
        with open(RESULTS, encoding="utf-8") as fh:
            data = json.load(fh)
    else:
        data = run(args)
    counts = build_docs(data)
    if args.strict and (counts["fp"] or counts["review"] or counts["error"]):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
