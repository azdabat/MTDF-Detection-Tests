#!/usr/bin/env python3
"""
new_detection.py - scaffold a complete detection folder in one command.

    python tools/new_detection.py --tactic persistence --name registry_run_keys ^
        --rule C:\\path\\to\\Registry_Persistence_RunKeys.kql ^
        --dataset ..\\Security-Datasets\\datasets\\atomic\\windows\\persistence\\host\\empire_persistence_registry_modification_run_keys_elevated_user.zip ^
        --eventid 1,12,13 --technique T1547.001 --catches "Run key pointing at an Empire launcher"

Creates:

    detections/<tactic>/<name>/
        <Rule>.kql            copied from --rule (or a template if --rule is omitted)
        test.yml              must_fire: true to start; tighten with contains: after the first run
        fixtures/<Table>.json converted from --dataset (.zip/.tar/.tar.gz/.json, current or legacy OTRF)

Then: python tools/run_tests.py -k <name>
"""
import argparse
import os
import re
import shutil
import sys

import attack_tactics as at
import mde_mapping
import lab_build
import mordor_to_mde as m2m

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

RULE_TEMPLATE = """// ============================================================================
// COMPOSITE HUNT (L3): {name}
// Author: Ala Dabat   |   MITRE: {technique}
//
// TRUTH DOMAIN :
// MINIMUM TRUTH:
//
// Portability conventions: iff(<cond>,1,0) not toint(<cond>); one extend per
// dependency layer; hive-agnostic registry anchors; column_ifexists() for
// non-standard columns; lookback wide enough for the fixture's capture date.
// ============================================================================

let lookback = 3650d;

DeviceProcessEvents
| where Timestamp >= ago(lookback)
| take 10
"""


def slug(text):
    s = re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")
    if not s:
        raise SystemExit("--name must contain letters or digits")
    return s


def yaml_str(s):
    """Single-quoted YAML string: backslashes stay literal, '' escapes a quote."""
    return "'" + str(s).replace("'", "''") + "'"


def main():
    ap = argparse.ArgumentParser(description="Scaffold detections/<tactic>/<name>/ with rule, test and fixtures.")
    ap.add_argument("--tactic", required=True, choices=at.SLUGS, help="ATT&CK tactic folder")
    ap.add_argument("--name", required=True, help="detection folder name, e.g. registry_run_keys")
    ap.add_argument("--rule", help="path to the .kql rule to copy in")
    ap.add_argument("--dataset", help="OTRF dataset (.zip/.tar/.tar.gz/.json) to convert into fixtures")
    ap.add_argument("--eventid", help="comma list of Sysmon EventIDs to keep, e.g. 1,12,13")
    ap.add_argument("--limit-per-table", type=int, default=2000)
    ap.add_argument("--technique", default="", help="e.g. T1547.001")
    ap.add_argument("--catches", default="", help="one line: what the rule must catch in this telemetry")
    ap.add_argument("--title", default="", help="detection title for the docs")
    ap.add_argument("--minimum-truth", default="", help="the one observable the attack cannot avoid leaving")
    ap.add_argument("--lookback", default="7d", help="production lookback (default 7d)")
    ap.add_argument("--force", action="store_true", help="overwrite an existing detection folder")
    args = ap.parse_args()

    name = slug(args.name)
    folder = os.path.join(ROOT, "detections", args.tactic, name)
    if os.path.exists(folder):
        if not args.force:
            raise SystemExit(f"{folder} already exists (use --force to overwrite)")
        shutil.rmtree(folder)
    os.makedirs(os.path.join(folder, "fixtures"))

    # 1) rule
    if args.rule:
        if not os.path.isfile(args.rule):
            raise SystemExit(f"rule not found: {args.rule}")
        rule_file = os.path.basename(args.rule)
        raw = open(args.rule, "rb").read().decode("utf-8-sig", errors="replace").replace("\r\n", "\n")
        text, notes = lab_build.lab_build(raw)          # widen ago() windows for 2019-2020 captures
        with open(os.path.join(folder, rule_file), "w", encoding="utf-8") as fh:
            fh.write(text)
        for n in notes:
            print(f"  LAB {n}")
    else:
        rule_file = "rule.kql"
        with open(os.path.join(folder, rule_file), "w", encoding="utf-8") as fh:
            fh.write(RULE_TEMPLATE.format(name=name, technique=args.technique or "T????"))

    # 2) fixtures
    source = ""
    if args.dataset:
        if not os.path.isfile(args.dataset):
            raise SystemExit(f"dataset not found: {args.dataset}")
        keep = {int(x) for x in args.eventid.split(",")} if args.eventid else None
        events = m2m.load_events(args.dataset, keep)
        tables, _ = mde_mapping.convert_events(events)
        if not tables:
            print("  warning: no Sysmon host telemetry in that dataset (network capture?) - fixtures left empty")
        rows = m2m.write_tables(tables, os.path.join(folder, "fixtures"), limit=args.limit_per_table)
        print(f"  {len(events)} sysmon events -> {rows} fixture rows")
        source = "OTRF " + re.sub(r"(_\d{4}-\d{2}-\d{2}\d*)?(\.tar\.gz|\.tgz|\.tar|\.zip|\.json)$", "",
                                  os.path.basename(args.dataset))

    # 3) test case
    test = (
        f"name: {yaml_str(name.replace('_', ' '))}\n"
        f"rule: {yaml_str(rule_file)}\n"
        f"fixture: fixtures\n"
        f"technique: {yaml_str(args.technique)}\n"
        f"source: {yaml_str(source)}\n"
        f"catches: {yaml_str(args.catches)}\n"
        f"maturity: experimental\n"
        f"expect:\n"
        f"  must_fire: true\n"
        f"  # after the first run, pin the attack it must catch, e.g.:\n"
        f"  # contains:\n"
        f"  #   - RegistryValueName: [\"UseLogonCredential\"]\n"
        f"  # columns: [RiskScore, RiskLevel, HunterDirective]\n"
    )
    with open(os.path.join(folder, "test.yml"), "w", encoding="utf-8") as fh:
        fh.write(test)

    import yaml
    tables_used = sorted({t for t in re.findall(r"\b(Device\w+Events|DeviceFileCertificateInfo)\b",
                                                 open(os.path.join(folder, rule_file), encoding="utf-8").read())})
    meta = {"title": args.title or name.replace("_", " ").title(), "author": "Ala Dabat",
            "techniques": [t.strip() for t in args.technique.split(",") if t.strip()],
            "minimum_truth": args.minimum_truth or "TODO: state the minimum truth",
            "reinforcement": "TODO", "data_sources": tables_used,
            "platforms": ["Microsoft Defender XDR Advanced Hunting", "Microsoft Sentinel (MDE connector)"],
            "production_lookback": args.lookback,
            "source_rule": os.path.splitext(rule_file)[0]}
    with open(os.path.join(folder, "detection.yml"), "w", encoding="utf-8") as fh:
        fh.write("# Detection metadata - source of truth for the generated README in this folder.\n")
        yaml.safe_dump(meta, fh, sort_keys=False, allow_unicode=True, width=110)

    rel = os.path.relpath(folder, ROOT)
    print(f"\ncreated {rel}")
    for f in sorted(os.listdir(folder)):
        print(f"  {f}")
    for f in sorted(os.listdir(os.path.join(folder, "fixtures"))):
        print(f"  fixtures/{f}")
    print(f"\nnext:  fill in TODOs in detection.yml, then  python tools/run_tests.py -k {args.tactic}/{name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
