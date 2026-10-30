"""mcpsec CLI — run a static MCP security triage on a config file."""
from __future__ import annotations

import argparse
import json
import sys
from typing import Dict, List

from . import checks


def _md_report(findings: List[Dict], cfg_path: str) -> str:
    s = checks.summarize(findings)
    lines = [
        "# MCP security scan — " + cfg_path,
        "",
        f"**{len(findings)} finding(s):** "
        + ", ".join(f"{s.get(k,0)} {k}" for k in ("critical","high","medium","low","info") if s.get(k)),
        "",
    ]
    if not findings:
        lines.append("_No static findings. This does NOT mean it's safe — run dynamic testing._")
    for f in findings:
        lines.append(f"## [{f['severity'].upper()}] {f['category']} — `{f['server']}/{f['tool']}`")
        lines.append(f"- **Evidence:** {f['evidence']}")
        lines.append(f"- **Fix:** {f['remediation']}")
        lines.append("")
    return "\n".join(lines)


def _bounty_skeleton(top: Dict) -> str:
    """Turn the top finding into the bug-report skeleton (ties to the P0 bounty lane)."""
    return (
        "# TEMPLATE — reproduce in-scope before submitting\n"
        f"- **Title:** `[High] MCP tool '{top['tool']}' ({top['category']}) in {top['server']}`\n"
        f"- **Severity & CVSS:** High | CVSS 3.1: <fill>\n"
        f"- **In-scope asset(s):** [FILL: exact in-scope MCP server / endpoint]\n"
        f"- **Impact:** {top['evidence']}\n"
        f"- **Steps to reproduce:** [FILL] load the MCP server, trigger tool '{top['tool']}'.\n"
        f"- **Proof of concept:** [FILL] request/response or screen-recording.\n"
        f"- **Suggested fix:** {top['remediation']}\n"
    )


def _to_sarif(findings: List[Dict], cfg_path: str) -> Dict:
    """Emit SARIF 2.1.0 so findings drop into GitHub Code Scanning / CI."""
    level = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
    rules, seen = [], set()
    for f in findings:
        if f["category"] not in seen:
            seen.add(f["category"])
            rules.append({"id": "mcpsec." + f["category"], "name": f["category"],
                         "fullDescription": {"text": f["remediation"]}})
    results = []
    for f in findings:
        results.append({
            "ruleId": "mcpsec." + f["category"],
            "level": level.get(f["severity"], "note"),
            "message": {"text": f"{f['category']}: {f['evidence']} — fix: {f['remediation']}"},
            "locations": [{"physicalLocation": {"artifactLocation": {
                "uri": f"{f['server']}/{f['tool']}", "index": 0}}}],
        })
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "mcpsec", "version": "0.1.0", "rules": rules}},
                      "results": results}]}


def _batch_run(dirpath: str, out_json) -> int:
    """Scan every MCP config under dirpath; print a per-file + aggregate report (PRO 'marketplace' tier)."""
    paths = checks.find_mcp_configs(dirpath)
    per, allf = [], []
    for p in paths:
        try:
            f = checks.scan(checks.load_config(p))
            per.append({"config": p, "findings": f})
            allf.extend(f)
        except Exception as e:
            per.append({"config": p, "error": str(e), "findings": []})
    print("# MCP batch scan — " + dirpath)
    print(f"\n**{len(paths)} config(s), {len(allf)} finding(s):**")
    if not paths:
        print("\n_(no MCP-like .json found under this dir)_")
    for item in per:
        s = checks.summarize(item["findings"])
        counts = ", ".join(f"{s.get(k)} {k}" for k in ("high", "medium", "low") if s.get(k)) or "clean"
        print(f"- `{item['config']}` -> {counts}" + (f"  (read err: {item['error']})" if item.get("error") else ""))
    if allf:
        print("\n## top offenders (all files)")
        for f in allf[:5]:
            print(f"- [{f['severity'].upper()}] {f['category']} — {f['server']}/{f['tool']}: {f['evidence'][:50]}")
    if out_json:
        with open(out_json, "w", encoding="utf-8") as fh:
            json.dump({"scanned_dir": dirpath, "configs": [i.get("config") for i in per],
                       "per_file": per, "total": len(allf),
                       "summary": checks.summarize(allf), "findings": allf}, fh, indent=2, ensure_ascii=False)
        print(f"\n[aggregate json written to {out_json}]")
    return 1 if any(f["severity"] in ("high", "critical") for f in allf) else 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="mcpsec", description="Static MCP security triage.")
    ap.add_argument("config", help="path to an MCP config (.json / .mcp.json)")
    ap.add_argument("--json", metavar="OUT", help="write findings as JSON to OUT")
    ap.add_argument("--sarif", metavar="OUT", help="write SARIF 2.1.0 (Code Scanning / CI) to OUT")
    ap.add_argument("--bounty", action="store_true", help="append a bug-report skeleton for the top finding")
    ap.add_argument("--batch", action="store_true",
                    help="treat the positional arg as a DIRECTORY and scan every MCP config under it")
    args = ap.parse_args(argv)

    if args.batch:
        return _batch_run(args.config, args.json)

    try:
        cfg = checks.load_config(args.config)
    except Exception as e:
        print(f"error: could not read config: {e}", file=sys.stderr)
        return 2

    findings = checks.scan(cfg)
    print(_md_report(findings, args.config))
    if args.bounty and findings:
        print("---\n")
        print(_bounty_skeleton(findings[0]))
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump({"config": args.config, "count": len(findings),
                       "summary": checks.summarize(findings), "findings": findings}, fh, indent=2)
        print(f"\n[json written to {args.json}]")
    if args.sarif:
        with open(args.sarif, "w", encoding="utf-8") as fh:
            json.dump(_to_sarif(findings, args.config), fh, indent=2)
        print(f"\n[sarif written to {args.sarif}]")
    # exit 1 if any high/critical -> usable in CI
    return 1 if any(f["severity"] in ("high", "critical") for f in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
