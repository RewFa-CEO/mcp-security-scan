# mcpsec — static security triage for MCP servers

`mcpsec` flags the security issues that actually matter for **Model Context Protocol (MCP)**
servers, from a plain config / tools manifest:

- 🔴 **secret-in-config** — API keys / tokens / creds sitting in the config (should be rotated)
- 🔴 **dangerous-tool-exposure** — `exec` / shell / file / network tools exposed with no gating
- 🔴 **prompt-injection-signal** — imperative instructions baked into tool descriptions/metadata
- 🟠 **arbitrary-file-access** — a `path` param with no sandbox root
- 🟠 **exfil-surface** — an attacker-controllable outbound URL / webhook param

It's a **static triage layer**: it tells you *what to test* (and pre-fills a bug-report
skeleton). It is not a substitute for dynamic testing — that's the [Pro tier](./PRO.md).

## Install
```bash
cd mcp-security-scan
python3 -m mcpsec examples/mcp.sample.json            # markdown report to stdout
python3 -m mcpsec your.mcp.json --bounty --json r.json # + bug-report skeleton + JSON
```
No dependencies (standard library, Python 3.9+). Exit code is `1` when any high/critical
finding exists, so it's CI-ready: `python3 -m mcpsec .mcp.json`.

## Example (real output on `examples/mcp.sample.json`)
```
# MCP security scan — examples/mcp.sample.json
**7 finding(s):** 5 high, 2 medium

## [HIGH] secret-in-config — `shell-tools/-`
- Evidence: OpenAI-style API key detected near: ...sk-abcd1234a***
- Fix: Move the credential out of config; rotate this value (treat it as leaked).

## [HIGH] prompt-injection-signal — `shell-tools/run_shell`
- Evidence: tool 'run_shell' description contains instruction-like text
- Fix: Treat tool descriptions as UNTRUSTED input; never honor directives inside tool metadata.

## [MEDIUM] exfil-surface — `shell-tools/fetch`
- Evidence: tool 'fetch' accepts a 'url' param -> attacker-controlled outbound URL
- Fix: Allowlist permitted hosts; never let model output choose the destination of sensitive data.
```

## Use it for bug bounties
`--bounty` turns the top finding into a **report skeleton** (title / severity / impact /
repro / suggested fix) you can finish and submit to an in-scope MCP-related program
(OpenAI Safety, or any platform that scopes agent/MCP surfaces). **Stay in scope; use your
own test servers; no DoS; no other users' data.**

## ⭐ Back this project
`mcpsec` is free & open-source (MIT core). If it helps you secure agent deployments:
- [GitHub Sponsors](https://github.com/sponsors/RewFa-CEO) · tiers: **$10/mo** keeps CI green ·
  **$50/mo** = your MCP server gets a security review · **retainer** = a real security partner.
- **Open-core:** the static scanner above is free. **Pro** (dynamic fuzzing, CI, hosted) is paid — see [PRO.md](./PRO.md).
