"""mcpsec — static security triage for Model Context Protocol (MCP) server configs.

Reads an MCP config (`.mcp.json` / a tools manifest) and flags the security issues
that actually matter for MCP: dangerous tool exposure, prompt-injection baked into
tool metadata, secrets in config, arbitrary-file access, and exfil surface.

This is a STATIC triage layer. It tells you what to test; it does not replace
dynamic testing (launch the server, fuzz the tool calls). See PRO.md for the
dynamic/CI tier.

3.9-compatible, standard library only.
"""
from __future__ import annotations

import json
import os
import re
from typing import Dict, List, Any, Iterator, Tuple

# --- patterns -----------------------------------------------------------------

DANGEROUS_TOOL_RE = re.compile(
    r"(shell|bash|zsh|exec|execute|run_cmd|command|cmd|python|node|npm|npx|apply_patch|"
    r"write_file|writefile|create_file|delete|remove|rm|sudo|curl|wget|fetch|http|"
    r"request|webhook|run|open|fs\b)",
    re.I,
)
EXFIL_PARAM_RE = re.compile(r"(url|endpoint|webhook|callback|post_to|target_url|dest|host)", re.I)
PATH_PARAM_RE = re.compile(r"^(path|file|filepath|directory|dir|file_path)$", re.I)

INJECTION_PATTERNS = [
    r"ignore\s+(all\s+|previous\s+|prior\s+)",
    r"do\s+not\s+(tell|inform|notify|reveal|mention)",
    r"always\s+(run|execute|send|upload|post|ignore)",
    r"without\s+(asking|confirmation|my\s+knowledge)",
    r"run\s+(this|the|that)\s+(command|script|code)",
    r"\bexfiltrat",
    r"reveal\s+(your|the)\s+(system|instructions|prompt|secret)",
    r"send\s+(all|everything|the\s+data|secrets|keys?)\s+to\b",
]
INJECTION_RE = [re.compile(p, re.I) for p in INJECTION_PATTERNS]

SECRET_RES = [
    (re.compile(r"sk-[A-Za-z0-9]{20,}"), "OpenAI-style API key"),
    (re.compile(r"ghp_[A-Za-z0-9]{20,}"), "GitHub personal access token"),
    (re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"), "Slack token"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key id"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "PEM private key"),
    (re.compile(r"(?i)(api_?key|token|secret|password|passwd|cred)\s*[:=]\s*[\"']?[A-Za-z0-9_\-./+]{8,}"),
     "generic credential"),
]

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def load_config(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _iter_servers(cfg: Dict[str, Any]) -> Iterator[Tuple[str, Dict[str, Any]]]:
    """Yield (server_name, server_spec). Handles top-level 'mcpServers', 'servers', or a flat list."""
    if isinstance(cfg, dict):
        for key in ("mcpServers", "servers"):
            block = cfg.get(key)
            if isinstance(block, dict):
                for name, spec in block.items():
                    yield name, (spec if isinstance(spec, dict) else {"value": spec})
                return
        # flat manifest: every top-level dict value that looks like a server
        if any(isinstance(v, dict) for v in cfg.values()):
            for name, spec in cfg.items():
                if isinstance(spec, dict) and any(k in spec for k in ("command", "url", "tools", "args")):
                    yield name, spec
    return


def _tools_of(spec: Dict[str, Any]) -> List[Dict[str, Any]]:
    tools = spec.get("tools")
    if isinstance(tools, list):
        return [t for t in tools if isinstance(t, dict)]
    return []


def _tool_params(t: Dict[str, Any]) -> Dict[str, Any]:
    p = t.get("parameters")
    if isinstance(p, dict):
        return p
    # also accept a JSON-schema-ish shape
    for cand in ("inputSchema", "schema"):
        s = t.get(cand)
        if isinstance(s, dict) and isinstance(s.get("properties"), dict):
            return s["properties"]
    return {}


def _is_remote_server(spec: Dict[str, Any]) -> bool:
    if any(spec.get(k) for k in ("url", "httpUrl", "sseUrl")):
        return True
    return str(spec.get("transport", "")).lower() in (
        "http", "sse", "streamable-http", "streamablehttp", "websocket")


def _internal_host(url: str) -> bool:
    m = re.search(r"https?://([^/?:]+)", url or "")
    host = (m.group(1) if m else "").lower()
    return (host in ("", "localhost", "0.0.0.0") or host.endswith((".local", ".internal"))
            or host.startswith(("127.", "10.", "192.168.", "169.254.")))


def _has_auth(spec: Dict[str, Any]) -> bool:
    hdrs = spec.get("headers") or {}
    if isinstance(hdrs, dict):
        keys = [str(k).lower() for k in hdrs]
        markers = ("authorization", "token", "x-api-key", "api-key", "apikey", "oauth", "bearer",
                   "cookie", "session")
        if any(mk in k for k in keys for mk in markers):
            return True
    envb = json.dumps(spec.get("env") or {}, ensure_ascii=False).lower()
    return any(mk in envb for mk in ("token", "api_key", "apikey", "secret", "auth"))


def scan(cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return a list of findings, most-severe first."""
    findings: List[Dict[str, Any]] = []

    def add(sev, cat, server, tool, evidence, remediation):
        findings.append({
            "severity": sev, "category": cat, "server": server, "tool": tool,
            "evidence": evidence, "remediation": remediation,
        })

    for server, spec in _iter_servers(cfg):
        # 1) secrets anywhere in the server spec (env, headers, args, url, ...)
        blob = json.dumps(spec, ensure_ascii=False)
        for rx, label in SECRET_RES:
            for m in rx.finditer(blob):
                add("high", "secret-in-config", server, "-",
                    f"{label} detected near: ...{m.group(0)[:12]}***",
                    "Move the credential out of config; use env var / secret manager; "
                    "rotate this value (treat it as leaked).")

        # remote MCP server transport: trust / SSRF / no-auth
        if _is_remote_server(spec):
            url = spec.get("url") or spec.get("httpUrl") or spec.get("sseUrl") or ""
            if _internal_host(url):
                add("high", "ssrf-to-internal", server, "-",
                    f"MCP server url points to an internal/loopback host: {url[:40]}",
                    "Never point an MCP client at internal services; allowlist target hosts.")
            elif not _has_auth(spec):
                add("medium", "untrusted-remote-server", server, "-",
                    "remote MCP server (url/transport) with no visible auth header/token",
                    "Treat remote MCP servers as untrusted third-party code: pin the endpoint, add "
                    "auth, and sandbox their tools.")

        for tool in _tools_of(spec):
            tname = tool.get("name", "?")
            desc = tool.get("description", "") or ""
            params = _tool_params(tool)
            pnames = list(params.keys())

            # 2) dangerous tool exposed
            hay = tname + " " + " ".join(pnames)
            if DANGEROUS_TOOL_RE.search(hay):
                add("high", "dangerous-tool-exposure", server, tname,
                    f"tool '{tname}' looks command/exec/file capable"
                    + (f" (params: {pnames})" if pnames else ""),
                    "Gate this tool behind explicit confirmation or a sandbox; "
                    "prefer allowlists over raw exec/file tools.")

            # 3) prompt-injection baked into tool metadata
            for rx in INJECTION_RE:
                if rx.search(desc):
                    add("high", "prompt-injection-signal", server, tname,
                        f"tool '{tname}' description contains instruction-like text: "
                        f"'{rx.pattern[:28]}...'",
                        "Treat tool descriptions as UNTRUSTED input; strip/neutralize "
                        "imperative instructions; never honor directives inside tool metadata.")
                    break

            # 4) arbitrary file access
            for pn in pnames:
                if PATH_PARAM_RE.match(pn):
                    add("medium", "arbitrary-file-access", server, tname,
                        f"tool '{tname}' takes a '{pn}' param with no visible root constraint",
                        "Constrain paths to a sandbox root; reject traversal (../) and absolute paths.")

            # 5) exfil surface
            for pn in pnames:
                if EXFIL_PARAM_RE.search(pn):
                    add("medium", "exfil-surface", server, tname,
                        f"tool '{tname}' accepts a '{pn}' param -> attacker-controlled outbound URL",
                        "Allowlist permitted hosts; never let model output choose the destination "
                        "of sensitive data.")

    findings.sort(key=lambda f: _SEV_ORDER.get(f["severity"], 9))
    return findings


def summarize(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for f in findings:
        out[f["severity"]] = out.get(f["severity"], 0) + 1
    return out


def _looks_like_mcp(cfg: Any) -> bool:
    if isinstance(cfg, dict):
        if "mcpServers" in cfg or "servers" in cfg:
            return True
        for v in cfg.values():
            if isinstance(v, dict) and any(k in v for k in ("command", "url", "tools", "args")):
                return True
    return False


def find_mcp_configs(root: str, max_depth: int = 6) -> List[str]:
    """Recursively find MCP-ish .json configs under root (skips .git/node_modules/venv)."""
    found: List[str] = []
    root = os.path.abspath(root)
    skip = {".git", "node_modules", ".venv", "venv", "__pycache__"}
    for dirpath, dirnames, filenames in os.walk(root):
        depth = 0 if os.path.abspath(dirpath) == root else os.path.relpath(dirpath, root).count(os.sep)
        if depth >= max_depth:
            dirnames[:] = []
            continue
        dirnames[:] = [d for d in dirnames if d not in skip]
        for fn in filenames:
            if not fn.endswith(".json"):
                continue
            p = os.path.join(dirpath, fn)
            try:
                with open(p, "r", encoding="utf-8") as fh:
                    if _looks_like_mcp(json.load(fh)):
                        found.append(p)
            except Exception:
                continue
    return sorted(found)
