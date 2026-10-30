# PUBLISH — turn mcp-security-scan into a live, earning repo (one-shot)

I don't run outward/publish actions for you (irreversible + your identity/KYC). These are your
steps; each is copy-paste. Do it once and this lane can start earning.

## 1) make it a repo + push public
```bash
cd ~/Desktop/GitHub/mcp-security-scan
git init
git add .
git commit -m "mcpsec v0.1.0: static MCP security triage (SARIF + CI + batch)"
gh repo create mcp-security-scan --public --source . --push   # gh is logged in as RewFa-CEO
```

## 2) enable Sponsors + tiers (the money rail)
- Repo → **Settings → Sponsors → Enable**, set your payout method (Stripe / bank / PayPal).
- Tiers: **$10/mo** "keep CI green" · **$50/mo** "security review of one of your MCP servers" · a **retainer**.
- Your Sponsors URL is already wired in the README as `https://github.com/sponsors/RewFa-CEO` — after
  enabling, confirm the button renders on the repo page.

## 3) start the recurring revenue
- **Pro (paid)** = CI + dynamic + hosted (see [PRO.md](./PRO.md)). Ship **"CI"** first — it's the
  fastest to sell and the `.github/workflows/mcpsec-ci.yml` template already ships in-repo.
- **Bounty pairing**: `python3 -m mcpsec <in-scope .mcp.json> --bounty` → file MCP findings into an
  in-scope program. **Stay in scope; own test servers; no DoS; no other users' data.**

## guardrails
- `.gitignore` already blocks committing secrets / local scan outputs / `.mcp.json` — keep it.
- Never commit PII or real credentials.
