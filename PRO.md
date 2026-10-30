# mcpsec Pro (paid open-core tier)

The free core = **static** triage (config/manifest scanning). Pro = the parts that take time to
build and that teams will pay for. License: the paid scope is **dual-licensed / commercial use
gated**; the static core stays MIT.

| Tier | What you get | Why it's paid |
|---|---|---|
| **CI** | `mcpsec` as a pre-merge check; block PRs that expose dangerous/exec tools or add injection-prone metadata; SARIF output | saves a real incident |
| **Dynamic** | launch the server, fuzz each tool's params (path traversal, SSRF host, injection payloads), auto-repro the finding | needs a sandbox + harness |
| **Marketplace screen** | batch-scan a folder / registry of MCP servers, rank by risk | the "I run many servers" pain |
| **Hosted** | upload your `.mcp.json` → dashboard + weekly re-scan + secret-rotation alerts | SaaS = recurring revenue |
| **Review** | a human review of your server ($50/mo tier in Sponsors) | your time = premium |

**Shipping order (revenue-first):** 1) CI (fastest to ship, easiest to sell) → 2) Hosted
(recurring MRR) → 3) Dynamic → 4) Marketplace → 5) human reviews.

> This is a definition of scope, not yet built. The core is real and running; Pro is what
> Sponsors/Stripe unlock.
