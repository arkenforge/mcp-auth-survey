# MCP Auth Survey

A systematic survey of authentication posture across the full public MCP registry.

**34K servers probed. Here's what requires credentials — and what doesn't.**

---

## Headline findings

- **33,901 of 37,167** public MCP endpoints probed (91.2% of the registry)
- **68.7%** of auth-classifiable endpoints returned a valid `initialize` response without credentials
- **27.4%** required OAuth
- **57%** of unique operators (n=16,118) had a majority-open posture
- Excluding the three largest bulk-registered operators: open drops to **64.0%**

> **"Open" means the MCP `initialize` handshake succeeded without credentials — not that tool calls are accessible.** Many servers intentionally allow `initialize` before gating everything else behind auth. No tool calls were made.

Full findings with methodology, Wilson CIs, platform breakdown, and OAuth IdP landscape: **[FINDINGS.md](FINDINGS.md)**

---

## What I measured

The MCP handshake starts with an `initialize` message — a mandatory JSON-RPC call every client sends before doing anything. I sent that one message, unauthenticated, to every endpoint in the registry and classified the response:

| Class | Meaning |
|---|---|
| `open` | Valid `initialize` reply, no credentials |
| `oauth` | HTTP 401 → RFC 9728 metadata resolved an auth server |
| `bearer_or_api_key` | 401/403 with API key hint |
| `not_mcp` | Responded but not MCP |
| `unreachable` | Timeout or connection refused |
| `skipped_robots` | `robots.txt` said no |

**Hard rules:** HTTPS only · 1 request per endpoint · 1s delay per host · 10s timeout · 4KB response cap · `robots.txt` respected · no tool calls ever

---

## Key results

### Auth posture (auth-classifiable endpoints, n=28,530)

| Class | n | % (95% Wilson CI) |
|---|---|---|
| `open` | 19,599 | 68.7% [68.2–69.2] |
| `oauth` | 7,804 | 27.4% [26.8–27.9] |
| `bearer_or_api_key` | 883 | 3.1% [2.9–3.3] |
| `auth_required_other` | 244 | 0.9% [0.8–1.0] |

### Platform defaults

| Platform | Endpoints | Open % | Default |
|---|---|---|---|
| Cloudflare Workers | 3,326 | 98.6% | open |
| Apify | 714 | 0.1% | **OAuth enforced** |
| Smithery | 218 | 0% | **OAuth enforced** |
| Vercel | 289 | 87.2% | operator choice |

### OAuth IdP landscape

| IdP | % of OAuth servers |
|---|---|
| Self-hosted | 83.8% |
| Apify | 10.2% |
| Supabase | 5.3% |
| Auth0, Stytch, Descope, WorkOS, Clerk | <0.5% each |

No Okta. No AWS Cognito. The MCP OAuth IdP market is fragmented and mostly self-hosted.

---

## Data

| File | Description |
|---|---|
| [`data/results_full.csv`](data/results_full.csv) | Full probe results (33,901 rows) |
| [`data/free_tier_candidates.csv`](data/free_tier_candidates.csv) | Open endpoints with free-tier phrases in their registry description |
| [`data/manual_validation_sample.csv`](data/manual_validation_sample.csv) | 25-endpoint random sample for manual review |

**Registry snapshot** (55K entries, 72MB) available on request — too large for git.

### CSV schema (`results_full.csv`)

```
registry_name, title, operator_domain, remote_type, url,
class, status, www_authenticate, auth_server, notes, probed_at
```

---

## Reproduce

```bash
pip install httpx tldextract

# Phase 2: probe all endpoints (resumable)
python mcp_survey.py phase2 --contact your@email.com

# Phase 3: analysis
python mcp_phase3.py --label "FINAL"

# Phase 4: publishable summary
python mcp_phase4.py
```

Probe is resumable — it skips URLs already in `data/results_full.csv`.

---

## Limitations

1. **Registry only** — Glama, PulseMCP, unregistered servers not included
2. **`initialize` is a weak signal** — tool-level auth is a separate question entirely
3. **Bulk operators skew per-endpoint numbers** — use per-operator figures as the primary unit
4. **OAuth vendor IDs are heuristics** — self-hosted figure likely overstated
5. **91.2% completion** — slow tail was timeouts, expected to be predominantly `unreachable`

---

## Responsible disclosure

This survey tested only the MCP `initialize` handshake. No tool calls, resource reads, or write operations were performed. No credentials or private data were accessed or retained.

Servers with unauthenticated tool calls that have persistent side effects, per-call cost, or private-data exposure are being contacted directly.

---

**Contact:** zachary.n.benson@outlook.com
**Survey date:** 2026-11-03/04
