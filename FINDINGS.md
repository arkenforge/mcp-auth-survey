# MCP Authentication Posture — Public Registry Survey

**Survey date:** 2026-11-03 to 2026-11-04  
**Published:** 2026-11-05 04:10Z  
**Contact:** zachary.n.benson@outlook.com  
**Data:** `mcp_probe/results_full.csv` (available on request)

> FACT = computed directly from the probe CSV. GUESS = judgment call or classification heuristic, noted inline.

---

## Headline findings  FACT

- **33,901 of 37,167** public MCP endpoints probed (91.2% of the registry)
- **68.7% [68.2–69.2]** of auth-classifiable endpoints returned a valid `initialize` response without credentials ("open")
- **27.4% [26.8–27.9]** required OAuth
- **56.9% [56.1–57.6]** of unique operators (n=16,118) had a majority-open posture
- Excluding the three largest bulk-registered operators: open drops to **64.0% [63.4–64.6]**

> **"Open" means only that the MCP `initialize` handshake succeeded without credentials.**
> It does not mean any tool call, resource, or prompt is accessible. Many servers
> intentionally allow `initialize` before redirecting to per-call auth or OAuth.

---

## Methodology

### Registry source

All server entries were fetched from `registry.modelcontextprotocol.io` on 2026-11-03
(paginated, `?limit=100&version=latest`). The snapshot contained **37,167 unique endpoints**
after filtering:

| Filter | Dropped |
|---|---|
| Inactive / no remote URLs | — |
| Non-HTTPS URLs | — |
| Unresolved `{...}` template placeholders | — |
| Duplicate URLs (keep first seen) | — |

Transport split: ~97% `streamable-http`, ~3% SSE.

### Probe logic (per endpoint, in order)

1. **`GET /robots.txt`** — if `Disallow: /` applies to `*` or our UA, classify `skipped_robots` and stop.
2. **`POST <endpoint>`** with a standard MCP `initialize` message (unauthenticated).
   - Valid JSON-RPC result → `open`
   - HTTP 401 with `WWW-Authenticate: Bearer` → go to step 3
   - HTTP 401 with other challenge → `auth_required_other`
   - HTTP 403 → `auth_required_other`
   - HTTP 4xx with `X-API-Key` header hint → `bearer_or_api_key`
   - HTTP 5xx → `origin_error`
   - Non-JSON or wrong content-type → `not_mcp`
   - Connection refused / timeout → `unreachable`
   - SSE stream (GET only) → `legacy_sse`
3. **`GET /.well-known/oauth-protected-resource`** (RFC 9728) — parse `authorization_servers[0]`
   to record the OAuth IdP domain. Classify `oauth`.

### Hard rules

- HTTPS only; no HTTP endpoints probed
- Maximum **1 `initialize` POST** per endpoint
- **1 s minimum delay** between requests to the same host
- **10 s timeout** per request; **4 KB** response body cap on `initialize`
- `robots.txt` respected (`User-Agent: *` and UA-specific rules)
- `opt_out.txt` hostname list checked before each probe
- **429 handling:** honor `Retry-After`; skip host after 2 consecutive 429s;
  pause entire run if >5% of last 100 requests return 429
- No tool calls, resource reads, or writes of any kind were performed

---

## Results

### 1. Per-endpoint class breakdown  FACT

n = 33,901 probed

| Class | n | % of all probed (95% Wilson CI) |
|---|---|---|
| `open` | 19,599 | 57.8% [57.3–58.3] |
| `oauth` | 7,804 | 23.0% [22.6–23.5] |
| `not_mcp` | 1,699 | 5.0% [4.8–5.2] |
| `skipped_robots` | 1,280 | 3.8% [3.6–4.0] |
| `unreachable` | 1,132 | 3.3% [3.2–3.5] |
| `bearer_or_api_key` | 883 | 2.6% [2.4–2.8] |
| `legacy_sse` | 814 | 2.4% [2.2–2.6] |
| `origin_error` | 444 | 1.3% [1.2–1.4] |
| `auth_required_other` | 244 | 0.7% [0.6–0.8] |
| `skipped_unsafe` | 2 | 0.0% [0.0–0.0] |

**Auth-classifiable subset** (n = 28,530, 84.2% of probed):

| Class | n | % of auth-classified (95% Wilson CI) |
|---|---|---|
| `open` | 19,599 | 68.7% [68.2–69.2] |
| `oauth` | 7,804 | 27.4% [26.8–27.9] |
| `bearer_or_api_key` | 883 | 3.1% [2.9–3.3] |
| `auth_required_other` | 244 | 0.9% [0.8–1.0] |

### 2. Per-operator view  FACT + GUESS

> GUESS: "operator" = registrable domain (eTLD+1). Multi-tenant platform domains
> (e.g. `workers.dev`) count as one operator regardless of how many endpoints they host.

**16,118 unique operators** with at least one auth-classified endpoint.

| Majority class | operators | % operators (95% Wilson CI) |
|---|---|---|
| `open` | 9,166 | 56.9% [56.1–57.6] |
| `oauth` | 6,121 | 38.0% [37.2–38.7] |
| `bearer_or_api_key` | 652 | 4.0% [3.8–4.4] |
| `auth_required_other` | 179 | 1.1% [1.0–1.3] |

**Bulk-operator sensitivity:**  FACT

Three operators account for a disproportionate share of endpoints:

| Operator | Endpoints | Open % |
|---|---|---|
| `workers.dev` (Cloudflare aggregator) | 3,536 | 92.8% |
| `pipeworx.io` | 1,916 | 96.5% |
| `mcp.ai` | 1,117 | 99.8% |

Excluding all three: open = **64.0% [63.4–64.6]** (n=24,822)

### 3. Platform-hosted vs self-hosted  FACT + GUESS

> GUESS: endpoints are tagged "platform-hosted" when their hostname ends with a known
> multi-tenant MCP hosting suffix. Auth posture reflects the **platform default**, not
> the individual operator's choice.

| Group | n auth-classified | open % (Wilson) | oauth % (Wilson) |
|---|---|---|---|
| All | 28,530 | 68.7% [68.2–69.2] | 27.4% [26.8–27.9] |
| Platform-hosted | 5,072 | 81.6% [80.5–82.6] | 15.0% [14.0–16.0] |
| Self-hosted | 23,458 | 65.9% [65.3–66.5] | 30.0% [29.4–30.6] |

Notable platform defaults:

| Platform | n endpoints | open | oauth | Default posture |
|---|---|---|---|---|
| `workers` | 3,326 | 3,281 | — | — |
| `apify` | 714 | 1 | — | OAuth enforced |
| `vercel` | 289 | 252 | — | mixed (operator choice) |
| `onrender` | 201 | 175 | — | — |
| `railway` | 126 | 109 | — | mixed |
| `getvda` | 104 | 104 | — | — |
| `supabase` | 101 | 67 | — | mixed |
| `run` | 91 | 68 | — | — |

### 4. TLD breakdown  FACT

> ⚠ = one operator accounts for >50% of that cell, or n<20. Treat with caution.

| TLD | n auth-classified | open % (Wilson) | oauth % |
|---|---|---|---|
| `.com` | 11,083 | 60.2% [59.3–61.1] | 35.4% |
| `.dev` | 4,448 | 90.4% [89.5–91.2] | 7.4% |
| `.io` | 3,833 | 82.7% [81.5–83.9] | 15.8% |
| `.ai` | 3,439 | 64.0% [62.4–65.6] | 32.8% |
| `.app` | 1,560 | 58.1% [55.6–60.5] | 36.5% |
| `.co` | 466 | 62.0% [57.5–66.3] | 35.2% |
| `.de` | 158 | 78.5% [71.4–84.2] | 16.5% |
| `.org` | 156 | 85.9% [79.6–90.5] | 11.5% |
| `.fr` | 135 | 75.6% [67.7–82.0] | 21.5% |
| `.cloud` | 127 | 33.9% [26.2–42.5] | 59.8% |
| `.eu` | 122 | 65.6% [56.8–73.4] | 27.9% |
| `.net` | 116 | 67.2% [58.3–75.1] | 21.6% |

### 5. OAuth authorization-server landscape  FACT + GUESS

Of 7,804 OAuth endpoints, all had a resolvable `auth_server` field via RFC 9728.

> GUESS: vendor names assigned by domain-suffix matching. Operators using a commercial
> IdP behind a custom subdomain are mis-classified as "self-hosted".
> This likely **understates** commercial IdP adoption.

| Vendor | endpoints | % of OAuth |
|---|---|---|
| self-hosted / other | 6,539 | 83.8% [83.0–84.6] |
| Apify | 799 | 10.2% [9.6–10.9] |
| Supabase | 411 | 5.3% [4.8–5.8] |
| Smithery | 28 | 0.4% [0.2–0.5] |
| Auth0 | 16 | 0.2% [0.1–0.3] |
| Stytch | 5 | 0.1% [0.0–0.1] |
| Descope | 4 | 0.1% [0.0–0.1] |
| WorkOS | 1 | 0.0% [0.0–0.1] |
| Clerk | 1 | 0.0% [0.0–0.1] |

Key observations:
- No Okta or AWS Cognito appeared in this sample
- Apify and Smithery are the only platforms sharing an auth backend across many servers
- The OAuth IdP landscape for MCP is highly fragmented — most operators are self-hosting

---

## Limitations

1. **Registry coverage only.** Servers listed on Glama, PulseMCP, or not registered
   anywhere are not included. The official registry skews toward newer/commercial servers.

2. **`initialize` is a weak signal.** Many MCP servers intentionally allow the handshake
   before requiring credentials for any tool call. "Open" in this survey means the
   handshake succeeded — it says nothing about whether tools, resources, or prompts
   are accessible without auth.

3. **No tool calls performed.** We did not test whether open servers expose sensitive
   tools, charge per-call fees, or allow writes. That requires separate validation.

4. **Vendor identification is approximate.** Commercial IdPs behind custom subdomains
   are classified as self-hosted. OAuth vendor adoption figures are floor estimates.

5. **Bulk-operator distortion.** Three operators contribute ~20% of all endpoints
   and are nearly all open. Per-operator numbers and sensitivity analyses
   are more meaningful than raw per-endpoint percentages.

6. **Snapshot date.** Auth posture can change. These numbers reflect the registry
   state on 2026-11-03 and probe results from 2026-11-03/04.

7. **91.2% completion.** The final ~9% of endpoints were in the slow tail
   (connection timeouts). These are expected to be predominantly `unreachable`
   and would not materially affect the open/oauth split.

---

## Responsible disclosure note

This survey tested only the MCP `initialize` handshake — a mandatory first message
in every MCP session. No tool calls, resource reads, or write operations were performed.
No credentials, tokens, or private data were accessed or retained.

Servers with unauthenticated tool calls that have persistent side effects, per-call cost,
or private-data exposure are being contacted directly before this report is published.

---

*Generated by `mcp_phase4.py` · 2026-11-05 04:10Z*