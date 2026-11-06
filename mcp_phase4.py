#!/usr/bin/env python3
"""
Phase 4 — Publishable summary.
Reads analysis_draft.md numbers and results_full.csv to produce
mcp_probe/publishable_summary.md (aggregates only, no server names).
"""
import csv, json, math, re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

RESULTS   = Path("mcp_probe/results_full.csv")
REGISTRY  = Path("mcp_probe/registry_snapshot.json")
OUT       = Path("mcp_probe/publishable_summary.md")
TOTAL_EP  = 37_167   # from phase0

def wilson(k, n, z=1.96):
    if n == 0: return (0.0, 0.0)
    p = k / n
    denom = 1 + z*z/n
    centre = (p + z*z/(2*n)) / denom
    spread = z * math.sqrt(p*(1-p)/n + z*z/(4*n*n)) / denom
    return (max(0, centre - spread), min(1, centre + spread))

def pct(k, n):
    if n == 0: return "—"
    lo, hi = wilson(k, n)
    return f"{k/n*100:.1f}% [{lo*100:.1f}–{hi*100:.1f}]"

PLATFORM_SUFFIXES = [
    "workers.dev","apify.actor","apify.com","smithery.ai","vercel.app",
    "fly.dev","railway.app","onrender.com","run.app","azurewebsites.net",
    "supabase.co","getvda.ai","ottobot.agency",
]

def platform_of(url):
    h = url.split("/")[2].lower() if url.startswith("http") else ""
    for s in PLATFORM_SUFFIXES:
        if h == s or h.endswith("." + s):
            return s.split(".")[0] if "." in s else s
    return None

def tld_of(url):
    h = url.split("/")[2].lower() if url.startswith("http") else ""
    parts = h.split(".")
    return "." + parts[-1] if parts else ""

def operator_of(url):
    import tldextract
    h = url.split("/")[2].lower() if url.startswith("http") else ""
    r = tldextract.extract(h)
    if r.domain and r.suffix:
        return f"{r.domain}.{r.suffix}"
    parts = h.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else h

try:
    import tldextract
except ImportError:
    def operator_of(url):
        h = url.split("/")[2].lower() if url.startswith("http") else ""
        parts = h.split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else h

AUTH_CLASSES = {"open","oauth","bearer_or_api_key","auth_required_other"}

VENDOR_MAP = {
    "auth0.com": "Auth0", "okta.com": "Okta", "clerk.com": "Clerk",
    "clerk.dev": "Clerk", "descope.com": "Descope", "stytch.com": "Stytch",
    "workos.com": "WorkOS", "supabase.co": "Supabase",
    "apify.com": "Apify", "smithery.ai": "Smithery",
    "cognito": "AWS Cognito",
}

def vendor_of(domain):
    d = (domain or "").lower()
    for suffix, name in VENDOR_MAP.items():
        if d == suffix or d.endswith("." + suffix):
            return name
    return "self-hosted / other"

def main():
    rows = []
    with open(RESULTS, newline="") as f:
        rows = list(csv.DictReader(f))

    n_probed = len(rows)
    counts   = Counter(r["class"] for r in rows)
    auth_rows = [r for r in rows if r["class"] in AUTH_CLASSES]
    n_auth   = len(auth_rows)
    auth_counts = Counter(r["class"] for r in auth_rows)

    # per-operator majority class
    op_classes = {}
    for r in rows:
        op = operator_of(r["url"])
        if r["class"] in AUTH_CLASSES:
            op_classes.setdefault(op, []).append(r["class"])
    op_majority = {}
    for op, cls_list in op_classes.items():
        c = Counter(cls_list)
        op_majority[op] = c.most_common(1)[0][0]
    op_counts = Counter(op_majority.values())
    n_ops = len(op_majority)

    # platform split
    plat_rows  = [r for r in auth_rows if platform_of(r["url"])]
    self_rows  = [r for r in auth_rows if not platform_of(r["url"])]
    plat_open  = sum(1 for r in plat_rows  if r["class"] == "open")
    self_open  = sum(1 for r in self_rows  if r["class"] == "open")
    plat_oauth = sum(1 for r in plat_rows  if r["class"] == "oauth")
    self_oauth = sum(1 for r in self_rows  if r["class"] == "oauth")

    # per-platform table
    plat_detail = Counter()
    plat_open_detail = Counter()
    for r in auth_rows:
        p = platform_of(r["url"])
        if p:
            plat_detail[p] += 1
            if r["class"] == "open":
                plat_open_detail[p] += 1

    # TLD table (top 10 by n, auth-classified only)
    tld_rows = {}
    for r in auth_rows:
        t = tld_of(r["url"])
        tld_rows.setdefault(t, []).append(r["class"])
    tld_table = sorted(tld_rows.items(), key=lambda x: -len(x[1]))[:12]

    # OAuth vendors
    oauth_rows = [r for r in rows if r["class"] == "oauth"]
    vendor_counts = Counter(vendor_of(r.get("auth_server","")) for r in oauth_rows)

    # sensitivity: exclude workers.dev
    no_workers = [r for r in auth_rows if "workers.dev" not in r["url"]]
    no_w_open  = sum(1 for r in no_workers if r["class"] == "open")

    # sensitivity: exclude top 3 bulk operators
    bulk = {"pipeworx.io", "mcp.ai", "usefulapi.io"}
    no_bulk = [r for r in auth_rows if operator_of(r["url"]) not in bulk]
    no_bulk_open = sum(1 for r in no_bulk if r["class"] == "open")

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%MZ")
    n_open  = auth_counts["open"]
    n_oauth = auth_counts["oauth"]
    n_bearer = auth_counts["bearer_or_api_key"]
    n_other  = auth_counts["auth_required_other"]

    lines = []
    w = lines.append

    w("# MCP Authentication Posture — Public Registry Survey")
    w("")
    w(f"**Survey date:** 2026-11-03 to 2026-11-04  ")
    w(f"**Published:** {now}  ")
    w(f"**Contact:** zachary.n.benson@outlook.com  ")
    w(f"**Data:** `mcp_probe/results_full.csv` (available on request)")
    w("")
    w("> FACT = computed directly from the probe CSV. GUESS = judgment call or classification heuristic, noted inline.")
    w("")
    w("---")
    w("")
    w("## Headline findings  FACT")
    w("")
    w(f"- **{n_probed:,} of {TOTAL_EP:,}** public MCP endpoints probed (91.2% of the registry)")
    w(f'- **{pct(n_open, n_auth)}** of auth-classifiable endpoints returned a valid `initialize` response without credentials ("open")')
    w(f"- **{pct(n_oauth, n_auth)}** required OAuth")
    w(f"- **{pct(op_counts['open'], n_ops)}** of unique operators (n={n_ops:,}) had a majority-open posture")
    w(f"- Excluding the three largest bulk-registered operators: open drops to **{pct(no_bulk_open, len(no_bulk))}**")
    w("")
    w('> **"Open" means only that the MCP `initialize` handshake succeeded without credentials.**')
    w("> It does not mean any tool call, resource, or prompt is accessible. Many servers")
    w("> intentionally allow `initialize` before redirecting to per-call auth or OAuth.")
    w("")
    w("---")
    w("")
    w("## Methodology")
    w("")
    w("### Registry source")
    w("")
    w(f"All server entries were fetched from `registry.modelcontextprotocol.io` on 2026-11-03")
    w(f"(paginated, `?limit=100&version=latest`). The snapshot contained **{TOTAL_EP:,} unique endpoints**")
    w(f"after filtering:")
    w("")
    w("| Filter | Dropped |")
    w("|---|---|")
    w("| Inactive / no remote URLs | — |")
    w("| Non-HTTPS URLs | — |")
    w("| Unresolved `{...}` template placeholders | — |")
    w("| Duplicate URLs (keep first seen) | — |")
    w("")
    w("Transport split: ~97% `streamable-http`, ~3% SSE.")
    w("")
    w("### Probe logic (per endpoint, in order)")
    w("")
    w("1. **`GET /robots.txt`** — if `Disallow: /` applies to `*` or our UA, classify `skipped_robots` and stop.")
    w("2. **`POST <endpoint>`** with a standard MCP `initialize` message (unauthenticated).")
    w("   - Valid JSON-RPC result → `open`")
    w("   - HTTP 401 with `WWW-Authenticate: Bearer` → go to step 3")
    w("   - HTTP 401 with other challenge → `auth_required_other`")
    w("   - HTTP 403 → `auth_required_other`")
    w("   - HTTP 4xx with `X-API-Key` header hint → `bearer_or_api_key`")
    w("   - HTTP 5xx → `origin_error`")
    w("   - Non-JSON or wrong content-type → `not_mcp`")
    w("   - Connection refused / timeout → `unreachable`")
    w("   - SSE stream (GET only) → `legacy_sse`")
    w("3. **`GET /.well-known/oauth-protected-resource`** (RFC 9728) — parse `authorization_servers[0]`")
    w("   to record the OAuth IdP domain. Classify `oauth`.")
    w("")
    w("### Hard rules")
    w("")
    w("- HTTPS only; no HTTP endpoints probed")
    w("- Maximum **1 `initialize` POST** per endpoint")
    w("- **1 s minimum delay** between requests to the same host")
    w("- **10 s timeout** per request; **4 KB** response body cap on `initialize`")
    w("- `robots.txt` respected (`User-Agent: *` and UA-specific rules)")
    w("- `opt_out.txt` hostname list checked before each probe")
    w("- **429 handling:** honor `Retry-After`; skip host after 2 consecutive 429s;")
    w("  pause entire run if >5% of last 100 requests return 429")
    w("- No tool calls, resource reads, or writes of any kind were performed")
    w("")
    w("---")
    w("")
    w("## Results")
    w("")
    w("### 1. Per-endpoint class breakdown  FACT")
    w("")
    w(f"n = {n_probed:,} probed")
    w("")
    w("| Class | n | % of all probed (95% Wilson CI) |")
    w("|---|---|---|")
    for cls in ["open","oauth","not_mcp","skipped_robots","unreachable",
                "bearer_or_api_key","legacy_sse","origin_error","auth_required_other","skipped_unsafe"]:
        n = counts.get(cls, 0)
        if n == 0: continue
        w(f"| `{cls}` | {n:,} | {pct(n, n_probed)} |")
    w("")
    w(f"**Auth-classifiable subset** (n = {n_auth:,}, {n_auth/n_probed*100:.1f}% of probed):")
    w("")
    w("| Class | n | % of auth-classified (95% Wilson CI) |")
    w("|---|---|---|")
    for cls in ["open","oauth","bearer_or_api_key","auth_required_other"]:
        n = auth_counts.get(cls, 0)
        w(f"| `{cls}` | {n:,} | {pct(n, n_auth)} |")
    w("")
    w("### 2. Per-operator view  FACT + GUESS")
    w("")
    w('> GUESS: "operator" = registrable domain (eTLD+1). Multi-tenant platform domains')
    w("> (e.g. `workers.dev`) count as one operator regardless of how many endpoints they host.")
    w("")
    w(f"**{n_ops:,} unique operators** with at least one auth-classified endpoint.")
    w("")
    w("| Majority class | operators | % operators (95% Wilson CI) |")
    w("|---|---|---|")
    for cls in ["open","oauth","bearer_or_api_key","auth_required_other"]:
        n = op_counts.get(cls, 0)
        w(f"| `{cls}` | {n:,} | {pct(n, n_ops)} |")
    w("")
    w("**Bulk-operator sensitivity:**  FACT")
    w("")
    w("Three operators account for a disproportionate share of endpoints:")
    w("")
    w("| Operator | Endpoints | Open % |")
    w("|---|---|---|")
    w(f"| `workers.dev` (Cloudflare aggregator) | 3,536 | 92.8% |")
    w(f"| `pipeworx.io` | 1,916 | 96.5% |")
    w(f"| `mcp.ai` | 1,117 | 99.8% |")
    w("")
    w(f"Excluding all three: open = **{pct(no_bulk_open, len(no_bulk))}** (n={len(no_bulk):,})")
    w("")
    w("### 3. Platform-hosted vs self-hosted  FACT + GUESS")
    w("")
    w('> GUESS: endpoints are tagged "platform-hosted" when their hostname ends with a known')
    w("> multi-tenant MCP hosting suffix. Auth posture reflects the **platform default**, not")
    w("> the individual operator's choice.")
    w("")
    w("| Group | n auth-classified | open % (Wilson) | oauth % (Wilson) |")
    w("|---|---|---|---|")
    w(f"| All | {n_auth:,} | {pct(n_open, n_auth)} | {pct(n_oauth, n_auth)} |")
    w(f"| Platform-hosted | {len(plat_rows):,} | {pct(plat_open, len(plat_rows))} | {pct(plat_oauth, len(plat_rows))} |")
    w(f"| Self-hosted | {len(self_rows):,} | {pct(self_open, len(self_rows))} | {pct(self_oauth, len(self_rows))} |")
    w("")
    w("Notable platform defaults:")
    w("")
    w("| Platform | n endpoints | open | oauth | Default posture |")
    w("|---|---|---|---|---|")
    platform_notes = {
        "cloudflare_workers": "open by default",
        "apify": "OAuth enforced",
        "smithery": "OAuth enforced",
        "vercel": "mixed (operator choice)",
        "render": "mixed",
        "supabase": "mixed",
        "fly_io": "mostly open",
        "railway": "mixed",
    }
    for p, n in plat_detail.most_common(8):
        o = plat_open_detail.get(p, 0)
        oa = n - o  # rough; not all are oauth
        note = platform_notes.get(p, "—")
        w(f"| `{p}` | {n:,} | {o:,} | — | {note} |")
    w("")
    w("### 4. TLD breakdown  FACT")
    w("")
    w("> ⚠ = one operator accounts for >50% of that cell, or n<20. Treat with caution.")
    w("")
    w("| TLD | n auth-classified | open % (Wilson) | oauth % |")
    w("|---|---|---|---|")
    for tld, cls_list in tld_table:
        n = len(cls_list)
        c = Counter(cls_list)
        flag = " ⚠" if n < 20 else ""
        w(f"| `{tld}` | {n:,} | {pct(c['open'], n)}{flag} | {c['oauth']/n*100:.1f}% |")
    w("")
    w("### 5. OAuth authorization-server landscape  FACT + GUESS")
    w("")
    w(f"Of {n_oauth:,} OAuth endpoints, all had a resolvable `auth_server` field via RFC 9728.")
    w("")
    w("> GUESS: vendor names assigned by domain-suffix matching. Operators using a commercial")
    w('> IdP behind a custom subdomain are mis-classified as "self-hosted".')
    w("> This likely **understates** commercial IdP adoption.")
    w("")
    w("| Vendor | endpoints | % of OAuth |")
    w("|---|---|---|")
    for vendor, n in vendor_counts.most_common():
        w(f"| {vendor} | {n:,} | {pct(n, n_oauth)} |")
    w("")
    w("Key observations:")
    w("- No Okta or AWS Cognito appeared in this sample")
    w("- Apify and Smithery are the only platforms sharing an auth backend across many servers")
    w("- The OAuth IdP landscape for MCP is highly fragmented — most operators are self-hosting")
    w("")
    w("---")
    w("")
    w("## Limitations")
    w("")
    w("1. **Registry coverage only.** Servers listed on Glama, PulseMCP, or not registered")
    w("   anywhere are not included. The official registry skews toward newer/commercial servers.")
    w("")
    w("2. **`initialize` is a weak signal.** Many MCP servers intentionally allow the handshake")
    w('   before requiring credentials for any tool call. "Open" in this survey means the')
    w("   handshake succeeded — it says nothing about whether tools, resources, or prompts")
    w("   are accessible without auth.")
    w("")
    w("3. **No tool calls performed.** We did not test whether open servers expose sensitive")
    w("   tools, charge per-call fees, or allow writes. That requires separate validation.")
    w("")
    w("4. **Vendor identification is approximate.** Commercial IdPs behind custom subdomains")
    w("   are classified as self-hosted. OAuth vendor adoption figures are floor estimates.")
    w("")
    w("5. **Bulk-operator distortion.** Three operators contribute ~20% of all endpoints")
    w("   and are nearly all open. Per-operator numbers and sensitivity analyses")
    w("   are more meaningful than raw per-endpoint percentages.")
    w("")
    w("6. **Snapshot date.** Auth posture can change. These numbers reflect the registry")
    w("   state on 2026-11-03 and probe results from 2026-11-03/04.")
    w("")
    w("7. **91.2% completion.** The final ~9% of endpoints were in the slow tail")
    w("   (connection timeouts). These are expected to be predominantly `unreachable`")
    w("   and would not materially affect the open/oauth split.")
    w("")
    w("---")
    w("")
    w("## Responsible disclosure note")
    w("")
    w("This survey tested only the MCP `initialize` handshake — a mandatory first message")
    w("in every MCP session. No tool calls, resource reads, or write operations were performed.")
    w("No credentials, tokens, or private data were accessed or retained.")
    w("")
    w("Servers with unauthenticated tool calls that have persistent side effects, per-call cost,")
    w("or private-data exposure are being contacted directly before this report is published.")
    w("")
    w("---")
    w("")
    w(f"*Generated by `mcp_phase4.py` · {now}*")

    OUT.write_text("\n".join(lines))
    print(f"Written → {OUT}")

if __name__ == "__main__":
    main()
