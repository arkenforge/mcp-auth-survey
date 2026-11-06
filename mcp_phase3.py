#!/usr/bin/env python3
"""
mcp_phase3.py — Phase 3 analysis (no network calls).
Reads mcp_probe/results_full.csv, writes mcp_probe/analysis_draft.md.
Run again on the complete CSV to produce the final version.

Usage: python3 mcp_phase3.py [--label "PRELIMINARY — 73% complete"]
"""
import argparse, csv, json, math, os, sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from urllib.parse import urlparse

RESULTS   = "mcp_probe/results_full.csv"
OUT_MD    = "mcp_probe/analysis_draft.md"
SNAPSHOT  = "mcp_probe/registry_snapshot.json"

# Must match mcp_survey.py
PLATFORM_SUFFIXES = [
    ("apify.actor",        "apify"),
    ("apify.com",          "apify"),
    ("smithery.ai",        "smithery"),
    ("workers.dev",        "cloudflare_workers"),
    ("supabase.co",        "supabase"),
    ("vercel.app",         "vercel"),
    ("fly.dev",            "fly_io"),
    ("railway.app",        "railway"),
    ("onrender.com",       "render"),
    ("run.app",            "cloud_run"),
    ("azurewebsites.net",  "azure"),
    ("getvda.ai",          "getvda"),
    ("ottobot.agency",     "ottobot"),
    ("ottobot2025.workers.dev", "cloudflare_workers"),
]

AUTH_CLASSES  = {"open", "oauth", "bearer_or_api_key", "auth_required_other"}
SKIP_CLASSES  = {"skipped_robots", "skipped_unsafe", "unreachable",
                 "not_mcp", "origin_error", "legacy_sse"}
ALL_CLASSES   = sorted(AUTH_CLASSES | SKIP_CLASSES)

FREE_PHRASES  = ["free", "no sign-up", "no signup", "no api key", "no-api-key",
                 "rate limit", "public access", "open access", "no auth",
                 "no authentication", "unauthenticated", "publicly accessible"]

# ── helpers ────────────────────────────────────────────────────────────────

def wilson(k, n, z=1.96):
    """95% Wilson score interval. Returns (lo, hi) as fractions."""
    if n == 0:
        return (0.0, 1.0)
    p = k / n
    denom = 1 + z*z/n
    centre = (p + z*z/(2*n)) / denom
    spread = z * math.sqrt(p*(1-p)/n + z*z/(4*n*n)) / denom
    return (max(0.0, centre - spread), min(1.0, centre + spread))

def fmt_wilson(k, n):
    lo, hi = wilson(k, n)
    return f"{k/n*100:.1f}% [{lo*100:.1f}–{hi*100:.1f}]"

def operator_domain(url: str) -> str:
    host = urlparse(url).hostname or ""
    try:
        import tldextract
        ext = tldextract.extract(host)
        if ext.suffix:
            return f"{ext.domain}.{ext.suffix}"
        return host
    except ImportError:
        parts = host.rsplit(".", 2)
        return ".".join(parts[-2:]) if len(parts) >= 2 else host

def platform_of(url: str):
    host = (urlparse(url).hostname or "").lower()
    for suffix, tag in PLATFORM_SUFFIXES:
        if host == suffix or host.endswith("." + suffix):
            return tag
    return None

def tld_of(url: str) -> str:
    host = urlparse(url).hostname or ""
    return host.rsplit(".", 1)[-1] if "." in host else "?"

def majority_class(class_list):
    if not class_list:
        return "unknown"
    return Counter(class_list).most_common(1)[0][0]

def pct(n, total):
    return f"{n/total*100:.1f}%" if total else "—"

def flag(n, dominant_op_share=None):
    flags = []
    if n < 20:
        flags.append("n<20")
    if dominant_op_share and dominant_op_share > 0.5:
        flags.append(f"1 op={dominant_op_share*100:.0f}%")
    return f"  ⚠ {', '.join(flags)}" if flags else ""

# ── load data ──────────────────────────────────────────────────────────────

def load_results():
    rows = []
    with open(RESULTS, newline="") as f:
        for row in csv.DictReader(f):
            if row.get("class"):
                rows.append(row)
    return rows

# ── analysis ───────────────────────────────────────────────────────────────

def run(label):
    rows = load_results()
    n_total = len(rows)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%MZ")

    lines = []
    def w(*args): lines.append(" ".join(str(a) for a in args))
    def h1(t): w(f"\n# {t}")
    def h2(t): w(f"\n## {t}")
    def h3(t): w(f"\n### {t}")
    def rule(): w("\n---")

    # ── header ──
    w(f"# MCP Authentication Posture — Analysis")
    w(f"\n> **{label}**")
    w(f"\nGenerated: {ts}  ")
    w(f"Rows analysed: {n_total:,} of 37,167 total endpoints  ")
    w(f"Source: `mcp_probe/results_full.csv`  ")
    w(f'Registry snapshot: `mcp_probe/registry_snapshot.json`\n')
    w("> **NOTE:** \"open\" means the MCP `initialize` handshake succeeded without")
    w("> credentials. It does **not** mean tool calls are callable without auth.")
    w("> FACT = computed from CSV. GUESS = judgment call noted inline.\n")
    rule()

    # ── 1. per-endpoint class breakdown ──
    h2("1. Per-endpoint class breakdown  FACT")
    counts = Counter(r["class"] for r in rows)
    w(f"\nn={n_total:,}\n")
    w(f"| Class | n | % (95% Wilson) |")
    w(f"|---|---|---|")
    for cls in sorted(counts, key=lambda x: -counts[x]):
        k = counts[cls]
        w(f"| {cls} | {k:,} | {fmt_wilson(k, n_total)} |")

    # Summarise auth-classified only (exclude skips/unreachable)
    auth_rows = [r for r in rows if r["class"] in AUTH_CLASSES]
    n_auth = len(auth_rows)
    h3("Auth-classified only (excludes skipped/unreachable/not_mcp/legacy_sse/origin_error)")
    w(f"\nn={n_auth:,}  (FACT: {n_auth/n_total*100:.1f}% of all probed had a classifiable auth posture)\n")
    auth_counts = Counter(r["class"] for r in auth_rows)
    w(f"| Class | n | % of auth-classified (95% Wilson) |")
    w(f"|---|---|---|")
    for cls in ["open","oauth","bearer_or_api_key","auth_required_other"]:
        k = auth_counts.get(cls, 0)
        w(f"| {cls} | {k:,} | {fmt_wilson(k, n_auth)} |")

    rule()

    # ── 2. platform vs self-hosted ──
    h2("2. Platform-hosted vs self-hosted  FACT + GUESS")
    w("""
JUDGMENT CALL: endpoints are tagged "platform-hosted" when their hostname ends
with a known multi-tenant MCP hosting suffix (workers.dev, apify.actor/.com,
smithery.ai, vercel.app, fly.dev, railway.app, onrender.com, run.app,
azurewebsites.net, supabase.co, getvda.ai, ottobot.agency).  Their auth posture
reflects the platform default, not the individual operator's choice.
Platform-hosted endpoints are reported separately throughout.
""")
    plat_rows = [r for r in rows if platform_of(r["url"])]
    self_rows = [r for r in rows if not platform_of(r["url"])]
    plat_auth = [r for r in plat_rows if r["class"] in AUTH_CLASSES]
    self_auth = [r for r in self_rows if r["class"] in AUTH_CLASSES]

    w(f"| | n endpoints | n auth-classified | open % (Wilson) | oauth % (Wilson) |")
    w(f"|---|---|---|---|---|")
    for label2, grp, agrp in [
        ("all", rows, auth_rows),
        ("platform-hosted", plat_rows, plat_auth),
        ("self-hosted", self_rows, self_auth),
    ]:
        no = Counter(r["class"] for r in agrp).get("open", 0)
        noa = Counter(r["class"] for r in agrp).get("oauth", 0)
        na = len(agrp)
        w(f"| {label2} | {len(grp):,} | {na:,} | {fmt_wilson(no,na)} | {fmt_wilson(noa,na)} |")

    # Platform breakdown
    plat_counts = Counter(platform_of(r["url"]) for r in plat_rows)
    plat_open   = Counter(platform_of(r["url"]) for r in plat_rows if r["class"]=="open")
    plat_oauth  = Counter(platform_of(r["url"]) for r in plat_rows if r["class"]=="oauth")
    w(f"\n| Platform | endpoints | open | oauth |")
    w(f"|---|---|---|---|")
    for p, n in plat_counts.most_common():
        w(f"| {p} | {n:,} | {plat_open[p]:,} | {plat_oauth[p]:,} |")

    rule()

    # ── 3. per-operator ──
    h2("3. Per-operator breakdown  FACT + GUESS")
    w("""
JUDGMENT CALL: "operator" = registrable domain (eTLD+1). Uses tldextract when
available; otherwise last two dot-labels (may mis-split ccSLDs like .co.uk —
flagged where observed). Each operator is assigned its majority class across all
its endpoints. Operators with mixed classes are counted separately.
""")

    op_rows = defaultdict(list)
    for r in rows:
        op_rows[operator_domain(r["url"])].append(r["class"])

    op_majority = {op: majority_class(cls) for op, cls in op_rows.items()}
    op_counts_by_class = Counter(op_majority.values())
    n_ops = len(op_rows)
    mixed_ops = sum(1 for op, cls in op_rows.items()
                    if len(set(c for c in cls if c in AUTH_CLASSES)) > 1)

    w(f"Total unique operators: {n_ops:,}  FACT")
    w(f"Operators with mixed auth classes (>1 auth class across their endpoints): {mixed_ops:,}  FACT\n")
    w(f"| Majority class | operators | % operators (Wilson) |")
    w(f"|---|---|---|")
    for cls in sorted(op_counts_by_class, key=lambda x: -op_counts_by_class[x]):
        k = op_counts_by_class[cls]
        w(f"| {cls} | {k:,} | {fmt_wilson(k, n_ops)} |")

    # top 20 operators by endpoint count
    h3("Top 20 operators by endpoint count")
    top_ops = Counter({op: len(cls) for op, cls in op_rows.items()}).most_common(20)
    w(f"\n| Rank | Operator | Endpoints | Majority class | Open% |")
    w(f"|---|---|---|---|---|")
    for i, (op, n) in enumerate(top_ops, 1):
        cls_list = op_rows[op]
        maj = majority_class(cls_list)
        n_open = cls_list.count("open")
        f_note = flag(n, n/n_total if n/n_total > 0.05 else None)
        w(f"| {i} | `{op}` | {n:,} | {maj} | {pct(n_open,n)}{f_note} |")

    # Excluding top operator — single-operator sensitivity
    top_op_name = top_ops[0][0] if top_ops else None
    if top_op_name:
        excl_rows = [r for r in rows if operator_domain(r["url"]) != top_op_name]
        excl_auth = [r for r in excl_rows if r["class"] in AUTH_CLASSES]
        no_excl = sum(1 for r in excl_auth if r["class"]=="open")
        h3(f"Sensitivity: excluding top operator (`{top_op_name}`)")
        w(f"\n| | n | open % (Wilson) |")
        w(f"|---|---|---|")
        w(f"| with top operator | {len(auth_rows):,} | {fmt_wilson(auth_counts.get('open',0), n_auth)} |")
        w(f"| without top operator | {len(excl_auth):,} | {fmt_wilson(no_excl, len(excl_auth))} |")

    rule()

    # ── 4. TLD breakdown ──
    h2("4. TLD breakdown  FACT")
    w(f"\nFLAG: cells with n<20 or one operator >50% of cell are marked ⚠\n")

    tld_rows = defaultdict(list)
    for r in rows:
        tld_rows[tld_of(r["url"])].append(r)

    tld_ops = defaultdict(set)
    for r in rows:
        tld_ops[tld_of(r["url"])].add(operator_domain(r["url"]))

    top_tlds = Counter({t: len(rs) for t, rs in tld_rows.items()}).most_common(25)
    w(f"| TLD | n | open % (Wilson) | oauth % | operators |")
    w(f"|---|---|---|---|---|")
    for tld, n in top_tlds:
        rs   = tld_rows[tld]
        auth = [r for r in rs if r["class"] in AUTH_CLASSES]
        no   = sum(1 for r in auth if r["class"]=="open")
        noa  = sum(1 for r in auth if r["class"]=="oauth")
        na   = len(auth)
        n_op = len(tld_ops[tld])
        # dominant operator share
        op_share = Counter(operator_domain(r["url"]) for r in rs)
        dom_share = op_share.most_common(1)[0][1]/n if op_share else 0
        f_note = flag(na, dom_share if dom_share > 0.5 else None)
        w(f"| .{tld} | {n:,} | {fmt_wilson(no,na) if na else '—'} | {pct(noa,na)}{f_note} | {n_op:,} |")

    rule()

    # ── 5. Transport type ──
    h2("5. Transport type  FACT")
    transport_rows = defaultdict(list)
    for r in rows:
        transport_rows[r.get("remote_type","unknown")].append(r)

    w(f"\n| Transport | n | open % (Wilson) | oauth % |")
    w(f"|---|---|---|---|")
    for t, rs in sorted(transport_rows.items(), key=lambda x: -len(x[1])):
        auth = [r for r in rs if r["class"] in AUTH_CLASSES]
        no  = sum(1 for r in auth if r["class"]=="open")
        noa = sum(1 for r in auth if r["class"]=="oauth")
        na  = len(auth)
        w(f"| {t} | {len(rs):,} | {fmt_wilson(no,na) if na else '—'} | {pct(noa,na)} |")

    rule()

    # ── 6. OAuth auth-server host ──
    h2("6. OAuth authorization-server hosts  FACT")
    w("""
Only endpoints classified `oauth` with a resolved `auth_server` field are included.
JUDGMENT CALL: vendors identified by domain suffix (e.g. *.clerk.com → Clerk,
*.descope.com → Descope). Servers on the operator's own subdomain are "self-hosted".
""")
    oauth_with_as = [r for r in rows
                     if r["class"]=="oauth" and r.get("auth_server","").strip()]
    as_counts = Counter(r["auth_server"] for r in oauth_with_as)
    n_oauth_total = counts.get("oauth", 0)

    # Tag vendor
    VENDOR_SUFFIXES = {
        "clerk.com": "Clerk", "clerk.dev": "Clerk",
        "descope.com": "Descope",
        "auth0.com": "Auth0", "okta.com": "Okta",
        "cognito": "AWS Cognito",
        "supabase.co": "Supabase",
        "fusionauth.io": "FusionAuth",
        "keycloak": "Keycloak",
        "workos.com": "WorkOS",
        "stytch.com": "Stytch",
        "apify.com": "Apify",
        "smithery.ai": "Smithery",
    }
    def vendor_of(domain):
        for suffix, name in VENDOR_SUFFIXES.items():
            if domain.endswith(suffix):
                return name
        return None

    vendor_counts = Counter()
    for domain, n in as_counts.items():
        v = vendor_of(domain)
        if v:
            vendor_counts[v] += n
        else:
            vendor_counts["self-hosted / other"] += n

    w(f"oauth endpoints: {n_oauth_total:,}  |  with resolved auth_server: {len(oauth_with_as):,}\n")
    w(f"**By vendor (GUESS — domain-suffix match):**\n")
    w(f"| Vendor | endpoints |")
    w(f"|---|---|")
    for v, n in vendor_counts.most_common():
        w(f"| {v} | {n:,} |")

    w(f"\n**Top 20 auth-server domains (FACT):**\n")
    w(f"| Auth-server domain | endpoints |")
    w(f"|---|---|")
    for domain, n in as_counts.most_common(20):
        w(f"| `{domain}` | {n:,} |")

    rule()

    # ── 7. Free-tier candidates ──
    h2("7. Free-tier candidates  FACT (phrase match) + GUESS (relevance)")
    w("""
Open endpoints whose registry `title` or `description` contains a phrase
suggesting intentional public/free access. JUDGMENT CALL: phrase list is
conservative; misses servers that are open by design but don't advertise it.
""")
    # Need to join with snapshot for descriptions
    desc_map = {}
    if os.path.exists(SNAPSHOT):
        with open(SNAPSHOT) as f:
            snap = json.load(f)
        for item in snap.get("servers", []):
            srv = item.get("server", {})
            remotes = srv.get("remotes", [])
            for rem in remotes:
                ep = rem.get("url","").rstrip("/")
                if ep:
                    desc_map[ep] = {
                        "name": srv.get("name",""),
                        "title": srv.get("title",""),
                        "desc": srv.get("description",""),
                        "repo": (srv.get("repository") or {}).get("url",""),
                        "website": srv.get("websiteUrl",""),
                    }

    free_candidates = []
    for r in rows:
        if r["class"] != "open":
            continue
        meta = desc_map.get(r["url"], {})
        text = " ".join([
            meta.get("title",""), meta.get("desc",""),
            r.get("registry_name",""), r.get("title","")
        ]).lower()
        matched = [p for p in FREE_PHRASES if p in text]
        if matched:
            free_candidates.append({
                "url": r["url"],
                "operator": r.get("operator_domain",""),
                "registry_name": meta.get("name","") or r.get("registry_name",""),
                "title": meta.get("title","") or r.get("title",""),
                "matched_phrase": matched[0],
                "repo": meta.get("repo",""),
                "website": meta.get("website",""),
            })

    w(f"\n{len(free_candidates):,} open endpoints matched a free-tier phrase.\n")
    w(f"Full list saved to `mcp_probe/free_tier_candidates.csv`.\n")
    w(f"Top 20 sample:\n")
    w(f"| Operator | Title | Matched phrase | Repo/Website |")
    w(f"|---|---|---|---|")
    for fc in free_candidates[:20]:
        link = fc["repo"] or fc["website"] or "—"
        w(f"| `{fc['operator']}` | {fc['title'][:40]} | `{fc['matched_phrase']}` | {link[:60]} |")

    # Save full CSV
    ftc_path = "mcp_probe/free_tier_candidates.csv"
    with open(ftc_path, "w", newline="") as f:
        fieldnames = ["url","operator","registry_name","title",
                      "matched_phrase","repo","website"]
        ww = csv.DictWriter(f, fieldnames=fieldnames)
        ww.writeheader()
        ww.writerows(free_candidates)

    rule()

    # ── 8. Manual validation sample ──
    h2("8. Manual validation sample (25 random open endpoints)")
    w("""
25 open endpoints selected at random (seed 7) for manual review.
Do NOT probe these — read their docs/repo only.
""")
    import random
    open_rows = [r for r in rows if r["class"]=="open"]
    rng = random.Random(7)
    sample = open_rows[:]
    rng.shuffle(sample)
    sample25 = sample[:25]

    w(f"| # | URL | Operator | Registry name | Repo/Website |")
    w(f"|---|---|---|---|---|")
    for i, r in enumerate(sample25, 1):
        meta = desc_map.get(r["url"], {})
        link = meta.get("repo","") or meta.get("website","") or "—"
        w(f"| {i} | `{r['url'][:55]}` | `{r.get('operator_domain','')}` | {r.get('registry_name','')[:35]} | {link[:55]} |")

    # Save CSV
    mvc_path = "mcp_probe/manual_validation_sample.csv"
    with open(mvc_path, "w", newline="") as f:
        fieldnames = ["url","operator_domain","registry_name","title","repo","website"]
        ww = csv.DictWriter(f, fieldnames=fieldnames)
        ww.writeheader()
        for r in sample25:
            meta = desc_map.get(r["url"], {})
            ww.writerow({
                "url": r["url"],
                "operator_domain": r.get("operator_domain",""),
                "registry_name": meta.get("name","") or r.get("registry_name",""),
                "title": meta.get("title","") or r.get("title",""),
                "repo": meta.get("repo",""),
                "website": meta.get("website",""),
            })

    rule()

    # ── 9. Limitations ──
    h2("9. Limitations")
    w("""
- **Registry coverage:** The official MCP registry is not the whole ecosystem.
  Servers listed on Glama, PulseMCP, or not registered anywhere are not included.
- **\"open\" means handshake only:** A successful `initialize` response does not
  imply that any tool call, resource, or prompt is accessible without credentials.
  Many servers gate all tools behind per-call auth even when `initialize` is open.
- **Vendor identification:** Auth-server vendors are identified by domain-suffix
  matching. Operators using Clerk/Auth0/etc. behind a custom domain are
  mis-classified as "self-hosted". This likely understates vendor adoption.
- **Bulk operators:** The registry contains several operators with hundreds to
  thousands of endpoints (pipeworx.io, mcp.ai, workers.dev aggregators). The
  per-endpoint open rate is heavily influenced by these. Per-operator numbers
  are the more meaningful unit.
- **Snapshot date:** Registry entries reflect the state at time of snapshot.
  Servers may have changed auth posture since then.
- **One-way test:** Only `initialize` was sent. We did not test whether servers
  that returned 401 would accept expired/malformed tokens, or whether open
  servers expose sensitive tools.
""")

    rule()

    # ── write ──
    out = "\n".join(lines)
    with open(OUT_MD, "w") as f:
        f.write(out)

    print(f"Written → {OUT_MD}", file=sys.stderr)
    print(f"Written → {ftc_path}", file=sys.stderr)
    print(f"Written → {mvc_path}", file=sys.stderr)
    return lines


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--label", default="PRELIMINARY — probe not yet complete")
    args = ap.parse_args()
    run(args.label)


if __name__ == "__main__":
    main()
