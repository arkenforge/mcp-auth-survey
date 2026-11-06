#!/usr/bin/env python3
"""
mcp_survey.py — MCP authentication posture survey, v0.2
Phases: phase0 (dry-run, 20 servers, stop), phase2 (full, resumable, background-safe)

Usage:
  python mcp_survey.py phase0 --contact EMAIL
  python mcp_survey.py phase2 --contact EMAIL [--delay 1.0]

Hard rules encoded here; do not relax them.
"""
import argparse, csv, datetime, ipaddress, json, os, random
import socket, sys, time
from collections import Counter, deque
from urllib import robotparser
from urllib.parse import urlparse, urljoin

import httpx

# ── paths ──────────────────────────────────────────────────────────────────
DIR            = "mcp_probe"
SNAPSHOT_FILE  = f"{DIR}/registry_snapshot.json"
RESULTS_FILE   = f"{DIR}/results_full.csv"
LOG_FILE       = f"{DIR}/run_log.txt"
OPT_OUT_FILE   = "opt_out.txt"

# ── tuning ─────────────────────────────────────────────────────────────────
VERSION        = "0.2"
MAX_BODY       = 4096
TIMEOUT        = 10
PAGE_DELAY     = 0.5
PROGRESS_EVERY = 200
PAUSE_THRESH   = 0.05   # pause if >5 % of last 100 return 429 (rate-limit only; 403 is valid auth class)

INIT_MSG = {
    "jsonrpc": "2.0", "id": 1, "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "mcp-auth-posture-survey", "version": VERSION},
    },
}

RESULT_FIELDS = [
    "registry_name", "title", "operator_domain", "remote_type", "url",
    "class", "status", "www_authenticate", "auth_server", "notes", "probed_at",
]

# Tag a URL as platform-hosted when the hostname ends with one of these suffixes.
# JUDGMENT CALL: these are well-known multi-tenant MCP hosting platforms or
# generic PaaS providers; their auth posture reflects the platform's default,
# not the operator's choice.  Report them separately in Phase 3.
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


# ── utilities ──────────────────────────────────────────────────────────────

def ts():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def log(msg, fp=None):
    line = f"[{datetime.datetime.now(datetime.timezone.utc).strftime('%H:%M:%SZ')}] {msg}"
    print(line, file=sys.stderr)
    if fp:
        fp.write(line + "\n")
        fp.flush()

def is_safe(url: str) -> bool:
    """HTTPS only; reject private/loopback/link-local IPs and placeholder templates."""
    p = urlparse(url)
    if p.scheme != "https":
        return False
    if "{" in url or "}" in url:
        return False
    try:
        infos = socket.getaddrinfo(p.hostname, p.port or 443)
    except Exception:
        return True          # let the HTTP client surface the error as unreachable
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            return False
    return True

def operator_domain(url: str) -> str:
    """
    Registrable domain (eTLD+1).
    JUDGMENT CALL: uses tldextract when available; otherwise takes the last two
    dot-separated labels, which is wrong for ccSLDs like .co.uk — flag those.
    """
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

def load_opt_out() -> set:
    if not os.path.exists(OPT_OUT_FILE):
        return set()
    with open(OPT_OUT_FILE) as f:
        return {ln.strip().lower() for ln in f if ln.strip()}

def read_limited(resp) -> str:
    buf = b""
    for chunk in resp.iter_bytes():
        buf += chunk
        if len(buf) >= MAX_BODY:
            break
    return buf[:MAX_BODY].decode("utf-8", "replace")

def get_json_safe(client, url):
    if not is_safe(url):
        return None
    try:
        r = client.get(url)
        return r.json() if r.status_code == 200 else None
    except Exception:
        return None


# ── probe ──────────────────────────────────────────────────────────────────

def probe_one(client, ep: dict, ua: str, opt_out: set) -> dict:
    """
    Send at most 3 requests as specified in the hard rules.
    Returns a dict matching RESULT_FIELDS.

    Classes:
      open               valid JSON-RPC initialize result, no credentials
      oauth              401 + resolvable RFC 9728 metadata with authorization_servers
      bearer_or_api_key  401, no OAuth discovery, but bearer/key hints in response
      auth_required_other 401/403, no usable hints
      not_mcp            2xx but not a JSON-RPC MCP response
      origin_error       5xx (including Cloudflare 52x)
      unreachable        network error or timeout
      legacy_sse         SSE-type endpoint, status recorded, connection closed
      skipped_robots     disallowed by robots.txt
      skipped_unsafe     private IP, non-HTTPS, opt-out, or placeholder URL

    NOTE: "open" means the initialize handshake succeeded.
          It does NOT mean tool calls are callable without credentials.
    """
    url = ep["url"]
    rtype = ep.get("remote_type", "streamable-http")
    p = urlparse(url)
    host = (p.hostname or "").lower()
    origin = f"{p.scheme}://{p.netloc}"

    out = {
        "registry_name":   ep.get("registry_name", ""),
        "title":           ep.get("title", ""),
        "operator_domain": operator_domain(url),
        "remote_type":     rtype,
        "url":             url,
        "class":           "",
        "status":          "",
        "www_authenticate": "",
        "auth_server":     "",
        "notes":           "",
        "probed_at":       ts(),
    }

    # ── safety gates ──
    if not is_safe(url):
        out["class"] = "skipped_unsafe"
        return out
    if host in opt_out:
        out["class"] = "skipped_unsafe"
        out["notes"] = "opt_out"
        return out

    # ── robots.txt ──
    try:
        rp = robotparser.RobotFileParser()
        r = client.get(origin + "/robots.txt")
        rp.parse(r.text.splitlines() if r.status_code == 200 else [])
        if not rp.can_fetch(ua, url):
            out["class"] = "skipped_robots"
            return out
    except Exception:
        pass   # unreachable robots.txt → proceed

    # ── SSE legacy endpoints: one GET, record status, close ──
    if rtype == "sse":
        try:
            with client.stream("GET", url,
                               headers={"Accept": "text/event-stream"}) as r:
                out["status"] = r.status_code
                out["www_authenticate"] = r.headers.get("www-authenticate", "")[:300]
            out["class"] = "legacy_sse"
        except Exception as e:
            out["class"] = "unreachable"
            out["notes"] = type(e).__name__
        return out

    # ── streamable-http: one POST initialize ──
    try:
        with client.stream("POST", url, json=INIT_MSG,
                           headers={"Accept": "application/json, text/event-stream"}) as r:
            out["status"] = r.status_code
            wa = r.headers.get("www-authenticate", "")
            out["www_authenticate"] = wa[:300]
            body = read_limited(r)
    except Exception as e:
        out["class"] = "unreachable"
        out["notes"] = f"{type(e).__name__}: {str(e)[:80]}"
        return out

    code = out["status"]

    # 5xx → origin_error (includes Cloudflare 52x)
    if isinstance(code, int) and 500 <= code < 600:
        out["class"] = "origin_error"
        out["notes"] = f"http_{code}"
        return out

    if code in (200, 202):
        if '"jsonrpc"' in body and ('"result"' in body or '"error"' in body):
            out["class"] = "open"
        else:
            out["class"] = "not_mcp"
        return out

    if code == 401:
        meta_urls = []
        if "resource_metadata=" in wa:
            ptr = wa.split("resource_metadata=")[1].split(",")[0].strip().strip('"')
            meta_urls.append(ptr)
        path = p.path.rstrip("/")
        meta_urls.append(f"{origin}/.well-known/oauth-protected-resource{path}")
        meta_urls.append(f"{origin}/.well-known/oauth-protected-resource")
        for m in meta_urls:
            data = get_json_safe(client, urljoin(origin, m))
            if isinstance(data, dict) and data.get("authorization_servers"):
                out["class"] = "oauth"
                out["auth_server"] = urlparse(data["authorization_servers"][0]).netloc
                return out
        low = (wa + body).lower()
        if any(k in low for k in ("bearer", "api key", "api-key", "x-api-key", "token")):
            out["class"] = "bearer_or_api_key"
        else:
            out["class"] = "auth_required_other"
        return out

    if code == 403:
        out["class"] = "auth_required_other"
        out["notes"] = "http_403"
    elif code == 429:
        out["class"] = "unreachable"
        out["notes"] = "http_429"
    else:
        out["class"] = "not_mcp"
        out["notes"] = f"http_{code}"
    return out


# ── registry fetch ─────────────────────────────────────────────────────────

def fetch_registry(ua: str) -> list:
    """Paginate the registry, save snapshot, return raw server list."""
    client = httpx.Client(timeout=15, follow_redirects=True, headers={"User-Agent": ua})
    all_items = []
    cursor = None
    page = 0
    while True:
        url = ("https://registry.modelcontextprotocol.io/v0.1/servers"
               "?limit=100&version=latest")
        if cursor:
            url += f"&cursor={cursor}"
        try:
            r = client.get(url)
            data = r.json()
        except Exception as e:
            print(f"Registry page {page} error: {e}", file=sys.stderr)
            break
        items = data.get("servers", [])
        all_items.extend(items)
        cursor = data.get("metadata", {}).get("nextCursor")
        page += 1
        if not cursor or not items:
            break
        time.sleep(PAGE_DELAY)
    client.close()

    os.makedirs(DIR, exist_ok=True)
    snapshot = {
        "fetched_at": ts(),
        "raw_count": len(all_items),
        "servers": all_items,
    }
    with open(SNAPSHOT_FILE, "w") as f:
        json.dump(snapshot, f, indent=2)
    print(f"Snapshot saved: {len(all_items)} raw entries → {SNAPSHOT_FILE}",
          file=sys.stderr)
    return all_items


def build_endpoint_list(raw_items: list) -> tuple:
    """
    Filter and deduplicate raw registry entries.
    Returns (endpoints list, stats Counter).
    Drop reasons recorded in stats.
    """
    stats = Counter()
    seen = {}
    endpoints = []

    for item in raw_items:
        srv  = item.get("server", {})
        meta = (item.get("_meta", {})
                    .get("io.modelcontextprotocol.registry/official", {}))
        stats["raw"] += 1

        status = meta.get("status", "active")
        if status not in ("active", "", None):
            stats["drop_inactive"] += 1
            continue

        remotes = srv.get("remotes", [])
        if not remotes:
            stats["drop_no_remotes"] += 1
            continue

        name    = srv.get("name", "")
        title   = srv.get("title") or name
        repo    = (srv.get("repository") or {}).get("url", "")
        website = srv.get("websiteUrl", "")

        added_this = 0
        for rem in remotes:
            rtype = rem.get("type", "streamable-http")
            ep    = rem.get("url", "").rstrip("/")

            if not ep:
                stats["drop_empty_url"] += 1
                continue
            if not ep.startswith("https"):
                stats["drop_not_https"] += 1
                continue
            if "{" in ep or "}" in ep:
                stats["drop_placeholder"] += 1
                continue
            if ep in seen:
                stats["drop_duplicate"] += 1
                continue

            seen[ep] = True
            added_this += 1
            stats["kept"] += 1
            endpoints.append({
                "registry_name": name,
                "title":         title,
                "repo":          repo,
                "website":       website,
                "remote_type":   rtype,
                "url":           ep,
            })

        if added_this == 0:
            stats["drop_all_remotes_filtered"] += 1

    return endpoints, stats


# ── phase 0 ────────────────────────────────────────────────────────────────

def phase0(args):
    ua = (f"mcp-auth-posture-survey/{VERSION} "
          f"(read-only research; contact: {args.contact})")
    opt_out = load_opt_out()

    print("\n══════ PHASE 0 — DRY RUN ══════\n", file=sys.stderr)

    raw     = fetch_registry(ua)
    eps, stats = build_endpoint_list(raw)

    # ── list stats ──
    print("\n── Registry / filter stats ──────────────────────────────────")
    print(f"  raw entries from registry   : {stats['raw']}")
    print(f"  drop: inactive status       : {stats.get('drop_inactive', 0)}")
    print(f"  drop: no remotes field      : {stats.get('drop_no_remotes', 0)}")
    print(f"  drop: all remotes filtered  : {stats.get('drop_all_remotes_filtered', 0)}")
    print(f"  drop: not https             : {stats.get('drop_not_https', 0)}")
    print(f"  drop: placeholder URL {{..}} : {stats.get('drop_placeholder', 0)}")
    print(f"  drop: duplicate URL         : {stats.get('drop_duplicate', 0)}")
    print(f"  drop: empty URL             : {stats.get('drop_empty_url', 0)}")
    print(f"  ──────────────────────────────")
    print(f"  kept (unique endpoints)     : {stats['kept']}")

    # ── TLD distribution ──
    tld_counts = Counter()
    for ep in eps:
        host = urlparse(ep["url"]).hostname or ""
        tld  = host.rsplit(".", 1)[-1] if "." in host else "?"
        tld_counts[tld] += 1
    print(f"\n── TLD distribution (top 20 of {len(tld_counts)} TLDs) ──────────")
    for tld, n in tld_counts.most_common(20):
        bar = "█" * (n * 30 // max(tld_counts.values()))
        print(f"  .{tld:<12} {n:>5}  {bar}")

    # ── transport type ──
    type_counts = Counter(ep["remote_type"] for ep in eps)
    print(f"\n── Transport types ───────────────────────────────────────────")
    for t, n in type_counts.most_common():
        print(f"  {t:<25} {n}")

    # ── platform distribution ──
    plat_counts = Counter()
    for ep in eps:
        plat_counts[platform_of(ep["url"]) or "self-hosted"] += 1
    print(f"\n── Platform hosting (top 10) ─────────────────────────────────")
    for p, n in plat_counts.most_common(10):
        print(f"  {p:<25} {n}")

    # ── top 15 operators ──
    op_counts = Counter(operator_domain(ep["url"]) for ep in eps)
    print(f"\n── Top 15 operators by endpoint count ────────────────────────")
    for op, n in op_counts.most_common(15):
        print(f"  {op:<40} {n}")

    # ── sample 20, seed 42 ──
    rng    = random.Random(42)
    sample = eps[:]
    rng.shuffle(sample)
    sample20 = sample[:20]

    print(f"\n══════ Probing 20 / {len(eps)} endpoints (seed 42) ══════\n")

    client = httpx.Client(
        timeout=TIMEOUT,
        follow_redirects=False,
        headers={"User-Agent": ua},
    )
    results = []
    for i, ep in enumerate(sample20, 1):
        res = probe_one(client, ep, ua, opt_out)
        results.append(res)
        auth = f"  auth_server={res['auth_server']}" if res["auth_server"] else ""
        print(f"  [{i:>2}/20] {res['class']:<22} {res['url']}{auth}")
        if i < 20:
            time.sleep(args.delay)
    client.close()

    # ── dry-run breakdown ──
    breakdown = Counter(r["class"] for r in results)
    print("\n── Dry-run class breakdown ───────────────────────────────────")
    for cls, n in sorted(breakdown.items(), key=lambda x: -x[1]):
        print(f"  {cls:<25} {n:>3}  {'█' * n}")

    print("\n── NOTE ──────────────────────────────────────────────────────")
    print("  'open' means the MCP initialize handshake succeeded without")
    print("  credentials.  It does NOT mean tool calls are callable.")

    print("\n══════ PHASE 0 COMPLETE ══════")
    print(f"  {len(eps)} endpoints ready.  Reply 'go' to start the full probe.")

    return eps, results, stats


# ── phase 2 ────────────────────────────────────────────────────────────────

def phase2(args, endpoints=None):
    ua = (f"mcp-auth-posture-survey/{VERSION} "
          f"(read-only research; contact: {args.contact})")
    opt_out = load_opt_out()

    if endpoints is None:
        if not os.path.exists(SNAPSHOT_FILE):
            print("ERROR: no snapshot. Run phase0 first.", file=sys.stderr)
            sys.exit(1)
        with open(SNAPSHOT_FILE) as f:
            snap = json.load(f)
        endpoints, _ = build_endpoint_list(snap["servers"])

    # Resumability: skip already-probed URLs
    already_done = set()
    if os.path.exists(RESULTS_FILE):
        with open(RESULTS_FILE) as f:
            for row in csv.DictReader(f):
                if row.get("class"):   # skip blank rows
                    already_done.add(row["url"])

    todo = [ep for ep in endpoints if ep["url"] not in already_done]
    log(f"Phase 2 start | total={len(endpoints)} already_done={len(already_done)} todo={len(todo)}")

    write_header = (not os.path.exists(RESULTS_FILE)) or (len(already_done) == 0)
    out_f  = open(RESULTS_FILE, "a", newline="")
    writer = csv.DictWriter(out_f, fieldnames=RESULT_FIELDS, extrasaction="ignore")
    if write_header:
        writer.writeheader()

    log_f = open(LOG_FILE, "a")
    log(f"Phase 2 start | total={len(endpoints)} already_done={len(already_done)} todo={len(todo)}", log_f)

    client = httpx.Client(
        timeout=TIMEOUT,
        follow_redirects=False,
        headers={"User-Agent": ua},
    )

    skipped_hosts: set  = set()
    consec_429          = Counter()   # host → consecutive 429 count
    recent_statuses     = deque(maxlen=100)   # track 403/429 for pause threshold
    done = 0

    for i, ep in enumerate(todo, 1):
        host = (urlparse(ep["url"]).hostname or "").lower()

        if host in skipped_hosts:
            row = {f: "" for f in RESULT_FIELDS}
            row.update(
                registry_name=ep["registry_name"],
                title=ep["title"],
                operator_domain=operator_domain(ep["url"]),
                remote_type=ep["remote_type"],
                url=ep["url"],
                **{"class": "unreachable"},
                notes="host_skipped_429",
                probed_at=ts(),
            )
            writer.writerow(row)
            out_f.flush()
            continue

        res  = probe_one(client, ep, ua, opt_out)
        code = res.get("status", "")
        notes = res.get("notes", "")

        # 429 handling
        if code == 429 or notes == "http_429":
            consec_429[host] += 1
            if consec_429[host] >= 2:
                skipped_hosts.add(host)
                log(f"SKIP host {host}: 2 consecutive 429s", log_f)
            # Honor Retry-After if present (not in probe_one output, so just extra delay)
            time.sleep(max(args.delay, 5.0))
        else:
            consec_429[host] = 0

        recent_statuses.append(code)
        writer.writerow(res)
        out_f.flush()
        done += 1

        # 5% threshold check
        if len(recent_statuses) == 100:
            n_blocked = sum(1 for s in recent_statuses if s == 429)
            if n_blocked / 100 > PAUSE_THRESH:
                msg = (f"PAUSE THRESHOLD: {n_blocked}/100 recent responses are "
                       f"429. Stopping. Check run_log.txt.")
                log(msg, log_f)
                print(f"\n*** {msg} ***\n")
                out_f.close(); log_f.close(); client.close()
                sys.exit(2)

        # Progress report
        if done % PROGRESS_EVERY == 0:
            total_done = len(already_done) + done
            bd = Counter(
                row["class"]
                for row in csv.DictReader(open(RESULTS_FILE))
            )
            log(
                f"Progress {total_done}/{len(endpoints)} | "
                f"open={bd['open']} oauth={bd['oauth']} "
                f"bearer={bd['bearer_or_api_key']} unreachable={bd['unreachable']} "
                f"origin_err={bd['origin_error']} skipped_robots={bd['skipped_robots']}",
                log_f,
            )

        time.sleep(args.delay)

    client.close()
    out_f.close()
    log(f"Phase 2 complete | probed={done} total_done={len(already_done)+done}", log_f)
    log_f.close()
    print(f"\nDone. {done} probed this session. Results → {RESULTS_FILE}")


# ── main ───────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description="MCP authentication posture survey"
    )
    ap.add_argument("phase", choices=["phase0", "phase2"])
    ap.add_argument("--contact", required=True,
                    help="Email shown in User-Agent")
    ap.add_argument("--delay", type=float, default=1.0,
                    help="Seconds between servers (min 1.0)")
    args = ap.parse_args()
    args.delay = max(args.delay, MIN_DELAY := 1.0)

    os.makedirs(DIR, exist_ok=True)

    if args.phase == "phase0":
        phase0(args)
    else:
        phase2(args)


if __name__ == "__main__":
    main()
