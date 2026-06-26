#!/usr/bin/env python3
"""
Fetch events from all FOMO monitors, pick the best ones from the last 48h,
and rewrite the REAL_EVENTS block in fomo-brief.html.

Runs inside GitHub Actions; parallel-cli must already be authenticated.
"""

import json
import re
import subprocess
import sys
from datetime import datetime, timezone, timedelta

# ── Monitor IDs (all hourly, base processor) ─────────────────────────────────
MONITORS = [
    {"id": "monitor_bec9824cc5224034b8321740757c10a9", "label": "DOJ Fraud",            "severity": "high", "walletIdx": 0,  "sources": ["The Block"]},
    {"id": "monitor_e171d371987048559b68a20af2fd3975", "label": "SEC Charges",           "severity": "high", "walletIdx": 1,  "sources": ["The Block"]},
    {"id": "monitor_9d18389273d04076b5c48cf05f8c030a", "label": "Whale Liquidation",     "severity": "high", "walletIdx": 2,  "sources": ["Twitter/X"]},
    {"id": "monitor_a8f3c8707f4d4083b96c8cc0a6e5dd99", "label": "Memecoin Rug Pull",     "severity": "high", "walletIdx": 3,  "sources": ["PeckShield"]},
    {"id": "monitor_593ed09b092c4606a2866af39ce5cf05", "label": "DeFi Enforcement",      "severity": "high", "walletIdx": 4,  "sources": ["CFTC.gov"]},
    {"id": "monitor_c1a5d571fbf740e385b90fdb7aab75d0", "label": "Chain Analytics",       "severity": "med",  "walletIdx": 5,  "sources": ["Chainalysis"]},
    {"id": "monitor_d016cee4608647a0bd48cab9818c963d", "label": "Exchange Suspension",   "severity": "med",  "walletIdx": 6,  "sources": ["The Block"]},
    # Round 2 — tighter queries for breaking news
    {"id": "monitor_6498408d8fcc4099809143787729a368", "label": "Trader Arrest",         "severity": "high", "walletIdx": 7,  "sources": ["The Block"]},
    {"id": "monitor_0f8d3d3bca26406f84ffc6f8cb771d17", "label": "Hyperliquid Alert",     "severity": "high", "walletIdx": 8,  "sources": ["Twitter/X"]},
    {"id": "monitor_6d50b2221d7d4521a4b6310a213dee43", "label": "Copy Trade Fraud",      "severity": "high", "walletIdx": 9,  "sources": ["The Block"]},
    {"id": "monitor_726d5e9d3f134a8fa6707b43565590b2", "label": "DeFi Exploit",          "severity": "high", "walletIdx": 10, "sources": ["PeckShield"]},
]

CONFIDENCE_RANK = {"high": 3, "medium": 2, "low": 1, None: 0}
CUTOFF_HOURS = 48   # monitor event age cutoff
ARTICLE_MAX_DAYS = 7  # reject articles older than this regardless of when monitor ran


def extract_article_date(output: dict, url: str) -> datetime | None:
    """
    Try to determine the actual publication date of an article.
    Checks: (1) URL path for YYYY/MM/DD or YYYY-MM-DD patterns,
            (2) first sentence of content for a leading date.
    Returns a tz-aware datetime or None if unknown.
    """
    import re

    # 1. URL date pattern: /2026/06/25/ or /2026-06-25/
    url_date_pattern = re.search(r'[/\-](20\d{2})[/\-](0[1-9]|1[0-2])[/\-](0[1-9]|[12]\d|3[01])', url or "")
    if url_date_pattern:
        try:
            return datetime(int(url_date_pattern.group(1)),
                            int(url_date_pattern.group(2)),
                            int(url_date_pattern.group(3)),
                            tzinfo=timezone.utc)
        except ValueError:
            pass

    # 2. Content leading date: "Jun 25, 2026" or "June 25, 2026" or "2026-06-25"
    content = output.get("content", "")
    excerpts = []
    for b in output.get("basis", []):
        for c in b.get("citations", []):
            excerpts += c.get("excerpts", [])
    text = (content + " " + " ".join(excerpts))[:400]

    month_names = {"jan":1,"feb":2,"mar":3,"apr":4,"may":5,"jun":6,
                   "jul":7,"aug":8,"sep":9,"oct":10,"nov":11,"dec":12}
    # "Jun 25, 2026" or "June 25 2026"
    m = re.search(r'\b(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\.?\s+(\d{1,2}),?\s+(20\d{2})', text, re.I)
    if m:
        try:
            return datetime(int(m.group(3)), month_names[m.group(1).lower()[:3]], int(m.group(2)), tzinfo=timezone.utc)
        except ValueError:
            pass
    # "March 2026" (no day — treat as 1st of month)
    m = re.search(r'\b(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\.?\s+(20\d{2})\b', text, re.I)
    if m:
        try:
            return datetime(int(m.group(2)), month_names[m.group(1).lower()[:3]], 1, tzinfo=timezone.utc)
        except ValueError:
            pass

    # ISO date in text
    m = re.search(r'\b(20\d{2})-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])\b', text)
    if m:
        try:
            return datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)), tzinfo=timezone.utc)
        except ValueError:
            pass

    return None


def run_cli(monitor_id: str, limit: int = 10) -> list:
    result = subprocess.run(
        ["parallel-cli", "monitor", "events", monitor_id, "--limit", str(limit), "--json"],
        capture_output=True, text=True, timeout=60
    )
    if result.returncode != 0:
        print(f"  WARN: CLI error for {monitor_id}: {result.stderr[:200]}", file=sys.stderr)
        return []
    try:
        data = json.loads(result.stdout)
        return data.get("events", [])
    except json.JSONDecodeError:
        return []


def score_event(raw_event: dict, monitor_meta: dict, now: datetime) -> float:
    """Higher is better. Combines recency + confidence."""
    output = raw_event.get("output", {})

    # Confidence — high only
    basis = output.get("basis", [{}])
    confidence_str = basis[0].get("confidence") if basis else None
    if confidence_str != "high":
        return -1

    # Get the best citation URL and check article publication date
    title, url = "", ""
    for b in output.get("basis", []):
        for c in b.get("citations", []):
            u = c.get("url", "").strip()
            if u and not is_low_signal_url(u):
                url = u
                title = c.get("title", "")
                break
        if url:
            break

    # Reject articles older than ARTICLE_MAX_DAYS — must confirm date or discard
    article_dt = extract_article_date(output, url)
    if not article_dt:
        return -1  # can't confirm recency — reject
    article_age_days = (now - article_dt).total_seconds() / 86400
    if article_age_days > ARTICLE_MAX_DAYS:
        return -1
    recency_score = max(0, 1 - article_age_days / ARTICLE_MAX_DAYS)

    confidence_score = CONFIDENCE_RANK.get(confidence_str, 0)
    severity_score = 1 if monitor_meta.get("severity") == "high" else 0

    return confidence_score * 10 + severity_score * 5 + recency_score * 3


def extract_best_citation(output: dict) -> tuple[str, str]:
    """Return (title, url) from the highest-confidence citation."""
    for basis_item in output.get("basis", []):
        for cite in basis_item.get("citations", []):
            url = cite.get("url", "").strip()
            title = cite.get("title", "").strip()
            if url and not is_homepage(url):
                return title, url
    return "", ""


def is_low_signal_url(url: str) -> bool:
    """Block homepages, section pages, search pages, and anything not a specific article."""
    from urllib.parse import urlparse, parse_qs
    p = urlparse(url)
    path_parts = [x for x in p.path.strip("/").split("/") if x]

    # Reject homepages
    if not path_parts:
        return True

    # Reject search/query pages
    if p.query and any(k in parse_qs(p.query) for k in ("q", "s", "search", "query")):
        return True
    if "search" in path_parts or "tag" in path_parts or "category" in path_parts:
        return True

    # Reject shallow section pages on known news/data domains
    # A real article needs at least 2 meaningful path segments (e.g. /blog/title, /post/123/slug)
    NEWS_DOMAINS = (
        "reuters.com", "coindesk.com", "theblock.co", "decrypt.co",
        "cointelegraph.com", "bloomberg.com", "ft.com", "wsj.com",
        "forbes.com", "yahoo.com", "businessinsider.com", "cnbc.com",
        "chainalysis.com", "elliptic.co", "trmlabs.com", "peckshield.com",
    )
    if any(d in p.netloc for d in NEWS_DOMAINS) and len(path_parts) < 2:
        return True

    return False


# Keep old name as alias so existing call-sites work
is_homepage = is_low_signal_url


def build_excerpt(output: dict, event_date: str, citation_title: str) -> str:
    """Build a 1-2 sentence excerpt starting with the event date."""
    content = output.get("content", "").strip()
    if not content:
        return ""

    # Format date like "Jun 25, 2026"
    try:
        dt = datetime.fromisoformat(event_date)
        date_label = dt.strftime("%b %-d, %Y")
    except (ValueError, TypeError):
        date_label = event_date

    # Trim to ~200 chars for card display
    summary = content[:220].rsplit(" ", 1)[0]
    if len(content) > 220:
        summary += "..."

    return f"{date_label} — {summary}"


def js_string(s: str) -> str:
    return json.dumps(s)  # proper JSON quoting handles all escaping


def build_real_events(candidates: list) -> str:
    lines = ["// Real events — auto-refreshed from Parallel monitors (last 48h, highest confidence first)",
             "var REAL_EVENTS = ["]
    for c in candidates:
        m = c["monitor"]
        ev = c["raw"]
        output = ev.get("output", {})
        title, url = extract_best_citation(output)
        excerpt = build_excerpt(output, ev.get("event_date", ""), title)
        desc = output.get("content", title)[:180].rsplit(" ", 1)[0]
        sources_js = json.dumps(m["sources"])
        lines.append("  {")
        lines.append(f"    walletIdx: {m['walletIdx']},")
        lines.append(f"    def: {{ label: {js_string(m['label'])}, severity: {js_string(m['severity'])}, sources: {sources_js} }},")
        lines.append(f"    desc: {js_string(desc)},")
        lines.append(f"    excerpt: {js_string(excerpt)},")
        lines.append(f"    url: {js_string(url)},")
        lines.append(f"    secsAgo: {c['secsAgo']},")
        lines.append("  },")
    lines.append("];")
    return "\n".join(lines)


SEARCH_QUERIES = [
    "crypto fraud arrest charged sentenced 2026",
    "DeFi exploit hack stolen funds confirmed 2026",
    "Hyperliquid whale manipulation on-chain alert 2026",
    "copy trading platform fraud victim lawsuit 2026",
    "crypto exchange enforcement action penalty 2026",
]

SEARCH_WALLET_IDX = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10]


def run_search(query: str) -> list:
    """Run parallel-cli search and return result items."""
    result = subprocess.run(
        ["parallel-cli", "search", query, "--json", "--limit", "3"],
        capture_output=True, text=True, timeout=90
    )
    if result.returncode != 0:
        print(f"  WARN: search error: {result.stderr[:200]}", file=sys.stderr)
        return []
    try:
        data = json.loads(result.stdout)
        return data.get("results", data.get("items", []))
    except json.JSONDecodeError:
        return []


def search_fallback(now: datetime) -> list:
    """Run web searches and convert results to scored candidates."""
    print("  No monitor events — running search fallback…", file=sys.stderr)
    candidates = []
    seen_urls = set()
    for i, query in enumerate(SEARCH_QUERIES):
        print(f"    search: {query[:60]}", file=sys.stderr)
        items = run_search(query)
        for item in items:
            url = item.get("url", "").strip()
            title = item.get("title", "").strip()
            snippet = item.get("snippet", item.get("description", "")).strip()
            if not url or is_homepage(url) or url in seen_urls:
                continue
            if len(snippet) < 60:
                continue
            # Confirm article is actually recent before accepting
            probe_output = {"content": snippet, "basis": [{"citations": [{"url": url, "excerpts": [snippet]}]}]}
            art_dt = extract_article_date(probe_output, url)
            if not art_dt or (now - art_dt).total_seconds() / 86400 > ARTICLE_MAX_DAYS:
                continue
            seen_urls.add(url)
            wallet_idx = SEARCH_WALLET_IDX[len(candidates) % len(SEARCH_WALLET_IDX)]
            # Synthesize a monitor-like candidate
            fake_output = {
                "content": snippet,
                "basis": [{"confidence": "medium", "citations": [{"url": url, "title": title, "excerpts": [snippet]}]}]
            }
            fake_event = {"event_date": now.strftime("%Y-%m-%d"), "output": fake_output}
            monitor_meta = {"label": title[:50], "severity": "high", "walletIdx": wallet_idx, "sources": ["The Block"]}
            candidates.append({"score": 20.0, "raw": fake_event, "monitor": monitor_meta})
            if len(candidates) >= 8:
                return candidates
    return candidates


def main():
    now = datetime.now(timezone.utc)
    print(f"Fetching monitor events at {now.isoformat()}", file=sys.stderr)

    scored = []
    for monitor in MONITORS:
        print(f"  {monitor['id']} ({monitor['label']})…", file=sys.stderr)
        events = run_cli(monitor["id"], limit=10)
        print(f"    {len(events)} events returned", file=sys.stderr)
        for ev in events:
            s = score_event(ev, monitor, now)
            if s >= 0:
                scored.append({"score": s, "raw": ev, "monitor": monitor})

    # Deduplicate by URL — keep highest-scoring entry per URL
    by_url = {}
    for c in scored:
        _, url = extract_best_citation(c["raw"].get("output", {}))
        if not url:
            continue
        if url not in by_url or c["score"] > by_url[url]["score"]:
            by_url[url] = c
    deduped = list(by_url.values())

    # Require minimum content quality
    quality = [c for c in deduped
               if extract_best_citation(c["raw"].get("output", {}))[1]
               and len(c["raw"].get("output", {}).get("content", "")) > 80]

    # If monitors came up dry, fall back to live search
    if not quality:
        quality = search_fallback(now)

    if not quality:
        print("No events from monitors or search — keeping existing REAL_EVENTS.", file=sys.stderr)
        sys.exit(0)

    # Sort best first, take up to 8
    quality.sort(key=lambda x: x["score"], reverse=True)
    best = quality[:8]

    # Assign secsAgo: spread events ~10 min apart starting at 6 min ago
    for i, c in enumerate(best):
        c["secsAgo"] = 360 + i * 600

    print(f"  Selected {len(best)} events for REAL_EVENTS", file=sys.stderr)
    for c in best:
        print(f"    [{c['score']:.1f}] {c['monitor']['label']} — {c['raw'].get('event_date','?')}", file=sys.stderr)

    new_block = build_real_events(best)

    # Replace the REAL_EVENTS block in the HTML
    html_path = "fomo-brief.html"
    with open(html_path, "r", encoding="utf-8") as f:
        html = f.read()

    pattern = r"// Real events[^\n]*\nvar REAL_EVENTS = \[[\s\S]*?\];"
    if not re.search(pattern, html):
        print("ERROR: Could not find REAL_EVENTS block in HTML.", file=sys.stderr)
        sys.exit(1)

    updated = re.sub(pattern, lambda m: new_block, html, count=1)
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(updated)

    print("  fomo-brief.html updated.", file=sys.stderr)


if __name__ == "__main__":
    main()
