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
    {"id": "monitor_bec9824cc5224034b8321740757c10a9", "label": "DOJ Fraud",          "severity": "high", "walletIdx": 0,  "sources": ["CoinDesk"]},
    {"id": "monitor_e171d371987048559b68a20af2fd3975", "label": "SEC Charges",         "severity": "high", "walletIdx": 1,  "sources": ["CoinDesk"]},
    {"id": "monitor_9d18389273d04076b5c48cf05f8c030a", "label": "Whale Liquidation",   "severity": "high", "walletIdx": 2,  "sources": ["Twitter/X"]},
    {"id": "monitor_a8f3c8707f4d4083b96c8cc0a6e5dd99", "label": "Memecoin Rug Pull",   "severity": "high", "walletIdx": 3,  "sources": ["Twitter/X"]},
    {"id": "monitor_593ed09b092c4606a2866af39ce5cf05", "label": "DeFi Enforcement",    "severity": "high", "walletIdx": 4,  "sources": ["CFTC.gov"]},
    {"id": "monitor_c1a5d571fbf740e385b90fdb7aab75d0", "label": "Chain Analytics",     "severity": "med",  "walletIdx": 5,  "sources": ["Chainalysis"]},
    {"id": "monitor_d016cee4608647a0bd48cab9818c963d", "label": "Exchange Suspension",  "severity": "med",  "walletIdx": 6,  "sources": ["CoinDesk"]},
]

CONFIDENCE_RANK = {"high": 3, "medium": 2, "low": 1, None: 0}
CUTOFF_HOURS = 48  # only surface events from the last 48 hours


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

    # Recency: prefer events within cutoff
    event_date_str = raw_event.get("event_date", "")
    try:
        event_dt = datetime.fromisoformat(event_date_str).replace(tzinfo=timezone.utc)
        age_hours = (now - event_dt).total_seconds() / 3600
    except (ValueError, TypeError):
        age_hours = 999

    if age_hours > CUTOFF_HOURS:
        return -1  # discard

    # Confidence
    basis = output.get("basis", [{}])
    confidence_str = basis[0].get("confidence") if basis else None
    confidence_score = CONFIDENCE_RANK.get(confidence_str, 0)

    # Prefer high-severity monitors
    severity_score = 1 if monitor_meta.get("severity") == "high" else 0

    recency_score = max(0, 1 - age_hours / CUTOFF_HOURS)  # 1.0 → 0.0 over 48h

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


def is_homepage(url: str) -> bool:
    from urllib.parse import urlparse
    p = urlparse(url)
    return p.path.strip("/") == ""


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

    if not scored:
        print("No recent high-confidence events found — keeping existing REAL_EVENTS.", file=sys.stderr)
        sys.exit(0)

    # Sort best first, take up to 8
    scored.sort(key=lambda x: x["score"], reverse=True)
    best = scored[:8]

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

    updated = re.sub(pattern, new_block, html, count=1)
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(updated)

    print("  fomo-brief.html updated.", file=sys.stderr)


if __name__ == "__main__":
    main()
