"""Admin analytics dashboard.

All counting happens in MongoDB. The only per-row work in Python is parsing user
agents, and that is done once per *distinct* agent string, not once per page view.
"""
from datetime import datetime, timedelta
from functools import lru_cache
from urllib.parse import urlencode

from flask import g, render_template, request
from pymongo import DESCENDING
from user_agents import parse

from .app import app, utc_now
from .db import ANALYTICS_RETENTION_DAYS
from .security import login_required

PARAM_KEYS = ("range", "date", "bots", "path", "referrer", "country", "browser", "os", "device")
UA_KEYS = ("browser", "os", "device")
RANGE_DAYS = {"7d": 7, "30d": 30, "90d": 90}
RANGE_CHOICES = ["24h", "7d", "30d", "90d", "all"]
MAX_AGENTS = 3000


@lru_cache(maxsize=4096)
def parse_ua(agent: str):
    ua = parse(agent or "")
    device = "Mobile" if ua.is_mobile else "Tablet" if ua.is_tablet else "Desktop"
    return ua.browser.family or "Other", ua.os.family or "Other", device


def _floor(dt: datetime, unit: str) -> datetime:
    if unit == "hour":
        return dt.replace(minute=0, second=0, microsecond=0)
    return dt.replace(hour=0, minute=0, second=0, microsecond=0)


def _parse_day(value: str):
    for fmt in ("%Y-%m-%d", "%b %d %Y"):
        for candidate in (value, f"{value} {utc_now().year}"):
            try:
                return datetime.strptime(candidate, fmt)
            except ValueError:
                continue
    return None


def resolve_window(now: datetime, col):
    """Work out start/end, bucket size and a label from the query string."""
    day = _parse_day(request.args.get("date", "")) if request.args.get("date") else None
    if day:
        return {"start": day, "end": day + timedelta(days=1), "unit": "hour",
                "label": day.strftime("%d %b %Y"), "range": None, "compare": True}

    rng = request.args.get("range", "7d")
    if rng == "4w":
        rng = "30d"
    if rng == "24h":
        end = _floor(now, "hour") + timedelta(hours=1)
        return {"start": end - timedelta(hours=24), "end": end, "unit": "hour",
                "label": "Last 24 hours", "range": "24h", "compare": True}
    if rng == "all":
        end = _floor(now, "day") + timedelta(days=1)
        first = col.find_one({"status_code": 200}, sort=[("timestamp", 1)])
        start = _floor(first["timestamp"], "day") if first else end - timedelta(days=30)
        start = max(start, end - timedelta(days=ANALYTICS_RETENTION_DAYS + 1))
        return {"start": start, "end": end, "unit": "day",
                "label": "All time", "range": "all", "compare": False}

    days = RANGE_DAYS.get(rng, 7)
    end = _floor(now, "day") + timedelta(days=1)
    return {"start": end - timedelta(days=days), "end": end, "unit": "day",
            "label": f"Last {days} days", "range": rng if rng in RANGE_DAYS else "7d", "compare": True}


def build_match(start, end, show_bots, filters, status=200):
    match = {"status_code": status, "timestamp": {"$gte": start, "$lt": end}}
    if not show_bots:
        match["is_bot"] = {"$ne": True}
    for key in ("path", "referrer"):
        if key in filters:
            match[key] = filters[key]
    if "country" in filters:
        match["country"] = {"$in": ["", None]} if filters["country"] == "Unknown" else filters["country"]
    return match


def totals(col, match):
    """(views, visitors) for a match. Visitors are daily hashes, so multi-day
    totals count a returning person once per day."""
    views = col.count_documents(match)
    row = next(col.aggregate([
        {"$match": match}, {"$group": {"_id": "$visitor_hash"}}, {"$count": "n"},
    ]), None)
    return views, (row["n"] if row else 0)


def pct_change(current, previous):
    if not previous:
        return None
    return round((current - previous) / previous * 100)


def ranked(rows, key="_id", limit=8):
    return [{"name": r[key] or "Unknown", "count": r["n"]} for r in rows[:limit]]


@app.route("/admin/analytics")
@login_required
def admin_analytics():
    col = g.analytics_col
    if col is None:
        return render_template("503.html", maintenance_active=False), 503

    now = utc_now()
    show_bots = request.args.get("bots") == "true"
    filters = {k: request.args[k] for k in ("path", "referrer", "country", *UA_KEYS) if request.args.get(k)}
    win = resolve_window(now, col)
    start, end, unit = win["start"], win["end"], win["unit"]

    # Filtered match, without the user-agent part.
    match = build_match(start, end, show_bots, filters)

    # ── User agents: group by agent string, parse each once ──
    agent_rows = list(col.aggregate([
        {"$match": match}, {"$group": {"_id": "$agent", "n": {"$sum": 1}}},
        {"$sort": {"n": DESCENDING}}, {"$limit": MAX_AGENTS},
    ]))
    if any(k in filters for k in UA_KEYS):
        wanted = []
        for row in agent_rows:
            browser, os_name, device = parse_ua(row["_id"])
            attrs = {"browser": browser, "os": os_name, "device": device}
            if all(attrs[k] == filters[k] for k in UA_KEYS if k in filters):
                wanted.append(row["_id"])
        match["agent"] = {"$in": wanted}
        agent_rows = [r for r in agent_rows if r["_id"] in set(wanted)]

    browsers, systems, devices = {}, {}, {}
    for row in agent_rows:
        browser, os_name, device = parse_ua(row["_id"])
        browsers[browser] = browsers.get(browser, 0) + row["n"]
        systems[os_name] = systems.get(os_name, 0) + row["n"]
        devices[device] = devices.get(device, 0) + row["n"]

    def as_rows(counts):
        return [{"name": k, "count": v} for k, v in sorted(counts.items(), key=lambda kv: -kv[1])[:8]]

    # ── Headline numbers, with the previous period for comparison ──
    views, visitors = totals(col, match)
    prev = {"views": None, "visitors": None}
    if win["compare"]:
        span = end - start
        prev_match = build_match(start - span, start, show_bots, filters)
        if "agent" in match:
            prev_match["agent"] = match["agent"]
        prev_views, prev_visitors = totals(col, prev_match)
        prev = {"views": prev_views, "visitors": prev_visitors}

    # ── Time series (views and visitors per bucket) ──
    fmt = "%Y-%m-%d %H:00" if unit == "hour" else "%Y-%m-%d"
    series_rows = col.aggregate([
        {"$match": match},
        {"$group": {"_id": {"b": {"$dateToString": {"format": fmt, "date": "$timestamp"}}, "v": "$visitor_hash"},
                    "n": {"$sum": 1}}},
        {"$group": {"_id": "$_id.b", "views": {"$sum": "$n"}, "visitors": {"$sum": 1}}},
    ])
    by_bucket = {r["_id"]: r for r in series_rows}

    chart = {"keys": [], "labels": [], "views": [], "visitors": [], "unit": unit}
    step = timedelta(hours=1) if unit == "hour" else timedelta(days=1)
    t = start
    while t < end:
        key = t.strftime(fmt)
        row = by_bucket.get(key, {})
        chart["keys"].append(t.strftime("%Y-%m-%d"))
        chart["labels"].append(t.strftime("%H:00") if unit == "hour" else t.strftime("%d %b"))
        chart["views"].append(row.get("views", 0))
        chart["visitors"].append(row.get("visitors", 0))
        t += step

    # ── Hour of day (real counts, UTC) ──
    hour_counts = [0] * 24
    for row in col.aggregate([{"$match": match}, {"$group": {"_id": {"$hour": "$timestamp"}, "n": {"$sum": 1}}}]):
        hour_counts[row["_id"]] = row["n"]

    # ── Top pages, referrers, countries ──
    top_pages = [
        {"path": r["_id"], "views": r["views"], "visitors": r["visitors"]}
        for r in col.aggregate([
            {"$match": match},
            {"$group": {"_id": {"p": "$path", "v": "$visitor_hash"}, "n": {"$sum": 1}}},
            {"$group": {"_id": "$_id.p", "views": {"$sum": "$n"}, "visitors": {"$sum": 1}}},
            {"$sort": {"views": DESCENDING}}, {"$limit": 10},
        ])
    ]
    referrers = ranked(list(col.aggregate([
        {"$match": match if "referrer" in filters else {**match, "referrer": {"$ne": "Direct / Internal"}}},
        {"$group": {"_id": "$referrer", "n": {"$sum": 1}}}, {"$sort": {"n": DESCENDING}}, {"$limit": 8},
    ])))
    countries = ranked(list(col.aggregate([
        {"$match": match}, {"$group": {"_id": "$country", "n": {"$sum": 1}}},
        {"$sort": {"n": DESCENDING}}, {"$limit": 8},
    ])))

    # ── Errors in the same window ──
    errors = list(col.aggregate([
        {"$match": {"status_code": {"$gte": 400}, "timestamp": {"$gte": start, "$lt": end}}},
        {"$group": {"_id": {"s": "$status_code", "p": "$path"}, "n": {"$sum": 1}, "last": {"$max": "$timestamp"}}},
        {"$sort": {"n": DESCENDING}}, {"$limit": 10},
    ]))

    # ── Side facts ──
    online_row = next(col.aggregate([
        {"$match": {"timestamp": {"$gte": now - timedelta(minutes=5)}, "is_bot": {"$ne": True}, "status_code": 200}},
        {"$group": {"_id": "$visitor_hash"}}, {"$count": "n"},
    ]), None)
    bot_requests = col.count_documents({"status_code": 200, "is_bot": True, "timestamp": {"$gte": start, "$lt": end}})

    # ── Link builder that keeps the current filters ──
    current = {k: request.args[k] for k in PARAM_KEYS if request.args.get(k)}

    def link(**changes):
        params = dict(current)
        for key, value in changes.items():
            if value is None:
                params.pop(key, None)
            else:
                params[key] = value
        return "/admin/analytics" + ("?" + urlencode(params) if params else "")

    return render_template(
        "analytics.html",
        win=win,
        views=views,
        visitors=visitors,
        prev=prev,
        views_change=pct_change(views, prev["views"]),
        visitors_change=pct_change(visitors, prev["visitors"]),
        per_visitor=round(views / visitors, 1) if visitors else 0,
        chart=chart,
        hour_counts=hour_counts,
        hour_max=max(hour_counts) or 1,
        top_pages=top_pages,
        referrers=referrers,
        countries=countries,
        browsers=as_rows(browsers),
        systems=as_rows(systems),
        devices=as_rows(devices),
        errors=errors,
        online=online_row["n"] if online_row else 0,
        bot_requests=bot_requests,
        show_bots=show_bots,
        filters=filters,
        range_choices=RANGE_CHOICES,
        retention_days=ANALYTICS_RETENTION_DAYS,
        link=link,
    )
