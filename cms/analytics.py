"""Admin analytics dashboard.

All counting happens in MongoDB. The only per-row work in Python is parsing user
agents, and that is done once per *distinct* agent string, not once per page view.
"""
import csv
import io
from datetime import datetime, timedelta
from functools import lru_cache
from urllib.parse import urlencode

from flask import Response, g, jsonify, render_template, request
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


def build_report(col):
    """Everything the page and the CSV export show, for the window in the query string."""
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
    prev_match = None
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

    chart = {"keys": [], "labels": [], "views": [], "visitors": [], "previous": None, "unit": unit}
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

    # The previous period's views, bucket for bucket, so the chart can draw it behind this one.
    if prev_match is not None:
        prev_rows = {r["_id"]: r["views"] for r in col.aggregate([
            {"$match": prev_match},
            {"$group": {"_id": {"$dateToString": {"format": fmt, "date": "$timestamp"}}, "views": {"$sum": 1}}},
        ])}
        chart["previous"] = []
        t = start - (end - start)
        while t < start:
            chart["previous"].append(prev_rows.get(t.strftime(fmt), 0))
            t += step

    # ── Hour of day and day of week (real counts, UTC) ──
    hour_counts = [0] * 24
    for row in col.aggregate([{"$match": match}, {"$group": {"_id": {"$hour": "$timestamp"}, "n": {"$sum": 1}}}]):
        hour_counts[row["_id"]] = row["n"]
    weekday_counts = [0] * 7
    for row in col.aggregate([{"$match": match}, {"$group": {"_id": {"$dayOfWeek": "$timestamp"}, "n": {"$sum": 1}}}]):
        weekday_counts[(row["_id"] + 5) % 7] += row["n"]  # Mongo counts Sunday as 1; shift so Monday is 0.

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

    # ── Visits: how many people read one page and left, and which page they arrived on ──
    visit_rows = list(col.aggregate([
        {"$match": match}, {"$sort": {"timestamp": 1}},
        {"$group": {"_id": "$visitor_hash", "n": {"$sum": 1}, "entry": {"$first": "$path"}}},
    ]))
    single_pct = round(sum(1 for r in visit_rows if r["n"] == 1) / len(visit_rows) * 100) if visit_rows else None
    entry_counts = {}
    for r in visit_rows:
        entry_counts[r["entry"]] = entry_counts.get(r["entry"], 0) + 1
    entry_pages = [{"path": k, "count": v} for k, v in sorted(entry_counts.items(), key=lambda kv: -kv[1])[:6]]

    # ── Contact: people who opened the page against messages that arrived ──
    contact_visitors = totals(col, build_match(start, end, show_bots, {"path": "contact"}))[1]
    messages = None
    if g.db is not None:
        try:
            messages = g.db.inquiries.count_documents(
                {"status": {"$ne": "SPAM"}, "received_at": {"$gte": start, "$lt": end}})
        except Exception:
            messages = None

    # ── Errors in the same window ──
    errors = list(col.aggregate([
        {"$match": {"status_code": {"$gte": 400}, "timestamp": {"$gte": start, "$lt": end}}},
        {"$group": {"_id": {"s": "$status_code", "p": "$path"}, "n": {"$sum": 1}, "last": {"$max": "$timestamp"}}},
        {"$sort": {"n": DESCENDING}}, {"$limit": 10},
    ]))

    # ── Bots by name ──
    bot_names = {}
    for row in col.aggregate([
        {"$match": {"status_code": 200, "is_bot": True, "timestamp": {"$gte": start, "$lt": end}}},
        {"$group": {"_id": "$agent", "n": {"$sum": 1}}}, {"$sort": {"n": DESCENDING}}, {"$limit": 200},
    ]):
        family = parse_ua(row["_id"])[0]
        label = "Unnamed crawler" if family in ("Other", "Generic Smartphone") else family
        bot_names[label] = bot_names.get(label, 0) + row["n"]
    bots = [{"name": k, "count": v} for k, v in sorted(bot_names.items(), key=lambda kv: -kv[1])[:6]]
    bot_requests = sum(bot_names.values())

    online_row = next(col.aggregate([
        {"$match": {"timestamp": {"$gte": now - timedelta(minutes=5)}, "is_bot": {"$ne": True}, "status_code": 200}},
        {"$group": {"_id": "$visitor_hash"}}, {"$count": "n"},
    ]), None)

    # ── A few plain sentences about the period ──
    insights = []
    if views and unit == "day":
        best = max(range(len(chart["views"])), key=lambda i: chart["views"][i])
        if chart["views"][best]:
            insights.append(f"Busiest day: {chart['labels'][best]}, with {chart['views'][best]} views.")
    if top_pages:
        name = "The home page" if top_pages[0]["path"] == "home" else "/" + top_pages[0]["path"]
        insights.append(f"{name} was read most, with {top_pages[0]['views']} views.")
    outside = [r for r in referrers if r["name"] not in ("Direct Entry", "Direct / Internal")]
    if outside:
        insights.append(f"Most outside visitors came from {outside[0]['name']}.")
    if sum(devices.values()):
        share = round(devices.get("Mobile", 0) / sum(devices.values()) * 100)
        insights.append(f"{share}% of views were on a phone.")
    if single_pct is not None and visitors >= 5:
        insights.append(f"{single_pct}% of visitors read one page and left.")

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

    return {
        "win": win, "views": views, "visitors": visitors, "prev": prev,
        "views_change": pct_change(views, prev["views"]),
        "visitors_change": pct_change(visitors, prev["visitors"]),
        "per_visitor": round(views / visitors, 1) if visitors else 0,
        "chart": chart, "hour_counts": hour_counts, "hour_max": max(hour_counts) or 1,
        "weekday_counts": weekday_counts, "weekday_max": max(weekday_counts) or 1,
        "top_pages": top_pages, "entry_pages": entry_pages, "single_pct": single_pct,
        "referrers": referrers, "countries": countries,
        "browsers": as_rows(browsers), "systems": as_rows(systems), "devices": as_rows(devices),
        "errors": errors, "online": online_row["n"] if online_row else 0,
        "bot_requests": bot_requests, "bots": bots, "show_bots": show_bots, "filters": filters,
        "contact_visitors": contact_visitors, "messages": messages, "insights": insights,
        "range_choices": RANGE_CHOICES, "retention_days": ANALYTICS_RETENTION_DAYS, "link": link,
    }


@app.route("/admin/analytics")
@login_required
def admin_analytics():
    col = g.analytics_col
    if col is None:
        return render_template("503.html", maintenance_active=False), 503
    return render_template("analytics.html", **build_report(col))


def _safe_cell(value):
    """Spreadsheets run text that starts with = + - @ as a formula, and paths and referrers come from visitors."""
    text = str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


@app.route("/admin/analytics.csv")
@login_required
def admin_analytics_csv():
    col = g.analytics_col
    if col is None:
        return render_template("503.html", maintenance_active=False), 503
    r = build_report(col)
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["Report", r["win"]["label"], "times in UTC"])
    w.writerow(["Page views", r["views"]])
    w.writerow(["Visitors", r["visitors"]])
    w.writerow([])
    w.writerow(["When", "Views", "Visitors"])
    c = r["chart"]
    for i, key in enumerate(c["keys"]):
        w.writerow([key if c["unit"] == "day" else f"{key} {c['labels'][i]}", c["views"][i], c["visitors"][i]])
    for title, rows, name_key in (("Page", r["top_pages"], "path"), ("Referrer", r["referrers"], "name"),
                                  ("Country", r["countries"], "name"), ("Browser", r["browsers"], "name"),
                                  ("Operating system", r["systems"], "name"), ("Device", r["devices"], "name")):
        w.writerow([])
        w.writerow([title, "Views"])
        for row in rows:
            w.writerow([_safe_cell(row[name_key]), row.get("views", row.get("count"))])
    return Response(out.getvalue(), mimetype="text/csv", headers={
        "Content-Disposition": f'attachment; filename="analytics-{utc_now():%Y-%m-%d}.csv"', "Cache-Control": "no-store"})


@app.route("/admin/analytics/live")
@login_required
def admin_analytics_live():
    """Who is on the site right now. The page asks for this every half minute."""
    col = g.analytics_col
    if col is None:
        return jsonify({"error": "unavailable"}), 503
    now = utc_now()
    recent = list(col.find(
        {"status_code": 200, "is_bot": {"$ne": True}, "timestamp": {"$gte": now - timedelta(minutes=30)}},
        {"path": 1, "country": 1, "referrer": 1, "timestamp": 1, "visitor_hash": 1},
    ).sort("timestamp", -1).limit(12))
    online = col.distinct("visitor_hash", {"status_code": 200, "is_bot": {"$ne": True}, "timestamp": {"$gte": now - timedelta(minutes=5)}})
    resp = jsonify({
        "online": len(online),
        "recent": [{"path": r["path"], "country": r.get("country") or "Unknown", "referrer": r.get("referrer", ""),
                    "minutes": int((now - r["timestamp"]).total_seconds() // 60)} for r in recent],
    })
    resp.headers["Cache-Control"] = "no-store"
    return resp
