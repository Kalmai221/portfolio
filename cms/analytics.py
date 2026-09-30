"""Admin analytics dashboard."""
from datetime import datetime, timedelta

from flask import g, render_template, request
from pymongo import ASCENDING, DESCENDING
from user_agents import parse

from .app import app, utc_now
from .security import login_required


@app.route("/admin/analytics")
@login_required
def admin_analytics():
    if g.analytics_col is None:
        return render_template("503.html", maintenance_active=False), 503
    now = utc_now()

    # ── Inputs ──
    time_range  = request.args.get("range", "7d")
    target_date = request.args.get("date")
    show_bots   = request.args.get("bots") == "true"

    # ── Time window ──
    if target_date:
        try:
            parsed_date = datetime.strptime(f"{target_date} {now.year}", "%b %d %Y")
            start_date, end_date = parsed_date, parsed_date + timedelta(days=1)
            display_range, date_format, steps, delta_unit = (
                f"Drill-down: {target_date}", "%Y-%m-%d %H:00", 23, "hours"
            )
        except ValueError:
            start_date, end_date = now - timedelta(days=7), now
            display_range, date_format, steps, delta_unit = "7d", "%Y-%m-%d", 7, "days"
    elif time_range == "24h":
        start_date, end_date = now - timedelta(hours=24), now
        display_range, date_format, steps, delta_unit = "24h", "%Y-%m-%d %H:00", 24, "hours"
    elif time_range == "4w":
        start_date, end_date = now - timedelta(weeks=4), now
        display_range, date_format, steps, delta_unit = "4w", "%Y-%m-%d", 28, "days"
    elif time_range == "all":
        first = g.analytics_col.find_one({"status_code": 200}, sort=[("timestamp", ASCENDING)])
        start_date = first["timestamp"] if first else now - timedelta(days=365)
        end_date, display_range, date_format = now, "All Time", "%Y-%m-%d"
        delta = end_date - start_date
        steps, delta_unit = delta.days, "days"
    else:  # 7d default
        start_date, end_date = now - timedelta(days=7), now
        display_range, date_format, steps, delta_unit = "7d", "%Y-%m-%d", 7, "days"

    # ── Filters ──
    valid_filters = ["path", "referrer", "browser", "os", "device", "country"]
    active_filters = {k: request.args.get(k) for k in valid_filters if request.args.get(k)}

    base_filter = {
        "status_code": 200,
        "timestamp":   {"$gte": start_date, "$lt": end_date},
    }
    if not show_bots:
        base_filter["is_bot"] = {"$ne": True}
    for field in ("path", "referrer", "country"):
        if field in active_filters:
            base_filter[field] = active_filters[field]

    # ── Chart pipeline ──
    raw_results = list(g.analytics_col.aggregate([
        {"$match": base_filter},
        {"$group": {
            "_id":   {"$dateToString": {"format": date_format, "date": "$timestamp"}},
            "logs":  {"$push": "$agent"},
            "count": {"$sum": 1},
        }},
        {"$sort": {"_id": 1}},
    ]))

    # Build a dict and apply browser/os/device filters
    raw_graph: dict[str, int] = {}
    for entry in raw_results:
        key = entry["_id"]
        count = 0
        for agent in entry["logs"]:
            ua = parse(agent or "")
            browser = ua.browser.family
            os_fam  = ua.os.family
            device  = "Mobile" if ua.is_mobile else "Tablet" if ua.is_tablet else "Desktop"
            if "browser" in active_filters and active_filters["browser"] != browser:
                continue
            if "os" in active_filters and active_filters["os"] != os_fam:
                continue
            if "device" in active_filters and active_filters["device"] != device:
                continue
            count += 1
        raw_graph[key] = count

    # ── Labels & values ──
    chart_labels, chart_values = [], []
    for i in range(steps, -1, -1):
        dt  = end_date - (timedelta(hours=i) if delta_unit == "hours" else timedelta(days=i))
        key = dt.strftime(date_format)
        chart_labels.append(dt.strftime("%b %d %H:00") if delta_unit == "hours" else dt.strftime("%b %d"))
        chart_values.append(raw_graph.get(key, 0))

    # ── Sidebar aggregation ──
    unique_visitors = len(g.analytics_col.distinct("visitor_hash", base_filter))
    online_count    = len(g.analytics_col.distinct(
        "visitor_hash",
        {"timestamp": {"$gt": now - timedelta(minutes=5)}}
    ))

    stats = {
        "browsers": {}, "os": {}, "devices": {},
        "referrers": {}, "referrers_detailed": {}, "countries": {},
    }
    logs = list(g.analytics_col.find(base_filter))
    filtered_count = 0

    for log in logs:
        ua      = parse(log.get("agent") or "")
        browser = ua.browser.family
        os_fam  = ua.os.family
        device  = "Mobile" if ua.is_mobile else "Tablet" if ua.is_tablet else "Desktop"
        country = log.get("country", "Unknown") or "Unknown"

        if "browser" in active_filters and active_filters["browser"] != browser:

            continue
        if "os" in active_filters and active_filters["os"] != os_fam:
            continue
        if "device" in active_filters and active_filters["device"] != device:
            continue

        filtered_count += 1
        stats["browsers"][browser]  = stats["browsers"].get(browser, 0) + 1
        stats["os"][os_fam]         = stats["os"].get(os_fam, 0) + 1
        stats["devices"][device]    = stats["devices"].get(device, 0) + 1
        stats["countries"][country] = stats["countries"].get(country, 0) + 1

        ref = log.get("referrer", "Direct Entry")
        stats["referrers"][ref] = stats["referrers"].get(ref, 0) + 1
        if ref not in stats["referrers_detailed"]:
            stats["referrers_detailed"][ref] = {"count": 0, "url": log.get("full_referrer_url", "")}
        stats["referrers_detailed"][ref]["count"] += 1

    # ── Top pages & errors ──
    top_pages = list(g.analytics_col.aggregate([
        {"$match": base_filter},
        {"$group": {"_id": "$path", "count": {"$sum": 1}}},
        {"$sort": {"count": DESCENDING}},
        {"$limit": 10},
    ]))

    error_logs = list(g.analytics_col.find(
        {"status_code": {"$gte": 400}, "timestamp": {"$gte": start_date, "$lt": end_date}}
    ).sort("timestamp", DESCENDING).limit(20))

    # ── Filter helpers (preserve all current params) ──
    def _base_params():
        p = {k: v for k, v in active_filters.items() if k != "bots"}
        p["range"] = time_range
        p["bots"]  = "true" if show_bots else "false"
        if target_date:
            p["date"] = target_date
        return p

    def add_filter(new_type, new_val):
        p = _base_params()
        p[new_type] = new_val
        return p

    def remove_filter(type_to_remove):
        p = _base_params()
        p.pop(type_to_remove, None)
        return p

    return render_template(
        "analytics.html",
        total_hits=filtered_count,
        unique_visitors=unique_visitors,
        online_count=online_count,
        chart_labels=chart_labels,
        chart_values=chart_values,
        stats=stats,
        top_pages=top_pages,
        error_logs=error_logs,
        active_filters=active_filters,
        active_range=display_range,
        delta_unit=delta_unit,
        target_date=target_date,
        add_filter=add_filter,
        remove_filter=remove_filter,
    )
