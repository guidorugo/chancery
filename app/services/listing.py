"""Search, filter and pagination for the list pages and their JSON form (F15).

Query parameters are shared by the HTML pages and the JSON API:
`q` (substring), per-list filters (`status`, `ca_id`, `profile`, ...),
`page` and `per_page`. HTML pages always paginate (50 rows by default). The
JSON API keeps returning a bare array unless `page` or `per_page` is given,
in which case it answers `{items, page, per_page, total, pages}` — existing
scripts keep working unchanged.
"""
from datetime import datetime, timedelta, timezone

from flask import current_app, jsonify, request, url_for

DEFAULT_PER_PAGE = 50
MAX_PER_PAGE = 500


def _escape_like(text):
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def contains(column, text):
    """Case-insensitive substring match with LIKE metacharacters escaped."""
    return column.ilike(f"%{_escape_like(text)}%", escape="\\")


def utc_now_naive():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def expiry_bounds():
    """(now, soon) as naive UTC, `soon` = now + CERT_EXPIRY_WARNING_DAYS."""
    now = utc_now_naive()
    return now, now + timedelta(days=current_app.config.get("CERT_EXPIRY_WARNING_DAYS", 30))


class ListQuery:
    """Parsed listing parameters plus pagination state for one request."""

    def __init__(self, html):
        args = request.args
        self.html = html
        self.filters = {}
        try:
            self.page = max(1, int(args.get("page", 1)))
        except (TypeError, ValueError):
            self.page = 1
        try:
            per_page = int(args.get("per_page", DEFAULT_PER_PAGE))
        except (TypeError, ValueError):
            per_page = DEFAULT_PER_PAGE
        self.per_page = min(max(1, per_page), MAX_PER_PAGE)
        self.paginated = html or ("page" in args) or ("per_page" in args)
        self.total = None
        self.pages = None

    # -- parameter helpers ---------------------------------------------------
    def text(self, name):
        value = (request.args.get(name) or "").strip()
        if value:
            self.filters[name] = value
        return value or None

    def choice(self, name, allowed):
        value = self.text(name)
        if value is None:
            return None
        if value not in allowed:
            raise ValueError(f"Unknown {name} filter '{value}' (allowed: {', '.join(allowed)}).")
        return value

    def integer(self, name):
        value = self.text(name)
        if value is None:
            return None
        try:
            return int(value)
        except ValueError:
            raise ValueError(f"{name} must be a whole number.")

    # -- execution -------------------------------------------------------------
    def apply(self, query):
        if not self.paginated:
            items = query.all()
            self.total = len(items)
            self.pages = 1
            return items
        self.total = query.order_by(None).count()
        self.pages = max(1, -(-self.total // self.per_page))
        return query.offset((self.page - 1) * self.per_page).limit(self.per_page).all()

    @property
    def has_prev(self):
        return self.page > 1

    @property
    def has_next(self):
        return self.pages is not None and self.page < self.pages

    def page_url(self, page):
        params = request.args.to_dict()
        params["page"] = page
        return url_for(request.endpoint, **params)

    def json(self, items, to_dict):
        if not self.paginated:
            return jsonify([to_dict(i) for i in items])
        return jsonify({
            "items": [to_dict(i) for i in items],
            "page": self.page,
            "per_page": self.per_page,
            "total": self.total,
            "pages": self.pages,
        })
