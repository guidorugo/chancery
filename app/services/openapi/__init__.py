"""OpenAPI 3.1 document of the JSON API (F22, 3.8.0) — see ``builder.py`` for the
static-document rule and the role filtering, ``operations.py`` for the per-endpoint
metadata and ``schemas.py`` for the component schemas."""
from .builder import app_version, build, document_for, openapi_path, rule_keys  # noqa: F401
