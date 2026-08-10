"""Single source of truth for the application version (shown in the footer).

Bump this when cutting a release so it matches the git tag (a ``v2.2.0`` tag
ships ``__version__ = "2.2.0"``). A deployment can override the *displayed*
value at runtime with the ``APP_VERSION`` environment variable — handy to
surface a git short SHA for an untagged build without editing this file.
"""

__version__ = "2.5.1"
