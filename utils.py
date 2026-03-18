"""Utility helpers: URL normalisation, domain extraction, logging setup."""

from __future__ import annotations

import hashlib
import logging
import re
import sys
from base64 import urlsafe_b64encode
from urllib.parse import urlparse, urlunparse


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def setup_logging(debug: bool = False) -> None:
    """Configure structured logging to stdout (secrets are never logged)."""
    level = logging.DEBUG if debug else logging.INFO
    fmt = "%(asctime)s %(levelname)-8s %(name)s | %(message)s"
    logging.basicConfig(
        level=level,
        format=fmt,
        stream=sys.stdout,
        datefmt="%Y-%m-%dT%H:%M:%SZ",
    )
    # Silence overly verbose third-party loggers
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)


# ---------------------------------------------------------------------------
# URL helpers
# ---------------------------------------------------------------------------

# Matches any URI scheme (e.g. http://, https://, ftp://)
_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", re.IGNORECASE)


def normalize_url(raw: str) -> str:
    """
    Normalize a raw URL string:
    - strip whitespace
    - add https:// if no scheme present
    - lowercase scheme and host
    - remove default ports (80/443)
    - strip trailing slash from path-less URLs
    """
    url = raw.strip()
    if not _SCHEME_RE.match(url):
        url = "https://" + url
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    netloc = parsed.hostname or ""
    port = parsed.port
    if port and not (
        (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    ):
        netloc = f"{netloc}:{port}"
    path = parsed.path or "/"
    # Remove redundant trailing slash when there is no query/fragment
    if path == "/" and not parsed.query and not parsed.fragment:
        path = ""
    normalized = urlunparse(
        (scheme, netloc, path, parsed.params, parsed.query, parsed.fragment)
    )
    return normalized


def extract_domain(url: str) -> str:
    """Return the hostname from a URL, lowercased, without port."""
    parsed = urlparse(url)
    return (parsed.hostname or "").lower()


def is_valid_url(url: str) -> bool:
    """Return True if *url* has a valid scheme and host."""
    try:
        parsed = urlparse(url)
        return parsed.scheme in ("http", "https") and bool(parsed.hostname)
    except Exception:
        return False


def vt_url_id(url: str) -> str:
    """
    Compute the VirusTotal URL identifier.

    VirusTotal uses URL-safe base64(sha256(url)) without trailing '=' padding
    as the identifier for the GET /api/v3/urls/{id} endpoint.
    """
    digest = hashlib.sha256(url.encode()).digest()
    return urlsafe_b64encode(digest).decode().rstrip("=")


# ---------------------------------------------------------------------------
# File helpers
# ---------------------------------------------------------------------------

def read_urls(path) -> list[str]:
    """
    Read URLs from *path*, one per line.
    Skips blank lines and lines starting with '#'.
    """
    from pathlib import Path

    lines = Path(path).read_text(encoding="utf-8").splitlines()
    urls: list[str] = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        urls.append(stripped)
    return urls
