"""Optional, low-cost reputation corroboration providers.

The local PhishGuard engine remains the primary decision maker. Provider hits
become attributed evidence; missing, timed-out, or rate-limited providers remain
unknown and are never interpreted as a clean result.
"""
from __future__ import annotations

import base64
import hashlib
import os
import threading
import time
import requests

TIMEOUT = (4, 8)
GSB_KEY = os.environ.get("GSB_API_KEY", "").strip()
VT_KEY = os.environ.get("VT_API_KEY", "").strip()
URLHAUS_KEY = os.environ.get("URLHAUS_AUTH_KEY", "").strip()
PHISHTANK_KEY = os.environ.get("PHISHTANK_APP_KEY", "").strip()

_CACHE: dict[tuple[str, str], tuple[float, dict]] = {}
_CACHE_LOCK = threading.Lock()
_CACHE_MAX = 2048


def configured() -> dict:
    """Report configured provider keys only; never return their values."""
    return {
        "safe_browsing": bool(GSB_KEY),
        "virustotal": bool(VT_KEY),
        "urlhaus": bool(URLHAUS_KEY),
        "phishtank": bool(PHISHTANK_KEY),
    }


def _cached(provider: str, key: str, ttl: int, lookup):
    cache_key = (provider, key)
    now = time.monotonic()
    with _CACHE_LOCK:
        cached = _CACHE.get(cache_key)
        if cached and cached[0] > now:
            return dict(cached[1])
        if cached:
            _CACHE.pop(cache_key, None)
    result = lookup()
    if result.get("ok"):
        cache_seconds = max(0, min(int(result.get("cache_seconds", ttl)), 86400))
        if cache_seconds:
            with _CACHE_LOCK:
                if len(_CACHE) >= _CACHE_MAX:
                    _CACHE.pop(next(iter(_CACHE)))
                _CACHE[cache_key] = (now + cache_seconds, dict(result))
    return result


def _unconfigured(provider: str, env_name: str) -> dict:
    return {"ok": False, "configured": False, "hit": False,
            "note": f"{provider} key not configured (set {env_name})"}


def _decode_safe_browsing_v5(payload: dict) -> tuple[list[dict], int]:
    """Normalize the JSON response from the Safe Browsing v5 REST endpoint."""
    raw_threats = payload.get("threats") or []
    threats = []
    for item in raw_threats:
        if not isinstance(item, dict):
            continue
        raw_types = item.get("threatTypes") or item.get("threat_types") or []
        threats.append({
            "url": str(item.get("url") or ""),
            "threat_types": sorted({str(kind) for kind in raw_types}),
        })
    duration = str(payload.get("cacheDuration") or "300s")
    try:
        # Google uses the protobuf JSON Duration form, such as "300s".
        seconds = int(float(duration[:-1])) if duration.endswith("s") else 300
    except (TypeError, ValueError):
        seconds = 300
    return threats, max(0, min(seconds, 86400))

def safe_browsing(url: str) -> dict:
    """Google Safe Browsing v5 real-time URL lookup (non-commercial use)."""
    if not GSB_KEY:
        return _unconfigured("Safe Browsing", "GSB_API_KEY")

    def lookup():
        try:
            response = requests.get(
                "https://safebrowsing.googleapis.com/v5/urls:search",
                params={"key": GSB_KEY, "urls": url},
                headers={"User-Agent": "PhishGuard/0.9"}, timeout=TIMEOUT,
            )
            response.raise_for_status()
            payload = response.json()
            if not isinstance(payload, dict) or "error" in payload:
                raise ValueError("unexpected Safe Browsing response")
            threats, cache_seconds = _decode_safe_browsing_v5(payload)
            kinds = sorted({kind for threat in threats for kind in threat["threat_types"]})
            return {"ok": True, "configured": True, "hit": bool(threats),
                    "threats": kinds, "cache_seconds": cache_seconds,
                    "note": ("Google Safe Browsing: listed as " + ", ".join(kinds)
                             if threats else "Google Safe Browsing: no listed threat (not a safety verdict)")}
        except Exception as exc:
            return {"ok": False, "configured": True, "hit": False,
                    "note": f"Google Safe Browsing unavailable ({type(exc).__name__})"}

    return _cached("gsb", url, 300, lookup)


def virustotal_url(url: str) -> dict:
    """VT v3 lookup only: this does not submit or initiate a scan of the URL."""
    if not VT_KEY:
        return _unconfigured("VirusTotal", "VT_API_KEY")

    def lookup():
        uid = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        try:
            response = requests.get(
                f"https://www.virustotal.com/api/v3/urls/{uid}",
                headers={"x-apikey": VT_KEY}, timeout=TIMEOUT,
            )
            if response.status_code == 404:
                return {"ok": True, "configured": True, "hit": False,
                        "never_seen": True, "cache_seconds": 900,
                        "note": "VirusTotal: URL has no report (not a safety verdict)"}
            response.raise_for_status()
            stats = response.json()["data"]["attributes"]["last_analysis_stats"]
            bad = int(stats.get("malicious", 0)) + int(stats.get("suspicious", 0))
            return {"ok": True, "configured": True, "hit": bad > 0, "stats": stats,
                    "cache_seconds": 3600,
                    "note": f"VirusTotal: {bad} engines flagged "
                            f"({stats.get('malicious', 0)} malicious, "
                            f"{stats.get('suspicious', 0)} suspicious)"}
        except Exception as exc:
            return {"ok": False, "configured": True, "hit": False,
                    "note": f"VirusTotal unavailable ({type(exc).__name__})"}

    return _cached("vt", url, 3600, lookup)


def urlhaus_url(url: str) -> dict:
    """Check URLhaus for known malware distribution URLs."""
    if not URLHAUS_KEY:
        return _unconfigured("URLhaus", "URLHAUS_AUTH_KEY")

    def lookup():
        try:
            response = requests.post(
                "https://urlhaus-api.abuse.ch/v1/url/",
                data={"url": url},
                headers={"Auth-Key": URLHAUS_KEY, "User-Agent": "PhishGuard/0.9"},
                timeout=TIMEOUT,
            )
            try:
                data = response.json()
            except ValueError:
                data = {}
            status_code = getattr(response, "status_code", 200)
            if not isinstance(status_code, int):
                status_code = 200
            query_status = data.get("query_status", "") if isinstance(data, dict) else ""
            if status_code in (401, 403) or query_status == "auth_error":
                return {"ok": False, "configured": True, "hit": False,
                        "note": f"URLhaus rejected the Auth-Key (HTTP {status_code}); "
                                "check the Preview URLHAUS_AUTH_KEY value"}
            if status_code == 429:
                return {"ok": False, "configured": True, "hit": False,
                        "note": "URLhaus rate limit reached (HTTP 429); retry later"}
            if status_code >= 400:
                return {"ok": False, "configured": True, "hit": False,
                        "note": f"URLhaus request failed (HTTP {status_code})"}
            response.raise_for_status()
            status = query_status
            hit = status == "ok"
            threat = data.get("threat", "malware URL") if hit else ""
            online = data.get("url_status", "unknown") if hit else ""
            return {"ok": status in {"ok", "no_results"}, "configured": True,
                    "hit": hit, "threat": threat, "url_status": online,
                    "cache_seconds": 900,
                    "note": (f"URLhaus: known {threat} ({online})" if hit
                             else "URLhaus: no matching malware URL (not a general safety verdict)")}
        except Exception as exc:
            return {"ok": False, "configured": True, "hit": False,
                    "note": f"URLhaus unavailable ({type(exc).__name__})"}

    return _cached("urlhaus", url, 900, lookup)


def phishtank_url(url: str) -> dict:
    """Check PhishTank's community phishing database for an exact URL."""
    if not PHISHTANK_KEY:
        return _unconfigured("PhishTank", "PHISHTANK_APP_KEY")
    cache_key = hashlib.sha256(url.encode("utf-8", "replace")).hexdigest()

    def lookup():
        try:
            form = {"url": url, "format": "json"}
            if PHISHTANK_KEY:
                form["app_key"] = PHISHTANK_KEY
            response = requests.post(
                "https://checkurl.phishtank.com/checkurl/", data=form,
                headers={"User-Agent": "phishtank/PhishGuard"}, timeout=TIMEOUT,
            )
            response.raise_for_status()
            payload = response.json()
            result = payload.get("results") if isinstance(payload, dict) else None
            if not isinstance(result, dict):
                return {"ok": False, "configured": True, "hit": False,
                        "note": "PhishTank unavailable (unexpected response)"}
            hit = bool(result.get("in_database") and result.get("verified") and result.get("valid"))
            return {"ok": True, "configured": True, "hit": hit,
                    "cache_seconds": 1800,
                    "note": ("PhishTank: URL is community-verified as phishing" if hit
                             else "PhishTank: no verified phishing match (not a safety verdict)")}
        except Exception as exc:
            return {"ok": False, "configured": True, "hit": False,
                    "note": f"PhishTank unavailable ({type(exc).__name__})"}

    return _cached("phishtank", cache_key, 1800, lookup)


def virustotal_hash(sha256: str) -> dict:
    """Look up an attachment hash without uploading the file."""
    if not VT_KEY:
        return _unconfigured("VirusTotal", "VT_API_KEY")
    try:
        response = requests.get(
            f"https://www.virustotal.com/api/v3/files/{sha256}",
            headers={"x-apikey": VT_KEY}, timeout=TIMEOUT,
        )
        if response.status_code == 404:
            return {"ok": True, "configured": True, "hit": False,
                    "never_seen": True,
                    "note": "VirusTotal: attachment hash has no report (not a safety verdict)"}
        response.raise_for_status()
        stats = response.json()["data"]["attributes"]["last_analysis_stats"]
        bad = int(stats.get("malicious", 0)) + int(stats.get("suspicious", 0))
        return {"ok": True, "configured": True, "hit": bad > 0, "stats": stats,
                "note": f"VirusTotal: {bad} engines flagged this file"}
    except Exception as exc:
        return {"ok": False, "configured": True, "hit": False,
                "note": f"VirusTotal unavailable ({type(exc).__name__})"}


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
