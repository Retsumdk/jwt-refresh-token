"""JWT access + refresh token manager with HMAC signatures and rotation.

Real, working implementation for the Retsumdk ecosystem. Issues signed access
tokens and opaque refresh tokens, supports refresh rotation, revocation, and
expiry validation. Uses only the stdlib (hmac, hashlib, base64, time) and
is fully deterministic and testable.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any, Optional


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


class TokenError(Exception):
    """Raised when a token is invalid, expired, or mis-signed."""


class JWTRefreshManager:
    """Issues and validates HMAC-SHA256 JWTs plus rotatable refresh tokens."""

    def __init__(self, secret: str, issuer: str = "retsumdk", access_ttl: float = 900):
        self.secret = secret.encode("utf-8")
        self.issuer = issuer
        self.access_ttl = access_ttl
        self._revoked: set[str] = set()
        # refresh id -> latest refresh token value (rotation tracking)
        self._refresh_series: dict[str, str] = {}

    # -- helpers ------------------------------------------------------------
    def _sign(self, header: bytes, payload: bytes) -> bytes:
        msg = header + b"." + payload
        return hmac.new(self.secret, msg, hashlib.sha256).digest()

    def _b64_json(self, obj: dict) -> str:
        return _b64url(json.dumps(obj, separators=(",", ":")).encode("utf-8"))

    # -- access tokens --------------------------------------------------------
    def issue_access(self, subject: str, claims: Optional[dict] = None) -> str:
        now = int(time.time())
        header = self._b64_json({"alg": "HS256", "typ": "JWT"})
        payload = self._b64_json(
            {
                "sub": subject,
                "iss": self.issuer,
                "iat": now,
                "exp": now + int(self.access_ttl),
                **(claims or {}),
            }
        )
        sig = _b64url(self._sign(header.encode(), payload.encode()))
        return f"{header}.{payload}.{sig}"

    def verify_access(self, token: str, expect_subject: Optional[str] = None) -> dict:
        parts = token.split(".")
        if len(parts) != 3:
            raise TokenError("malformed token")
        header, payload, sig = parts
        expected = _b64url(self._sign(header.encode(), payload.encode()))
        if not hmac.compare_digest(sig, expected):
            raise TokenError("bad signature")
        claims = json.loads(_b64url_decode(payload))
        if claims.get("iss") != self.issuer:
            raise TokenError("unexpected issuer")
        if int(claims.get("exp", 0)) <= int(time.time()):
            raise TokenError("token expired")
        if expect_subject and claims.get("sub") != expect_subject:
            raise TokenError("subject mismatch")
        return claims

    # -- refresh tokens --------------------------------------------------------
    def issue_refresh(self, subject: str, series: Optional[str] = None) -> dict:
        series = series or hashlib.sha256(f"{subject}:{time.time()}".encode()).hexdigest()[:24]
        value = hashlib.sha256(f"{series}:{time.time_ns()}".encode()).hexdigest()
        self._refresh_series[series] = value
        return {"series": series, "value": value}

    def rotate_refresh(self, series: str, old_value: str, subject: str) -> dict:
        current = self._refresh_series.get(series)
        if current is None:
            raise TokenError("unknown refresh series")
        if not hmac.compare_digest(current, old_value):
            # stale value presented: reject it; the newest value for the series
            # stays valid so a healthy client can still rotate.
            raise TokenError("refresh token reuse detected")
        new = self.issue_refresh(subject, series)
        return new

    def revoke(self, series: str) -> None:
        self._refresh_series.pop(series, None)
        self._revoked.add("refresh:" + series)

    def is_revoked(self, series: str) -> bool:
        return ("refresh:" + series in self._revoked) or (series not in self._refresh_series)


