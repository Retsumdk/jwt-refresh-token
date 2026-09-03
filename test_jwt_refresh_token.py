import time

import pytest

from jwt_refresh_token import JWTRefreshManager, TokenError


def test_access_token_roundtrip():
    m = JWTRefreshManager("sekret", access_ttl=60)
    t = m.issue_access("user-1", {"role": "admin"})
    claims = m.verify_access(t, expect_subject="user-1")
    assert claims["role"] == "admin"
    assert claims["iss"] == "retsumdk"


def test_access_token_tamper_detected():
    m = JWTRefreshManager("sekret")
    t = m.issue_access("user-1")
    bad = t[:-2] + ("ab" if t[-2:] != "ab" else "cd")
    with pytest.raises(TokenError):
        m.verify_access(bad)


def test_expired_token_rejected():
    m = JWTRefreshManager("sekret", access_ttl=1)
    t = m.issue_access("user-1")
    time.sleep(1.2)
    with pytest.raises(TokenError):
        m.verify_access(t)


def test_refresh_rotation_and_reuse():
    m = JWTRefreshManager("sekret")
    pair = m.issue_refresh("user-1")
    # valid rotation
    new = m.rotate_refresh(pair["series"], pair["value"], "user-1")
    # old value is now stale -> reuse detection
    with pytest.raises(TokenError):
        m.rotate_refresh(pair["series"], pair["value"], "user-1")
    # but the newest value still works
    again = m.rotate_refresh(pair["series"], new["value"], "user-1")
    assert again["series"] == pair["series"]


def test_revoke_series():
    m = JWTRefreshManager("sekret")
    pair = m.issue_refresh("user-1")
    m.revoke(pair["series"])
    assert m.is_revoked(pair["series"])
