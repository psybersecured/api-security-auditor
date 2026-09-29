import pytest
from auditor.engine.scope import ScopeError, validate_scope


def test_loopback_allowed_with_ack():
    assert validate_scope("http://127.0.0.1:9000", set(), True) == "127.0.0.1"


def test_remote_requires_exact_allowlist():
    with pytest.raises(ScopeError):
        validate_scope("https://api.example.com", set(), True)
    assert validate_scope("https://api.example.com", {"api.example.com"}, True) == "api.example.com"


def test_ack_required():
    with pytest.raises(ScopeError):
        validate_scope("http://127.0.0.1:9000", set(), False)
