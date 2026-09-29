from __future__ import annotations

import ipaddress
from urllib.parse import urlparse


class ScopeError(ValueError):
    pass


LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


def validate_scope(base_url: str, allowed_hosts: set[str], authorization_ack: bool) -> str:
    if not authorization_ack:
        raise ScopeError("Authorization acknowledgement is required before scanning")
    parsed = urlparse(base_url)
    if parsed.scheme not in {"http", "https"}:
        raise ScopeError("Target base URL must use http or https")
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host:
        raise ScopeError("Target base URL does not contain a hostname")
    if host in LOCAL_HOSTS:
        return host
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_loopback:
            return host
    except ValueError:
        pass
    normalized = {h.lower().rstrip(".") for h in allowed_hosts}
    if host not in normalized:
        raise ScopeError(
            f"Remote target '{host}' is outside the explicit allowlist. Add the exact host before scanning."
        )
    return host
