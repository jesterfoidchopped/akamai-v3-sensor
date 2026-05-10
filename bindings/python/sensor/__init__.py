"""
sensor - Browser fingerprint emulation HTTP client

A requests-compatible HTTP client with TLS fingerprinting.
Drop-in replacement for the requests library.

Example:
    import sensor

    r = sensor.get("https://example.com")
    print(r.status_code, r.text)

    r = sensor.post("https://api.example.com", json={"key": "value"})
    print(r.json())

    sensor.configure(
        preset="chrome-144-windows",
        headers={"Authorization": "Bearer token"},
    )
    r = sensor.get("https://example.com")  # uses configured preset

    with sensor.Session(preset="firefox-133") as session:
        r = session.get("https://example.com")
        print(r.json())
"""

from .client import (
    Session,
    LocalProxy,
    PresetPool,
    Response,
    FastResponse,
    HTTPCloakError,
    Preset,
    SessionCacheBackend,
    load_preset,
    load_preset_from_json,
    unregister_preset,
    describe_preset,
    configure,
    configure_session_cache,
    clear_session_cache,
    get,
    post,
    put,
    delete,
    patch,
    head,
    options,
    request,
    available_presets,
    version,
    set_ech_dns_servers,
    get_ech_dns_servers,
)

__all__ = [
    "Session",
    "LocalProxy",
    "PresetPool",
    "Response",
    "FastResponse",
    "HTTPCloakError",
    "Preset",
    "SessionCacheBackend",
    "load_preset",
    "load_preset_from_json",
    "unregister_preset",
    "describe_preset",
    "configure",
    "configure_session_cache",
    "clear_session_cache",
    "get",
    "post",
    "put",
    "delete",
    "patch",
    "head",
    "options",
    "request",
    "available_presets",
    "version",
    "set_ech_dns_servers",
    "get_ech_dns_servers",
]
__version__ = "1.6.6"
