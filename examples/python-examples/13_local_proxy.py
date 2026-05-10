#!/usr/bin/env python3
"""
Example 13: LocalProxy - Local HTTP Proxy with TLS Fingerprinting

This example shows how to use LocalProxy to transparently apply TLS
fingerprinting to any HTTP client. Perfect for integrating with:
- requests
- httpx
- aiohttp
- Any HTTP client that supports proxy configuration

Features:
- TLS-only mode: Pass headers through, only apply TLS fingerprint
- Per-request proxy rotation via Proxy-Authorization header
- High-performance streaming with no buffering
"""

import sensor
from sensor import LocalProxy, Session

def basic_local_proxy():
    """Basic LocalProxy usage."""
    print("=== Basic LocalProxy Usage ===\n")

    proxy = LocalProxy(
        preset="chrome-latest",
        port=0,  # Auto-select available port
    )

    print(f"Proxy started on port {proxy.port}")
    print(f"Proxy URL: {proxy.proxy_url}")
    print(f"Is running: {proxy.is_running}")

    stats = proxy.get_stats()
    print(f"Stats: {stats}")

    proxy.close()
    print(f"Proxy stopped: {not proxy.is_running}\n")

def tls_only_mode():
    """TLS-only mode passes headers through while applying TLS fingerprinting."""
    print("=== TLS-Only Mode ===\n")
    print("TLS-only mode passes HTTP headers through unchanged while applying TLS fingerprinting.")
    print("Perfect for Playwright/Puppeteer integration where browser headers are already authentic.\n")

    proxy = LocalProxy(
        preset="chrome-latest",
        tls_only=True,  # Only apply TLS fingerprint, pass headers through
        port=0,
    )

    print(f"TLS-only proxy running on {proxy.proxy_url}")

    session = Session(
        proxy=proxy.proxy_url,
        preset="chrome-latest",
    )

    try:
        response = session.get("https://httpbin.org/headers")
        print(f"Response status: {response.status_code}")
        print(f"Protocol used: {response.protocol}")

        import json
        data = response.json()
        print(f"Headers received by server: {json.dumps(data, indent=2)}")
    except Exception as e:
        print(f"Request error: {e}")
    finally:
        session.close()
        proxy.close()

    print()

def per_request_proxy_rotation():
    """Use Proxy-Authorization header to rotate upstream proxies per-request."""
    print("=== Per-Request Proxy Rotation ===\n")
    print("Use Proxy-Authorization header to rotate upstream proxies per-request.")
    print("This works for BOTH HTTP and HTTPS requests (unlike X-Upstream-Proxy).")
    print("Perfect for proxy rotation with services like Bright Data.\n")

    proxy = LocalProxy(
        preset="chrome-latest",
        tls_only=True,
        port=0,
    )

    print(f"LocalProxy running on {proxy.proxy_url}")
    print("Requests can specify different upstream proxies via header.\n")

    upstream_proxies = [
        "http://user:pass@proxy-1.example.com:8080",
        "http://user:pass@proxy-2.example.com:8080",
        "socks5://user:pass@socks-proxy.example.com:1080",
    ]

    print("Header format: Proxy-Authorization: HTTPCloak <proxy-url>")
    print("\nExample usage:")
    for upstream_proxy in upstream_proxies:
        print(f"  Proxy-Authorization: HTTPCloak {upstream_proxy}")

    print("\nThe header is automatically stripped before forwarding to the target.")
    print("Note: X-Upstream-Proxy header still works for HTTP requests (legacy support).")

    proxy.close()
    print()

def with_default_upstream_proxy():
    """LocalProxy with a default upstream proxy."""
    print("=== LocalProxy with Default Upstream Proxy ===\n")

    proxy = LocalProxy(
        preset="chrome-latest",
        tls_only=True,
        tcp_proxy="http://user:pass@your-proxy.example.com:8080",  # Default for HTTP/1.1, HTTP/2
        port=0,
    )

    print(f"LocalProxy with default upstream running on {proxy.proxy_url}")
    print("All requests will go through the configured upstream proxy.")
    print("Individual requests can override with Proxy-Authorization header.\n")

    proxy.close()

def proxy_statistics():
    """Monitor proxy statistics."""
    print("=== Proxy Statistics ===\n")

    proxy = LocalProxy(
        preset="chrome-latest",
        max_connections=1000,
        timeout=30,
        port=0,
    )

    session = Session(
        proxy=proxy.proxy_url,
        preset="chrome-latest",
    )

    try:
        session.get("https://httpbin.org/get")
        session.get("https://httpbin.org/ip")

        stats = proxy.get_stats()
        print("Proxy statistics:")
        print(f"  Running: {stats.get('running')}")
        print(f"  Active connections: {stats.get('active_connections')}")
        print(f"  Total requests: {stats.get('total_requests')}")
        print(f"  Failed requests: {stats.get('failed_requests')}")
    except Exception as e:
        print(f"Request error: {e}")
    finally:
        session.close()
        proxy.close()

    print()

def context_manager_usage():
    """LocalProxy supports context manager for automatic cleanup."""
    print("=== Context Manager Usage ===\n")

    with LocalProxy(preset="chrome-latest", tls_only=True) as proxy:
        print(f"Proxy running on {proxy.proxy_url}")

        with Session(proxy=proxy.proxy_url) as session:
            response = session.get("https://httpbin.org/get")
            print(f"Response status: {response.status_code}")

    print("Proxy automatically closed when exiting context\n")

def requests_integration_example():
    """Example code for integrating LocalProxy with the requests library."""
    print("=== Requests Library Integration Example ===\n")
    print("Example code for integrating LocalProxy with requests:\n")

    code = '''
from sensor import LocalProxy
import requests

proxy = LocalProxy(
    preset="chrome-latest",
    tls_only=True,  # Pass headers through, only apply TLS fingerprint
    port=8888
)

proxies = {
    "http": proxy.proxy_url,
    "https": proxy.proxy_url,
}

response = requests.get(
    "https://example.com",
    proxies=proxies,
    headers={
        "User-Agent": "Your-Custom-UA",
        "Accept": "text/html",
        "Proxy-Authorization": "HTTPCloak http://user:pass@rotating-proxy.brightdata.com:8080"
    }
)

print("Status:", response.status_code)
print("Body:", response.text)

proxy.close()
'''

    print(code)

def main():
    try:
        basic_local_proxy()
        tls_only_mode()
        per_request_proxy_rotation()
        with_default_upstream_proxy()
        proxy_statistics()
        context_manager_usage()
        requests_integration_example()

        print("=== Summary ===\n")
        print("LocalProxy Features:")
        print("  - Transparent TLS fingerprinting for any HTTP client")
        print("  - TLS-only mode for Playwright/Puppeteer integration")
        print("  - Per-request proxy rotation via Proxy-Authorization header")
        print("  - High-performance streaming (64KB buffers, ~3GB/s)")
        print("  - Connection statistics and monitoring")
        print("  - Context manager support for automatic cleanup")
    except Exception as e:
        print(f"Error: {e}")
        raise

if __name__ == "__main__":
    main()
