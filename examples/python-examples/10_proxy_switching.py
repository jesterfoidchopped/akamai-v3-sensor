#!/usr/bin/env python3
"""
Runtime Proxy Switching

This example demonstrates:
- Switching proxies mid-session without creating new sessions
- Split proxy configuration (different proxies for TCP and UDP)
- Getting current proxy configuration
- H2 and H3 proxy switching
"""

import sensor

TEST_URL = "https://www.cloudflare.com/cdn-cgi/trace"

def parse_trace(body):
    """Parse cloudflare trace response to get IP and colo."""
    result = {}
    for line in body.strip().split('\n'):
        if '=' in line:
            key, val = line.split('=', 1)
            result[key] = val
    return result

print("=" * 60)
print("Example 1: Basic Proxy Switching")
print("-" * 60)

session = sensor.Session(preset="chrome-latest")

r = session.get(TEST_URL)
trace = parse_trace(r.text)
print(f"Direct connection:")
print(f"  Protocol: {r.protocol}, IP: {trace.get('ip', 'N/A')}, Colo: {trace.get('colo', 'N/A')}")

session.close()

print("\n" + "=" * 60)
print("Example 2: Getting Current Proxy Configuration")
print("-" * 60)

session = sensor.Session(preset="chrome-latest")

print(f"Initial proxy: '{session.get_proxy()}' (empty = direct)")
print(f"TCP proxy: '{session.get_tcp_proxy()}'")
print(f"UDP proxy: '{session.get_udp_proxy()}'")

session.close()

print("\n" + "=" * 60)
print("Example 3: Split Proxy Configuration (TCP vs UDP)")
print("-" * 60)

print("""

session = sensor.Session(preset="chrome-latest")

session.set_tcp_proxy("http://tcp-proxy.example.com:8080")

session.set_udp_proxy("socks5://udp-proxy.example.com:1080")

print(f"TCP proxy: {session.get_tcp_proxy()}")
print(f"UDP proxy: {session.get_udp_proxy()}")
""")

print("\n" + "=" * 60)
print("Example 4: HTTP/3 Proxy Switching")
print("-" * 60)

print("""

session = sensor.Session(preset="chrome-latest", http_version="h3")

r = session.get("https://example.com")
print(f"Direct: {r.protocol}")

session.set_udp_proxy("socks5://user:pass@proxy.example.com:1080")
r = session.get("https://example.com")
print(f"Via SOCKS5: {r.protocol}")

session.set_udp_proxy("https://user:pass@brd.superproxy.io:10001")
r = session.get("https://example.com")
print(f"Via MASQUE: {r.protocol}")
""")

print("\n" + "=" * 60)
print("Example 5: Proxy Rotation Pattern")
print("-" * 60)

print("""

proxies = [
    "http://proxy1.example.com:8080",
    "http://proxy2.example.com:8080",
    "http://proxy3.example.com:8080",
]

session = sensor.Session(preset="chrome-latest")

for i, proxy in enumerate(proxies):
    session.set_proxy(proxy)
    r = session.get("https://api.ipify.org")
    print(f"Request {i+1} via {proxy}: IP = {r.text}")

session.close()
""")

print("\n" + "=" * 60)
print("Proxy switching examples completed!")
print("=" * 60)
