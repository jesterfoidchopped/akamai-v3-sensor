#!/usr/bin/env python3
"""
Warmup & Fork: Browser-Like Page Load and Parallel Tab Simulation

This example demonstrates:
- warmup() - simulate a real browser page load (HTML + subresources)
- fork(n)  - create parallel sessions sharing cookies and TLS cache (like browser tabs)
"""

import sensor
import threading

TEST_URL = "https://www.cloudflare.com/cdn-cgi/trace"

def parse_trace(body):
    """Parse cloudflare trace response."""
    result = {}
    for line in body.strip().split('\n'):
        if '=' in line:
            key, val = line.split('=', 1)
            result[key] = val
    return result

print("=" * 60)
print("Example 1: Warmup (Browser Page Load)")
print("-" * 60)

session = sensor.Session(preset="chrome-latest", timeout=30)

session.warmup("https://www.cloudflare.com")
print("Warmup complete - TLS tickets, cookies, and cache populated")

r = session.get(TEST_URL)
trace = parse_trace(r.text)
print(f"Follow-up request: Protocol={r.protocol}, IP={trace.get('ip', 'N/A')}")

session.close()

print("\n" + "=" * 60)
print("Example 2: Fork (Parallel Browser Tabs)")
print("-" * 60)

session = sensor.Session(preset="chrome-latest", timeout=30)

session.warmup("https://www.cloudflare.com")
print("Parent session warmed up")

tabs = session.fork(3)
print(f"Forked into {len(tabs)} tabs")

results = [None] * len(tabs)

def fetch(tab, index):
    r = tab.get(TEST_URL)
    trace = parse_trace(r.text)
    results[index] = (r.protocol, trace.get("ip", "N/A"))

threads = []
for i, tab in enumerate(tabs):
    t = threading.Thread(target=fetch, args=(tab, i))
    threads.append(t)
    t.start()

for t in threads:
    t.join()

for i, (proto, ip) in enumerate(results):
    print(f"  Tab {i}: Protocol={proto}, IP={ip}")

tabs[0].cookies = {"shared_cookie": "from_tab_0"}
print(f"\nCookie set in tab 0, visible in parent: "
      f"{'shared_cookie' in session.get_cookies()}")

for tab in tabs:
    tab.close()
session.close()

print("\n" + "=" * 60)
print("Example 3: Warmup + Fork (Recommended Pattern)")
print("-" * 60)

print("""
The recommended pattern for parallel scraping:

1. Create one session
2. Warmup to establish TLS tickets and cookies
3. Fork into N parallel sessions
4. Use each fork for independent requests

    session = sensor.Session(preset="chrome-latest")
    session.warmup("https://example.com")

    tabs = session.fork(10)
    for i, tab in enumerate(tabs):
        threading.Thread(
            target=lambda t, n: t.get(f"https://example.com/page/{n}"),
            args=(tab, i)
        ).start()

All forks share the same TLS fingerprint, cookies, and TLS session
cache (for 0-RTT resumption), but have independent TCP/QUIC connections.
This looks exactly like a single browser with multiple tabs.
""")

print("=" * 60)
print("Warmup & Fork examples completed!")
print("=" * 60)
