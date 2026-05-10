#!/usr/bin/env python3
"""
New Features: Refresh, Local Address Binding, TLS Key Logging

This example demonstrates:
- refresh() - simulate browser page refresh (close connections, keep TLS cache)
- Local Address Binding - bind to specific local IP (IPv4 or IPv6)
- TLS Key Logging - write TLS keys for Wireshark decryption
"""

import os
import sensor

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
print("Example 1: Refresh (Browser Page Refresh)")
print("-" * 60)

session = sensor.Session(preset="chrome-latest", timeout=30)

r = session.get(TEST_URL)
trace = parse_trace(r.text)
print(f"First request: Protocol={r.protocol}, IP={trace.get('ip', 'N/A')}")

session.refresh()
print("Called refresh() - connections closed, TLS cache kept")

r = session.get(TEST_URL)
trace = parse_trace(r.text)
print(f"After refresh: Protocol={r.protocol}, IP={trace.get('ip', 'N/A')} (TLS resumption)")

session.close()

print("\n" + "=" * 60)
print("Example 2: TLS Key Logging")
print("-" * 60)

keylog_path = "/tmp/python_keylog_example.txt"

if os.path.exists(keylog_path):
    os.remove(keylog_path)

session = sensor.Session(
    preset="chrome-latest",
    timeout=30,
    key_log_file=keylog_path
)

r = session.get(TEST_URL)
print(f"Request completed: Protocol={r.protocol}")

session.close()

if os.path.exists(keylog_path):
    size = os.path.getsize(keylog_path)
    print(f"Key log file created: {keylog_path} ({size} bytes)")
    print("Use in Wireshark: Edit -> Preferences -> Protocols -> TLS -> Pre-Master-Secret log filename")
else:
    print("Key log file not found")

print("\n" + "=" * 60)
print("Example 3: Local Address Binding")
print("-" * 60)

print("""
Local address binding allows you to specify which local IP to use
for outgoing connections. This is essential for IPv6 rotation scenarios.

Usage:

session = sensor.Session(
    preset="chrome-latest",
    local_address="2001:db8::1"
)

session = sensor.Session(
    preset="chrome-latest",
    local_address="192.168.1.100"
)

Note: When local address is set, target IPs are filtered to match
the address family (IPv6 local -> only connects to IPv6 targets).

Example with your machine's IPs:
""")

print("\n" + "=" * 60)
print("New features examples completed!")
print("=" * 60)
