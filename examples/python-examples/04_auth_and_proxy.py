#!/usr/bin/env python3
"""
Authentication and Proxy Usage

This example demonstrates:
- Basic authentication
- Using proxies
- Timeout configuration
- Error handling
"""

import sensor

print("=" * 60)
print("Example 1: Basic Authentication")
print("-" * 60)

r = sensor.get(
    "https://httpbin.org/basic-auth/user/pass",
    auth=("user", "pass")
)
print(f"Status: {r.status_code}")
print(f"Authenticated: {r.json().get('authenticated')}")
print(f"User: {r.json().get('user')}")

r = sensor.get(
    "https://httpbin.org/basic-auth/user/pass",
    auth=("wrong", "credentials")
)
print(f"\nWrong credentials - Status: {r.status_code}")

print("\n" + "=" * 60)
print("Example 2: Global Auth Configuration")
print("-" * 60)

sensor.configure(
    preset="chrome-latest",
    auth=("user", "pass"),
)

r = sensor.get("https://httpbin.org/basic-auth/user/pass")
print(f"Status: {r.status_code}")
print(f"Auth header sent automatically")

sensor.configure(preset="chrome-latest")

print("\n" + "=" * 60)
print("Example 3: Timeout Configuration")
print("-" * 60)

session = sensor.Session(preset="chrome-latest", timeout=10)

try:
    r = session.get("https://httpbin.org/delay/2")
    print(f"2s delay - Status: {r.status_code} (completed)")
except sensor.HTTPCloakError as e:
    print(f"2s delay - Error: {e}")

session.close()

print("\nPer-request timeout:")
session = sensor.Session(preset="chrome-latest", timeout=30)

try:
    r = session.get("https://httpbin.org/delay/1", timeout=5)
    print(f"1s delay with 5s timeout - Status: {r.status_code}")
except sensor.HTTPCloakError as e:
    print(f"Error: {e}")

session.close()

print("\n" + "=" * 60)
print("Example 4: Error Handling")
print("-" * 60)

r = sensor.get("https://httpbin.org/status/404")
print(f"404 response - Status: {r.status_code}, OK: {r.ok}")

try:
    r.raise_for_status()
except sensor.HTTPCloakError as e:
    print(f"raise_for_status() raised: {e}")

r = sensor.get("https://httpbin.org/status/500")
print(f"500 response - Status: {r.status_code}, OK: {r.ok}")

print("\n" + "=" * 60)
print("Example 5: Proxy Configuration (Reference)")
print("-" * 60)

print("""
session = sensor.Session(
    preset="chrome-latest",
    proxy="http://user:pass@proxy.example.com:8080"
)

sensor.configure(
    preset="chrome-latest",
    proxy="socks5://user:pass@proxy.example.com:1080"
)

session = sensor.Session(
    preset="chrome-latest",
    proxy="http://user:pass@proxy.example.com:8080",
    enable_speculative_tls=True
)
""")

print("=" * 60)
print("Auth and proxy examples completed!")
print("=" * 60)
