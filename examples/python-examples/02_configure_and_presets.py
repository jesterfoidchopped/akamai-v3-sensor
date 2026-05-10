#!/usr/bin/env python3
"""
Configuration and Browser Presets

This example demonstrates:
- Using configure() for global defaults
- Different browser presets
- Forcing HTTP versions
- Header order customization
"""

import sensor

print("=" * 60)
print("Example 1: Configure Global Defaults")
print("-" * 60)

sensor.configure(
    preset="chrome-latest-linux",
    headers={"Accept-Language": "en-US,en;q=0.9"},
    timeout=30,
)

r = sensor.get("https://www.cloudflare.com/cdn-cgi/trace")
print(f"Protocol: {r.protocol}")
print(f"First few lines of trace:")
for line in r.text.split("\n")[:5]:
    print(f"  {line}")

print("\n" + "=" * 60)
print("Example 2: Different Browser Presets")
print("-" * 60)

presets = [
    "chrome-latest",
    "chrome-latest-windows",
    "chrome-latest-linux",
    "chrome-143",
    "firefox-133",
    "safari-18",
]

for preset in presets:
    session = sensor.Session(preset=preset)
    r = session.get("https://www.cloudflare.com/cdn-cgi/trace")

    trace = dict(line.split("=", 1) for line in r.text.strip().split("\n") if "=" in line)
    print(f"{preset:25} | Protocol: {r.protocol:5} | http={trace.get('http', 'N/A')}")
    session.close()

print("\n" + "=" * 60)
print("Example 3: Force HTTP Versions")
print("-" * 60)

http_versions = ["auto", "h1", "h2", "h3"]

for version in http_versions:
    session = sensor.Session(preset="chrome-latest", http_version=version)
    try:
        r = session.get("https://www.cloudflare.com/cdn-cgi/trace")
        trace = dict(line.split("=", 1) for line in r.text.strip().split("\n") if "=" in line)
        print(f"http_version={version:5} | Actual Protocol: {r.protocol:5} | http={trace.get('http', 'N/A')}")
    except Exception as e:
        print(f"http_version={version:5} | Error: {e}")
    finally:
        session.close()

print("\n" + "=" * 60)
print("Example 4: List Available Presets")
print("-" * 60)

presets = sensor.available_presets()
print("Available presets:")
for preset in presets:
    print(f"  - {preset}")

print(f"\nsensor version: {sensor.version()}")

print("\n" + "=" * 60)
print("Example 5: Header Order Customization")
print("-" * 60)

session = sensor.Session(preset="chrome-latest")

default_order = session.get_header_order()
print(f"Default header order ({len(default_order)} headers):")
for i, header in enumerate(default_order[:5]):
    print(f"  {i+1}. {header}")
print(f"  ... and {len(default_order) - 5} more")

custom_order = ["accept", "user-agent", "sec-ch-ua", "accept-language", "accept-encoding"]
session.set_header_order(custom_order)
print(f"\nCustom order set: {session.get_header_order()}")

r = session.get("https://httpbin.org/headers")
print(f"Request with custom order - Status: {r.status_code}, Protocol: {r.protocol}")

session.set_header_order([])
reset_order = session.get_header_order()
print(f"Reset to default ({len(reset_order)} headers): {reset_order[:3]}...")

session.close()

print("\n" + "=" * 60)
print("Configuration examples completed!")
print("=" * 60)
