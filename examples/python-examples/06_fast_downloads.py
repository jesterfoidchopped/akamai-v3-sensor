#!/usr/bin/env python3
"""
High-Performance Downloads with sensor

This example demonstrates the fastest way to download files using sensor.

What you'll learn:
- Using get_fast() for maximum download speed
- Buffer pooling and memory efficiency
- When to use get_fast() vs get()
- Best practices for high-throughput scenarios

Performance comparison (100MB local file):
- get():      ~500-1000 MB/s (safe, copies data)
- get_fast(): ~5000 MB/s (zero-copy, uses memoryview)

Requirements:
    pip install sensor

Run:
    python 06_fast_downloads.py
"""

import time
import sensor

print("=" * 70)
print("sensor - High-Performance Downloads with get_fast()")
print("=" * 70)

print("\n[INFO] Understanding get_fast()")
print("-" * 50)
print("""
get_fast() is optimized for maximum download speed by:
1. Using pre-allocated buffer pools (no per-request allocation)
2. Returning memoryview instead of bytes (zero-copy)
3. Minimizing memory allocations

IMPORTANT: The memoryview in response.content may be reused by
subsequent get_fast() calls. Copy if you need to keep the data.
""")

session = sensor.Session(preset="chrome-latest")

print("\n[1] Basic get_fast() Usage")
print("-" * 50)

response = session.get_fast("https://httpbin.org/bytes/10240")

print(f"Status Code: {response.status_code}")
print(f"Protocol: {response.protocol}")
print(f"Content Type: {type(response.content)}")  # memoryview
print(f"Content Length: {len(response.content)} bytes")

first_10_bytes = bytes(response.content[:10])
print(f"First 10 bytes: {first_10_bytes.hex()}")

print("\n[2] Copy Data If You Need to Keep It")
print("-" * 50)

response = session.get_fast("https://httpbin.org/bytes/1024")

data_copy = bytes(response.content)
print(f"Copied {len(data_copy)} bytes to keep after next request")

response2 = session.get_fast("https://httpbin.org/bytes/1024")

print(f"data_copy still valid: {len(data_copy)} bytes")

print("\n[3] Process In Place (Most Efficient)")
print("-" * 50)

response = session.get_fast("https://httpbin.org/json")

import json
data = json.loads(response.content)
print(f"Parsed JSON with keys: {list(data.keys())}")

print("\n[4] Download Speed Comparison")
print("-" * 50)

test_url = "https://httpbin.org/bytes/102400"  # 100KB

session.get_fast(test_url)

iterations = 10
total_bytes = 0
start = time.perf_counter()
for _ in range(iterations):
    r = session.get_fast(test_url)
    total_bytes += len(r.content)
elapsed = time.perf_counter() - start

speed_fast = (total_bytes / (1024 * 1024)) / elapsed
print(f"get_fast(): {iterations} requests, {total_bytes/1024:.0f} KB")
print(f"           Time: {elapsed*1000:.0f}ms, Speed: {speed_fast:.1f} MB/s")

total_bytes = 0
start = time.perf_counter()
for _ in range(iterations):
    r = session.get(test_url)
    total_bytes += len(r.content)
elapsed = time.perf_counter() - start

speed_regular = (total_bytes / (1024 * 1024)) / elapsed
print(f"get():      {iterations} requests, {total_bytes/1024:.0f} KB")
print(f"           Time: {elapsed*1000:.0f}ms, Speed: {speed_regular:.1f} MB/s")

if speed_fast > speed_regular:
    print(f"\nget_fast() is {speed_fast/speed_regular:.1f}x faster!")

print("\n[5] When to Use get_fast() vs get()")
print("-" * 50)
print("""
USE get_fast() when:
- Downloading large files (>1MB)
- High-throughput scenarios (many requests)
- Processing data immediately (JSON parsing, writing to file)
- Memory efficiency is important

USE get() when:
- You need to store response.content for later
- Making occasional small requests
- Simpler code is preferred
- Thread safety is needed (get() returns independent copy)
""")

print("\n[6] Writing Downloaded Data to File")
print("-" * 50)

response = session.get_fast("https://httpbin.org/bytes/10240")

import tempfile
import os

with tempfile.NamedTemporaryFile(delete=False) as f:
    f.write(response.content)
    temp_path = f.name

file_size = os.path.getsize(temp_path)
print(f"Wrote {file_size} bytes to {temp_path}")
os.unlink(temp_path)

print("\n[7] get_fast() with Different Protocols")
print("-" * 50)

session_h2 = sensor.Session(preset="chrome-latest", http_version="h2")
response = session_h2.get_fast("https://cloudflare.com/cdn-cgi/trace")
print(f"HTTP/2: {len(response.content)} bytes, protocol: {response.protocol}")
session_h2.close()

session_h3 = sensor.Session(preset="chrome-latest", http_version="h3")
response = session_h3.get_fast("https://cloudflare.com/cdn-cgi/trace")
print(f"HTTP/3: {len(response.content)} bytes, protocol: {response.protocol}")
session_h3.close()

session.close()

print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)
print("""
get_fast() provides maximum download performance by:
1. Using pre-allocated buffer pools
2. Returning memoryview (zero-copy)
3. Minimizing memory allocations

Remember:
- Copy data with bytes(response.content) if you need to keep it
- memoryview is reused between calls
- Use for high-throughput and large file scenarios
""")
