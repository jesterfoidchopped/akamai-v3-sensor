#!/usr/bin/env python3
"""
Basic HTTP Requests with sensor

This is the simplest example - perfect for beginners!

What you'll learn:
- Making GET and POST requests
- Sending query parameters and headers
- Reading response data (status, body, JSON)
- Using different HTTP methods

Requirements:
    pip install sensor

Run:
    python 01_basic_requests.py
"""

import sensor

print("=" * 60)
print("Example 1: Simple GET Request")
print("-" * 60)

response = sensor.get("https://httpbin.org/get")

print(f"Status Code: {response.status_code}")  # 200 = success
print(f"Protocol: {response.protocol}")         # h2 = HTTP/2, h3 = HTTP/3
print(f"OK: {response.ok}")                     # True if status < 400

print("\n" + "=" * 60)
print("Example 2: GET with Query Parameters")
print("-" * 60)

response = sensor.get(
    "https://httpbin.org/get",
    params={
        "search": "sensor",
        "page": 1,
        "limit": 10
    }
)

print(f"Status: {response.status_code}")
print(f"Final URL: {response.url}")  # Shows the full URL with params

print("\n" + "=" * 60)
print("Example 3: POST with JSON Body")
print("-" * 60)

response = sensor.post(
    "https://httpbin.org/post",
    json={
        "name": "sensor",
        "version": "1.5.0",
        "features": ["fingerprinting", "http3", "async"]
    }
)

print(f"Status: {response.status_code}")

data = response.json()
print(f"Server received: {data.get('json')}")

print("\n" + "=" * 60)
print("Example 4: POST with Form Data")
print("-" * 60)

response = sensor.post(
    "https://httpbin.org/post",
    data={
        "username": "john_doe",
        "password": "secret123",
        "remember_me": "true"
    }
)

print(f"Status: {response.status_code}")
data = response.json()
print(f"Form data received: {data.get('form')}")

print("\n" + "=" * 60)
print("Example 5: Custom Headers")
print("-" * 60)

response = sensor.get(
    "https://httpbin.org/headers",
    headers={
        "X-Custom-Header": "my-value",
        "X-Request-ID": "abc-123-xyz",
        "Accept-Language": "en-US,en;q=0.9"
    }
)

print(f"Status: {response.status_code}")
data = response.json()
print(f"Custom header received: {data['headers'].get('X-Custom-Header')}")
print(f"Request ID received: {data['headers'].get('X-Request-Id')}")

print("\n" + "=" * 60)
print("Example 6: Reading Response Data")
print("-" * 60)

response = sensor.get("https://httpbin.org/json")

print(f"Status Code: {response.status_code}")
print(f"OK (status < 400): {response.ok}")

print(f"Content-Type: {response.headers.get('content-type')}")

print(f"Body as bytes: {len(response.content)} bytes")
print(f"Body as string: {len(response.text)} characters")

json_data = response.json()
print(f"JSON parsed successfully: {type(json_data).__name__}")

print("\n" + "=" * 60)
print("Example 7: Other HTTP Methods")
print("-" * 60)

response = sensor.put(
    "https://httpbin.org/put",
    json={"updated": True}
)
print(f"PUT: {response.status_code}")

response = sensor.patch(
    "https://httpbin.org/patch",
    json={"field": "new_value"}
)
print(f"PATCH: {response.status_code}")

response = sensor.delete("https://httpbin.org/delete")
print(f"DELETE: {response.status_code}")

response = sensor.head("https://httpbin.org/get")
print(f"HEAD: {response.status_code} (body length: {len(response.content)})")

response = sensor.options("https://httpbin.org/get")
print(f"OPTIONS: {response.status_code}")

print("\n" + "=" * 60)
print("Example 8: Error Handling")
print("-" * 60)

response = sensor.get("https://httpbin.org/status/404")
print(f"404 Status: {response.status_code}, OK: {response.ok}")

response = sensor.get("https://httpbin.org/status/500")
print(f"500 Status: {response.status_code}, OK: {response.ok}")

try:
    response = sensor.get("https://httpbin.org/status/404")
    response.raise_for_status()  # Raises HTTPCloakError for 4xx/5xx
except sensor.HTTPCloakError as e:
    print(f"Caught error: {e}")

print("\n" + "=" * 60)
print("All basic examples completed!")
print("=" * 60)
print("""
Next steps:
- Run 02_configure_and_presets.py to learn about browser presets
- Run 03_sessions_and_cookies.py to learn about sessions
- Run 05_async_requests.py to learn about concurrent requests
""")
