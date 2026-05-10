/**
 * Basic HTTP Requests with sensor
 *
 * This is the simplest example - perfect for beginners!
 *
 * What you'll learn:
 * - Making GET and POST requests
 * - Sending query parameters and headers
 * - Reading response data (status, body, JSON)
 * - Using different HTTP methods
 *
 * Requirements:
 *   npm install sensor
 *
 * Run:
 *   node 01_basic_requests.js
 */

const sensor = require("sensor");

async function main() {

  console.log("=".repeat(60));
  console.log("Example 1: Simple GET Request");
  console.log("-".repeat(60));

  let response = await sensor.get("https://httpbin.org/get");

  console.log(`Status Code: ${response.statusCode}`); // 200 = success
  console.log(`Protocol: ${response.protocol}`); // h2 = HTTP/2, h3 = HTTP/3
  console.log(`OK: ${response.ok}`); // true if status < 400

  console.log("\n" + "=".repeat(60));
  console.log("Example 2: GET with Query Parameters");
  console.log("-".repeat(60));

  response = await sensor.get("https://httpbin.org/get", {
    params: {
      search: "sensor",
      page: 1,
      limit: 10,
    },
  });

  console.log(`Status: ${response.statusCode}`);
  console.log(`Final URL: ${response.url}`); // Shows the full URL with params

  console.log("\n" + "=".repeat(60));
  console.log("Example 3: POST with JSON Body");
  console.log("-".repeat(60));

  response = await sensor.post("https://httpbin.org/post", {
    json: {
      name: "sensor",
      version: "1.5.0",
      features: ["fingerprinting", "http3", "async"],
    },
  });

  console.log(`Status: ${response.statusCode}`);

  const data = response.json();
  console.log("Server received:", data.json);

  console.log("\n" + "=".repeat(60));
  console.log("Example 4: POST with Form Data");
  console.log("-".repeat(60));

  response = await sensor.post("https://httpbin.org/post", {
    data: {
      username: "john_doe",
      password: "secret123",
      remember_me: "true",
    },
  });

  console.log(`Status: ${response.statusCode}`);
  const formData = response.json();
  console.log("Form data received:", formData.form);

  console.log("\n" + "=".repeat(60));
  console.log("Example 5: Custom Headers");
  console.log("-".repeat(60));

  response = await sensor.get("https://httpbin.org/headers", {
    headers: {
      "X-Custom-Header": "my-value",
      "X-Request-ID": "abc-123-xyz",
      "Accept-Language": "en-US,en;q=0.9",
    },
  });

  console.log(`Status: ${response.statusCode}`);
  const headersData = response.json();
  console.log(`Custom header received: ${headersData.headers["X-Custom-Header"]}`);
  console.log(`Request ID received: ${headersData.headers["X-Request-Id"]}`);

  console.log("\n" + "=".repeat(60));
  console.log("Example 6: Reading Response Data");
  console.log("-".repeat(60));

  response = await sensor.get("https://httpbin.org/json");

  console.log(`Status Code: ${response.statusCode}`);
  console.log(`OK (status < 400): ${response.ok}`);

  console.log(`Content-Type: ${response.headers["content-type"]}`);

  console.log(`Body as Buffer: ${response.content.length} bytes`);
  console.log(`Body as string: ${response.text.length} characters`);

  const jsonData = response.json();
  console.log(`JSON parsed successfully: ${typeof jsonData}`);

  console.log("\n" + "=".repeat(60));
  console.log("Example 7: Other HTTP Methods");
  console.log("-".repeat(60));

  response = await sensor.put("https://httpbin.org/put", {
    json: { updated: true },
  });
  console.log(`PUT: ${response.statusCode}`);

  response = await sensor.patch("https://httpbin.org/patch", {
    json: { field: "new_value" },
  });
  console.log(`PATCH: ${response.statusCode}`);

  response = await sensor.delete("https://httpbin.org/delete");
  console.log(`DELETE: ${response.statusCode}`);

  response = await sensor.head("https://httpbin.org/get");
  console.log(`HEAD: ${response.statusCode} (body length: ${response.content.length})`);

  response = await sensor.options("https://httpbin.org/get");
  console.log(`OPTIONS: ${response.statusCode}`);

  console.log("\n" + "=".repeat(60));
  console.log("Example 8: Error Handling");
  console.log("-".repeat(60));

  response = await sensor.get("https://httpbin.org/status/404");
  console.log(`404 Status: ${response.statusCode}, OK: ${response.ok}`);

  response = await sensor.get("https://httpbin.org/status/500");
  console.log(`500 Status: ${response.statusCode}, OK: ${response.ok}`);

  try {
    response = await sensor.get("https://httpbin.org/status/404");
    response.raiseForStatus(); // Throws HTTPCloakError for 4xx/5xx
  } catch (error) {
    console.log(`Caught error: ${error.message}`);
  }

  console.log("\n" + "=".repeat(60));
  console.log("All basic examples completed!");
  console.log("=".repeat(60));
  console.log(`
Next steps:
- Run 02_configure_and_presets.js to learn about browser presets
- Run 03_sessions_and_cookies.js to learn about sessions
- Run 06_async_concurrent.js to learn about concurrent requests
- Run 07_esm_example.mjs to see ES Modules syntax
`);
}

main().catch(console.error);
