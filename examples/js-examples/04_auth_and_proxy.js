/**
 * Authentication and Proxy Usage
 *
 * This example demonstrates:
 * - Basic authentication
 * - Using proxies
 * - Timeout configuration
 * - Error handling
 *
 * Run: node 04_auth_and_proxy.js
 */

const sensor = require("sensor");

async function main() {
  console.log("=".repeat(60));
  console.log("Example 1: Basic Authentication");
  console.log("-".repeat(60));

  let r = await sensor.get("https://httpbin.org/basic-auth/user/pass", {
    auth: ["user", "pass"],
  });
  console.log(`Status: ${r.statusCode}`);
  console.log(`Authenticated: ${r.json().authenticated}`);
  console.log(`User: ${r.json().user}`);

  r = await sensor.get("https://httpbin.org/basic-auth/user/pass", {
    auth: ["wrong", "credentials"],
  });
  console.log(`\nWrong credentials - Status: ${r.statusCode}`);

  console.log("\n" + "=".repeat(60));
  console.log("Example 2: Global Auth Configuration");
  console.log("-".repeat(60));

  sensor.configure({
    preset: "chrome-latest",
    auth: ["user", "pass"],
  });

  r = await sensor.get("https://httpbin.org/basic-auth/user/pass");
  console.log(`Status: ${r.statusCode}`);
  console.log("Auth header sent automatically");

  sensor.configure({ preset: "chrome-latest" });

  console.log("\n" + "=".repeat(60));
  console.log("Example 3: Timeout Configuration");
  console.log("-".repeat(60));

  const session = new sensor.Session({ preset: "chrome-latest", timeout: 10 });

  try {
    r = await session.get("https://httpbin.org/delay/2");
    console.log(`2s delay - Status: ${r.statusCode} (completed)`);
  } catch (e) {
    console.log(`2s delay - Error: ${e.message}`);
  }

  session.close();

  console.log("\n" + "=".repeat(60));
  console.log("Example 4: Error Handling");
  console.log("-".repeat(60));

  r = await sensor.get("https://httpbin.org/status/404");
  console.log(`404 response - Status: ${r.statusCode}, OK: ${r.ok}`);

  try {
    r.raiseForStatus();
  } catch (e) {
    console.log(`raiseForStatus() raised: ${e.message}`);
  }

  r = await sensor.get("https://httpbin.org/status/500");
  console.log(`500 response - Status: ${r.statusCode}, OK: ${r.ok}`);

  console.log("\n" + "=".repeat(60));
  console.log("Example 5: Proxy Configuration (Reference)");
  console.log("-".repeat(60));

  console.log(`
const session = new sensor.Session({
  preset: "chrome-latest",
  proxy: "http://user:pass@proxy.example.com:8080"
});

sensor.configure({
  preset: "chrome-latest",
  proxy: "socks5://user:pass@proxy.example.com:1080"
});

const session2 = new sensor.Session({
  preset: "chrome-latest",
  proxy: "http://user:pass@proxy.example.com:8080",
  disableSpeculativeTls: true
});
`);

  console.log("=".repeat(60));
  console.log("Auth and proxy examples completed!");
  console.log("=".repeat(60));
}

main().catch(console.error);
