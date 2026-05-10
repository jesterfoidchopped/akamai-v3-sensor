/**
 * Runtime Proxy Switching
 *
 * This example demonstrates:
 * - Switching proxies mid-session without creating new sessions
 * - Split proxy configuration (different proxies for TCP and UDP)
 * - Getting current proxy configuration
 * - H2 and H3 proxy switching
 */

const sensor = require("sensor");

const TEST_URL = "https://www.cloudflare.com/cdn-cgi/trace";

function parseTrace(body) {
  const result = {};
  for (const line of body.trim().split("\n")) {
    const idx = line.indexOf("=");
    if (idx !== -1) {
      result[line.slice(0, idx)] = line.slice(idx + 1);
    }
  }
  return result;
}

async function main() {
  console.log("=".repeat(60));
  console.log("Example 1: Basic Proxy Switching");
  console.log("-".repeat(60));

  const session = new sensor.Session({ preset: "chrome-latest" });

  let r = await session.get(TEST_URL);
  let trace = parseTrace(r.text);
  console.log("Direct connection:");
  console.log(`  Protocol: ${r.protocol}, IP: ${trace.ip}, Colo: ${trace.colo}`);

  session.close();

  console.log("\n" + "=".repeat(60));
  console.log("Example 2: Getting Current Proxy Configuration");
  console.log("-".repeat(60));

  const session2 = new sensor.Session({ preset: "chrome-latest" });

  console.log(`Initial proxy: '${session2.getProxy()}' (empty = direct)`);
  console.log(`TCP proxy: '${session2.getTcpProxy()}'`);
  console.log(`UDP proxy: '${session2.getUdpProxy()}'`);

  console.log(`Proxy (via property): '${session2.proxy}'`);

  session2.close();

  console.log("\n" + "=".repeat(60));
  console.log("Example 3: Split Proxy Configuration (TCP vs UDP)");
  console.log("-".repeat(60));

  console.log(`

const session = new sensor.Session({ preset: "chrome-latest" });

session.setTcpProxy("http://tcp-proxy.example.com:8080");

session.setUdpProxy("socks5://udp-proxy.example.com:1080");

console.log(\`TCP proxy: \${session.getTcpProxy()}\`);
console.log(\`UDP proxy: \${session.getUdpProxy()}\`);
`);

  console.log("\n" + "=".repeat(60));
  console.log("Example 4: HTTP/3 Proxy Switching");
  console.log("-".repeat(60));

  console.log(`

const session = new sensor.Session({ preset: "chrome-latest", httpVersion: "h3" });

let r = await session.get("https://example.com");
console.log(\`Direct: \${r.protocol}\`);

session.setUdpProxy("socks5://user:pass@proxy.example.com:1080");
r = await session.get("https://example.com");
console.log(\`Via SOCKS5: \${r.protocol}\`);

session.setUdpProxy("https://user:pass@brd.superproxy.io:10001");
r = await session.get("https://example.com");
console.log(\`Via MASQUE: \${r.protocol}\`);
`);

  console.log("\n" + "=".repeat(60));
  console.log("Example 5: Proxy Rotation Pattern");
  console.log("-".repeat(60));

  console.log(`

const proxies = [
  "http://proxy1.example.com:8080",
  "http://proxy2.example.com:8080",
  "http://proxy3.example.com:8080",
];

const session = new sensor.Session({ preset: "chrome-latest" });

for (let i = 0; i < proxies.length; i++) {
  session.setProxy(proxies[i]);
  const r = await session.get("https://api.ipify.org");
  console.log(\`Request \${i + 1} via \${proxies[i]}: IP = \${r.text}\`);
}

session.close();
`);

  console.log("\n" + "=".repeat(60));
  console.log("Proxy switching examples completed!");
  console.log("=".repeat(60));
}

main().catch(console.error);
