/**
 * Configuration and Browser Presets
 *
 * This example demonstrates:
 * - Using configure() for global defaults
 * - Different browser presets
 * - Forcing HTTP versions
 * - Header order customization
 *
 * Run: node 02_configure_and_presets.js
 */

const sensor = require("sensor");

async function main() {
  console.log("=".repeat(60));
  console.log("Example 1: Configure Global Defaults");
  console.log("-".repeat(60));

  sensor.configure({
    preset: "chrome-latest-linux",
    headers: { "Accept-Language": "en-US,en;q=0.9" },
    timeout: 30,
  });

  let r = await sensor.get("https://www.cloudflare.com/cdn-cgi/trace");
  console.log(`Protocol: ${r.protocol}`);
  console.log("First few lines of trace:");
  r.text
    .split("\n")
    .slice(0, 5)
    .forEach((line) => console.log(`  ${line}`));

  console.log("\n" + "=".repeat(60));
  console.log("Example 2: Different Browser Presets");
  console.log("-".repeat(60));

  const presets = [
    "chrome-latest",
    "chrome-latest-windows",
    "chrome-latest-linux",
    "chrome-143",
    "firefox-133",
    "safari-18",
  ];

  for (const preset of presets) {
    const session = new sensor.Session({ preset });
    const r = await session.get("https://www.cloudflare.com/cdn-cgi/trace");

    const trace = {};
    r.text.split("\n").forEach((line) => {
      const [key, value] = line.split("=");
      if (key && value) trace[key] = value;
    });

    console.log(
      `${preset.padEnd(25)} | Protocol: ${r.protocol.padEnd(5)} | http=${trace.http || "N/A"}`
    );
    session.close();
  }

  console.log("\n" + "=".repeat(60));
  console.log("Example 3: Force HTTP Versions");
  console.log("-".repeat(60));

  const httpVersions = ["auto", "h1", "h2", "h3"];

  for (const version of httpVersions) {
    const session = new sensor.Session({
      preset: "chrome-latest",
      httpVersion: version,
    });

    try {
      const r = await session.get("https://www.cloudflare.com/cdn-cgi/trace");
      const trace = {};
      r.text.split("\n").forEach((line) => {
        const [key, value] = line.split("=");
        if (key && value) trace[key] = value;
      });

      console.log(
        `httpVersion=${version.padEnd(5)} | Actual Protocol: ${r.protocol.padEnd(5)} | http=${trace.http || "N/A"}`
      );
    } catch (e) {
      console.log(`httpVersion=${version.padEnd(5)} | Error: ${e.message}`);
    } finally {
      session.close();
    }
  }

  console.log("\n" + "=".repeat(60));
  console.log("Example 4: List Available Presets");
  console.log("-".repeat(60));

  const availablePresets = sensor.availablePresets();
  console.log("Available presets:");
  availablePresets.forEach((preset) => console.log(`  - ${preset}`));

  console.log(`\nsensor version: ${sensor.version()}`);

  console.log("\n" + "=".repeat(60));
  console.log("Example 5: Header Order Customization");
  console.log("-".repeat(60));

  const session = new sensor.Session({ preset: "chrome-latest" });

  const defaultOrder = session.getHeaderOrder();
  console.log(`Default header order (${defaultOrder.length} headers):`);
  defaultOrder.slice(0, 5).forEach((header, i) => {
    console.log(`  ${i + 1}. ${header}`);
  });
  console.log(`  ... and ${defaultOrder.length - 5} more`);

  const customOrder = ["accept", "user-agent", "sec-ch-ua", "accept-language", "accept-encoding"];
  session.setHeaderOrder(customOrder);
  console.log(`\nCustom order set: ${JSON.stringify(session.getHeaderOrder())}`);

  const resp = await session.get("https://httpbin.org/headers");
  console.log(`Request with custom order - Status: ${resp.statusCode}, Protocol: ${resp.protocol}`);

  session.setHeaderOrder([]);
  const resetOrder = session.getHeaderOrder();
  console.log(`Reset to default (${resetOrder.length} headers): ${JSON.stringify(resetOrder.slice(0, 3))}...`);

  session.close();

  console.log("\n" + "=".repeat(60));
  console.log("Configuration examples completed!");
  console.log("=".repeat(60));
}

main().catch(console.error);
