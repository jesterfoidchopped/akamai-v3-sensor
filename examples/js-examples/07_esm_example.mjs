/**
 * ESM (ES Modules) Example
 *
 * This example demonstrates using sensor with ES Modules syntax.
 * ES Modules use 'import' instead of 'require'.
 *
 * Note: This file uses .mjs extension to indicate it's an ES Module.
 * Alternatively, you can set "type": "module" in your package.json.
 *
 * Run: node 07_esm_example.mjs
 */

import sensor from "sensor";

import { Session, get, post, version, availablePresets, Preset } from "sensor";

console.log("=".repeat(60));
console.log("Example 1: Using Named Imports");
console.log("-".repeat(60));

console.log(`sensor version: ${version()}`);
console.log(`Available presets: ${availablePresets().slice(0, 5).join(", ")}...`);

console.log(`\nPreset constants:`);
console.log(`  Preset.CHROME_143 = "${Preset.CHROME_143}"`);
console.log(`  Preset.FIREFOX_133 = "${Preset.FIREFOX_133}"`);

console.log("\n" + "=".repeat(60));
console.log("Example 2: Module-Level Functions");
console.log("-".repeat(60));

const response = await get("https://httpbin.org/get");
console.log(`GET Status: ${response.statusCode}`);
console.log(`Protocol: ${response.protocol}`);

const postResponse = await post("https://httpbin.org/post", {
  json: { source: "ESM module", timestamp: new Date().toISOString() },
});
console.log(`POST Status: ${postResponse.statusCode}`);

console.log("\n" + "=".repeat(60));
console.log("Example 3: Session Class");
console.log("-".repeat(60));

const session = new Session({
  preset: Preset.CHROME_143,
  httpVersion: "h2",
});

const r1 = await session.get("https://httpbin.org/get");
console.log(`Session GET: ${r1.statusCode}`);

session.setCookie("esm_test", "hello_from_esm");
console.log(`Cookies:`, session.getCookies());

session.close();

console.log("\n" + "=".repeat(60));
console.log("Example 4: Default Import");
console.log("-".repeat(60));

const session2 = new sensor.Session({ preset: "chrome-latest" });
const r2 = await session2.get("https://httpbin.org/headers");
console.log(`Default import GET: ${r2.statusCode}`);
session2.close();

console.log("\n" + "=".repeat(60));
console.log("Example 5: Top-Level Await (ESM Feature)");
console.log("-".repeat(60));

const urls = ["https://httpbin.org/get", "https://httpbin.org/ip"];
const responses = await Promise.all(urls.map((url) => get(url)));
console.log(`Fetched ${responses.length} URLs concurrently`);
responses.forEach((r, i) => {
  console.log(`  ${urls[i].split("/").pop()}: ${r.statusCode}`);
});

console.log("\n" + "=".repeat(60));
console.log("ESM examples completed!");
console.log("=".repeat(60));
