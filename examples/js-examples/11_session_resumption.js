/**
 * Session Resumption (0-RTT)
 *
 * This example demonstrates TLS session resumption which dramatically
 * improves bot detection scores by making connections look like
 * returning visitors rather than new connections.
 *
 * Key concepts:
 * - First connection: Bot score ~43 (new TLS handshake)
 * - Resumed connection: Bot score ~99 (looks like returning visitor)
 * - Cross-domain warming: Session tickets work across same-infrastructure sites
 *
 * Run: node 11_session_resumption.js
 */

const sensor = require("sensor");
const fs = require("fs");

const SESSION_FILE = "session_state.json";

async function main() {
  console.log("=".repeat(60));
  console.log("Example 1: Save and Load Session (File)");
  console.log("-".repeat(60));

  let session;

  if (fs.existsSync(SESSION_FILE)) {
    console.log("Loading existing session...");
    session = sensor.Session.load(SESSION_FILE);
    console.log("Session loaded with TLS tickets!");
  } else {
    console.log("Creating new session...");
    session = new sensor.Session({ preset: "chrome-latest" });

    console.log("Warming up session...");
    const r = await session.get("https://cloudflare.com/cdn-cgi/trace");
    console.log(`Warmup complete - Protocol: ${r.protocol}`);
  }

  let r = await session.get("https://www.cloudflare.com/cdn-cgi/trace");
  console.log(`Request - Protocol: ${r.protocol}`);

  session.save(SESSION_FILE);
  console.log(`Session saved to ${SESSION_FILE}`);
  session.close();

  console.log("\n" + "=".repeat(60));
  console.log("Example 2: Marshal/Unmarshal Session (String)");
  console.log("-".repeat(60));

  session = new sensor.Session({ preset: "chrome-latest" });
  await session.get("https://cloudflare.com/");

  const sessionData = session.marshal();
  console.log(`Marshaled session: ${sessionData.length} bytes`);
  session.close();

  const restored = sensor.Session.unmarshal(sessionData);
  r = await restored.get("https://www.cloudflare.com/cdn-cgi/trace");
  console.log(`Restored session request - Protocol: ${r.protocol}`);
  restored.close();

  console.log("\n" + "=".repeat(60));
  console.log("Example 3: Cross-Domain Warming");
  console.log("-".repeat(60));

  session = new sensor.Session({ preset: "chrome-latest" });

  console.log("Warming up on cloudflare.com...");
  r = await session.get("https://cloudflare.com/cdn-cgi/trace");
  console.log(`Warmup - Protocol: ${r.protocol}`);

  console.log("\nUsing warmed session on cf.erisa.uk (CF-protected)...");
  r = await session.get("https://cf.erisa.uk/");
  const data = r.json();
  const botScore = data.botManagement?.score ?? "N/A";
  console.log(`Bot Score: ${botScore}`);
  console.log(`Protocol: ${r.protocol}`);

  session.close();

  console.log("\n" + "=".repeat(60));
  console.log("Example 4: Sync Operations");
  console.log("-".repeat(60));

  session = new sensor.Session({ preset: "chrome-latest" });

  session.getSync("https://cloudflare.com/cdn-cgi/trace");
  console.log("Warmup complete (sync)");

  session.save("sync_session.json");

  const syncSession = sensor.Session.load("sync_session.json");
  r = syncSession.getSync("https://cf.erisa.uk/");
  console.log(`Bot Score: ${r.json().botManagement?.score}`);

  syncSession.close();
  session.close();

  for (const f of [SESSION_FILE, "sync_session.json"]) {
    if (fs.existsSync(f)) fs.unlinkSync(f);
  }

  console.log("\n" + "=".repeat(60));
  console.log("Session resumption examples completed!");
  console.log("=".repeat(60));
}

main().catch(console.error);
