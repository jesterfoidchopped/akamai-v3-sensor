/**
 * Tweak Specific Fingerprint Values
 *
 * For most users, picking a built-in preset (chrome-latest, firefox-148, ...)
 * is enough — the wire bytes already match real browsers. This example is
 * for power users who want to tweak ONE OR TWO specific fingerprint values
 * while inheriting everything else from a built-in preset.
 *
 * The recipe:
 *   1. describePreset(name)         → JSON of all fingerprint fields
 *   2. JSON.parse + edit            → standard object mutation
 *   3. loadPresetFromJSON(json)     → registers under a new name
 *   4. new Session({preset: name})  → uses your customized version
 *
 * Why this works for any fingerprint field:
 * - describePreset() emits ALL effective values (including inherited
 *   defaults like the per-resource-type priority table). Whatever you see
 *   in the output is editable.
 * - The mutated JSON round-trips byte-equal: same fingerprint mechanics,
 *   just the values you changed.
 * - Composes naturally: priority + headers + JA3 + akamai + settings can
 *   all be tweaked in one pass.
 *
 * Run:
 *   node 18_tweak_fingerprint.js
 */

const {
  Session,
  describePreset,
  loadPresetFromJSON,
  unregisterPreset,
} = require("sensor");

async function main() {

  console.log("=".repeat(60));
  console.log("Recipe 1: Bump image priority from u=2 (183) to u=1 (220)");
  console.log("-".repeat(60));

  {
    const p = JSON.parse(describePreset("chrome-147-windows"));
    p.preset.name = "chrome-147-img-bumped";
    p.preset.http2.priority_table.image = {
      urgency: 1,
      incremental: true,
      emit_header: true,
    };
    loadPresetFromJSON(JSON.stringify(p));

    const session = new Session({ preset: "chrome-147-img-bumped" });
    try {
      const response = await session.get("https://tls.peet.ws/api/all", {
        headers: { "Sec-Fetch-Dest": "image" },
      });
      const sent = response.json()?.http2?.sent_frames ?? [];
      const headersFrame = sent.find((f) => f.frame_type === "HEADERS");
      if (headersFrame) {
        const priority = headersFrame.priority || {};
        console.log(
          `H2 frame priority: weight=${priority.weight} exclusive=${priority.exclusive}`
        );
        console.log("Expected weight=220 (u=1) instead of 183 (u=2)");
      }
    } finally {
      session.close();
    }
  }

  console.log("\n" + "=".repeat(60));
  console.log("Recipe 2: Append a header to the HPACK header order");
  console.log("-".repeat(60));

  {
    const p = JSON.parse(describePreset("chrome-147-windows"));
    p.preset.name = "chrome-147-with-tracking-header";
    const order = p.preset.http2.hpack_header_order;
    order.splice(order.indexOf("priority"), 0, "x-tracking-id");
    loadPresetFromJSON(JSON.stringify(p));
    console.log(`New header order:\n  ${order.join(", ")}`);
  }

  console.log("\n" + "=".repeat(60));
  console.log("Recipe 3: Build a preset from a peet.ws capture");
  console.log("-".repeat(60));

  const PEET_JA3 =
    "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172" +
    "-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-65037,29-23-24,0";
  const PEET_AKAMAI = "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p";

  {
    const p = JSON.parse(describePreset("chrome-147-windows"));
    p.preset.name = "from-peet-capture";
    p.preset.tls = { ja3: PEET_JA3 };
    p.preset.http2.akamai = PEET_AKAMAI;
    loadPresetFromJSON(JSON.stringify(p));

    const session = new Session({ preset: "from-peet-capture" });
    try {
      const response = await session.get("https://tls.peet.ws/api/tls");
      const data = response.json();
      console.log(`JA3 hash:  ${data?.tls?.ja3_hash ?? "N/A"}`);
      console.log(`JA3 sent matches PEET_JA3: ${data?.tls?.ja3 === PEET_JA3}`);
    } finally {
      session.close();
    }
  }

  console.log("\n" + "=".repeat(60));
  console.log("Recipe 4: Unregister custom presets");
  console.log("-".repeat(60));

  for (const name of [
    "chrome-147-img-bumped",
    "chrome-147-with-tracking-header",
    "from-peet-capture",
  ]) {
    unregisterPreset(name);
    console.log(`Unregistered: ${name}`);
  }

  console.log("\n" + "=".repeat(60));
  console.log("Summary");
  console.log("=".repeat(60));
  console.log(`
The describePreset → edit → loadPresetFromJSON workflow lets you tweak ANY
fingerprint value while inheriting the rest. Common edit points:

    p.preset.http2.priority_table[dest]    per-resource priorities
    p.preset.http2.hpack_header_order      HPACK encoding order
    p.preset.http2.settings_order          SETTINGS frame ID order
    p.preset.http2.pseudo_order            HTTP/2 pseudo-headers
    p.preset.http2.akamai                  single-string override
    p.preset.http3                         HTTP/3 / QUIC params
    p.preset.tls.ja3                       JA3 string
    p.preset.tcp                           TCP/IP fingerprint
    p.preset.headers.values                static header values
    p.preset.headers.order                 request header order

Print describePreset(name) once to see the full editable surface.
`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
