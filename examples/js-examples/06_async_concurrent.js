/**
 * Async and Concurrent Requests
 *
 * This example demonstrates:
 * - Async GET and POST requests using promises
 * - Running multiple requests concurrently with Promise.all()
 * - Performance comparison: sequential vs concurrent
 * - Error handling in async context
 *
 * Why use async?
 * - Non-blocking: Your code can do other things while waiting for responses
 * - Concurrent: Multiple requests can run at the same time
 * - Performance: Much faster when making many requests
 *
 * Run: node 06_async_concurrent.js
 */

const sensor = require("sensor");

async function main() {
  console.log("=".repeat(60));
  console.log("Example 1: Basic Async Request");
  console.log("-".repeat(60));

  const session = new sensor.Session({ preset: "chrome-latest" });

  const response = await session.get("https://httpbin.org/get");
  console.log(`Status: ${response.statusCode}`);
  console.log(`Protocol: ${response.protocol}`);

  const postResponse = await session.post("https://httpbin.org/post", {
    json: { message: "Hello from async!", timestamp: Date.now() },
  });
  console.log(`POST Status: ${postResponse.statusCode}`);
  console.log(`Echoed data:`, postResponse.json().json);

  console.log("\n" + "=".repeat(60));
  console.log("Example 2: Concurrent Requests");
  console.log("-".repeat(60));

  const urls = [
    "https://httpbin.org/get",
    "https://httpbin.org/headers",
    "https://httpbin.org/user-agent",
    "https://httpbin.org/ip",
  ];

  console.log(`Fetching ${urls.length} URLs concurrently...`);
  const startTime = Date.now();

  const responses = await Promise.all(urls.map((url) => session.get(url)));

  const elapsed = Date.now() - startTime;
  console.log(`All ${responses.length} requests completed in ${elapsed}ms\n`);

  responses.forEach((r, i) => {
    const endpoint = urls[i].split("/").pop();
    console.log(`  ${endpoint.padEnd(12)} | Status: ${r.statusCode} | Protocol: ${r.protocol}`);
  });

  console.log("\n" + "=".repeat(60));
  console.log("Example 3: Sequential vs Concurrent Timing");
  console.log("-".repeat(60));

  const delayUrls = [
    "https://httpbin.org/delay/1",
    "https://httpbin.org/delay/1",
    "https://httpbin.org/delay/1",
  ];

  console.log("Sequential (one at a time)...");
  let start = Date.now();
  for (const url of delayUrls) {
    await session.get(url);
  }
  const sequentialTime = Date.now() - start;
  console.log(`  Time: ${sequentialTime}ms (expected: ~3000ms)`);

  console.log("\nConcurrent (all at once)...");
  start = Date.now();
  await Promise.all(delayUrls.map((url) => session.get(url)));
  const concurrentTime = Date.now() - start;
  console.log(`  Time: ${concurrentTime}ms (expected: ~1000ms)`);

  const speedup = (sequentialTime / concurrentTime).toFixed(1);
  console.log(`\n  Speedup: ${speedup}x faster with concurrent requests!`);

  console.log("\n" + "=".repeat(60));
  console.log("Example 4: Error Handling");
  console.log("-".repeat(60));

  try {
    const r = await session.get("https://httpbin.org/status/404");
    console.log(`404 response - Status: ${r.statusCode}, OK: ${r.ok}`);

    r.raiseForStatus();
  } catch (error) {
    console.log(`Caught error: ${error.message}`);
  }

  console.log("\nHandling mixed success/failure...");
  const mixedUrls = [
    "https://httpbin.org/get",
    "https://httpbin.org/status/500",
    "https://httpbin.org/json",
  ];

  const results = await Promise.allSettled(
    mixedUrls.map((url) => session.get(url))
  );

  results.forEach((result, i) => {
    const endpoint = mixedUrls[i].split("/").pop();
    if (result.status === "fulfilled") {
      console.log(`  ${endpoint}: Success (${result.value.statusCode})`);
    } else {
      console.log(`  ${endpoint}: Failed (${result.reason.message})`);
    }
  });

  console.log("\n" + "=".repeat(60));
  console.log("Example 5: Batched Requests (Rate Limiting)");
  console.log("-".repeat(60));

  const manyUrls = Array(10)
    .fill()
    .map((_, i) => `https://httpbin.org/get?id=${i + 1}`);

  const batchSize = 3;
  console.log(`Processing ${manyUrls.length} URLs in batches of ${batchSize}...`);

  const allResults = [];
  for (let i = 0; i < manyUrls.length; i += batchSize) {
    const batch = manyUrls.slice(i, i + batchSize);
    console.log(`  Batch ${Math.floor(i / batchSize) + 1}: Processing ${batch.length} URLs...`);

    const batchResults = await Promise.all(batch.map((url) => session.get(url)));
    allResults.push(...batchResults);

    if (i + batchSize < manyUrls.length) {
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
  }

  console.log(`\nCompleted all ${allResults.length} requests successfully!`);

  session.close();

  console.log("\n" + "=".repeat(60));
  console.log("Async examples completed!");
  console.log("=".repeat(60));
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
