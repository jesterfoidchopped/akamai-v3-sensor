#!/usr/bin/env node
/**
 * Warmup & Fork: Browser-Like Page Load and Parallel Tab Simulation
 *
 * This example demonstrates:
 * - warmup() - simulate a real browser page load (HTML + subresources)
 * - fork(n)  - create parallel sessions sharing cookies and TLS cache (like browser tabs)
 */

const { Session } = require('sensor');

const TEST_URL = 'https://www.cloudflare.com/cdn-cgi/trace';

function parseTrace(body) {
    const result = {};
    for (const line of body.trim().split('\n')) {
        const idx = line.indexOf('=');
        if (idx !== -1) {
            result[line.slice(0, idx)] = line.slice(idx + 1);
        }
    }
    return result;
}

async function main() {
    console.log('='.repeat(60));
    console.log('Example 1: Warmup (Browser Page Load)');
    console.log('-'.repeat(60));

    let session = new Session({
        preset: 'chrome-latest',
        timeout: 30
    });

    session.warmup('https://www.cloudflare.com');
    console.log('Warmup complete - TLS tickets, cookies, and cache populated');

    let resp = await session.get(TEST_URL);
    let trace = parseTrace(resp.text);
    console.log(`Follow-up request: Protocol=${resp.protocol}, IP=${trace.ip || 'N/A'}`);

    session.close();

    console.log('\n' + '='.repeat(60));
    console.log('Example 2: Fork (Parallel Browser Tabs)');
    console.log('-'.repeat(60));

    session = new Session({
        preset: 'chrome-latest',
        timeout: 30
    });

    session.warmup('https://www.cloudflare.com');
    console.log('Parent session warmed up');

    const tabs = session.fork(3);
    console.log(`Forked into ${tabs.length} tabs`);

    const results = await Promise.all(
        tabs.map(async (tab, i) => {
            const r = await tab.get(TEST_URL);
            const t = parseTrace(r.text);
            return { index: i, protocol: r.protocol, ip: t.ip || 'N/A' };
        })
    );

    for (const { index, protocol, ip } of results) {
        console.log(`  Tab ${index}: Protocol=${protocol}, IP=${ip}`);
    }

    for (const tab of tabs) {
        tab.close();
    }
    session.close();

    console.log('\n' + '='.repeat(60));
    console.log('Example 3: Warmup + Fork (Recommended Pattern)');
    console.log('-'.repeat(60));

    console.log(`
The recommended pattern for parallel scraping:

1. Create one session
2. Warmup to establish TLS tickets and cookies
3. Fork into N parallel sessions
4. Use each fork for independent requests

    const session = new Session({ preset: "chrome-latest" });
    session.warmup("https://example.com");

    const tabs = session.fork(10);
    await Promise.all(
        tabs.map((tab, i) => tab.get(\`https://example.com/page/\${i}\`))
    );

All forks share the same TLS fingerprint, cookies, and TLS session
cache (for 0-RTT resumption), but have independent TCP/QUIC connections.
This looks exactly like a single browser with multiple tabs.
`);

    console.log('='.repeat(60));
    console.log('Warmup & Fork examples completed!');
    console.log('='.repeat(60));
}

main().catch(err => {
    console.error(err);
    process.exit(1);
});
