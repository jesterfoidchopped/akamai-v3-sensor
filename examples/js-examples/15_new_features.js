#!/usr/bin/env node
/**
 * New Features: Refresh, Local Address Binding, TLS Key Logging
 *
 * This example demonstrates:
 * - refresh() - simulate browser page refresh (close connections, keep TLS cache)
 * - Local Address Binding - bind to specific local IP (IPv4 or IPv6)
 * - TLS Key Logging - write TLS keys for Wireshark decryption
 */

const fs = require('fs');
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
    console.log('Example 1: Refresh (Browser Page Refresh)');
    console.log('-'.repeat(60));

    let session = new Session({
        preset: 'chrome-latest',
        timeout: 30
    });

    let resp = await session.get(TEST_URL);
    let trace = parseTrace(resp.text);
    console.log(`First request: Protocol=${resp.protocol}, IP=${trace.ip || 'N/A'}`);

    session.refresh();
    console.log('Called refresh() - connections closed, TLS cache kept');

    resp = await session.get(TEST_URL);
    trace = parseTrace(resp.text);
    console.log(`After refresh: Protocol=${resp.protocol}, IP=${trace.ip || 'N/A'} (TLS resumption)`);

    session.close();

    console.log('\n' + '='.repeat(60));
    console.log('Example 2: TLS Key Logging');
    console.log('-'.repeat(60));

    const keylogPath = '/tmp/nodejs_keylog_example.txt';

    if (fs.existsSync(keylogPath)) {
        fs.unlinkSync(keylogPath);
    }

    session = new Session({
        preset: 'chrome-latest',
        timeout: 30,
        keyLogFile: keylogPath
    });

    resp = await session.get(TEST_URL);
    console.log(`Request completed: Protocol=${resp.protocol}`);

    session.close();

    if (fs.existsSync(keylogPath)) {
        const stats = fs.statSync(keylogPath);
        console.log(`Key log file created: ${keylogPath} (${stats.size} bytes)`);
        console.log('Use in Wireshark: Edit -> Preferences -> Protocols -> TLS -> Pre-Master-Secret log filename');
    } else {
        console.log('Key log file not found');
    }

    console.log('\n' + '='.repeat(60));
    console.log('Example 3: Local Address Binding');
    console.log('-'.repeat(60));

    console.log(`
Local address binding allows you to specify which local IP to use
for outgoing connections. This is essential for IPv6 rotation scenarios.

Usage:

const session = new Session({
    preset: 'chrome-latest',
    localAddress: '2001:db8::1'
});

const session = new Session({
    preset: 'chrome-latest',
    localAddress: '192.168.1.100'
});

Note: When local address is set, target IPs are filtered to match
the address family (IPv6 local -> only connects to IPv6 targets).

Example with your machine's IPs:
`);

    console.log('\n' + '='.repeat(60));
    console.log('New features examples completed!');
    console.log('='.repeat(60));
}

main().catch(err => {
    console.error(err);
    process.exit(1);
});
