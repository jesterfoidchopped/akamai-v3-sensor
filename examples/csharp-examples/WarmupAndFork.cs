/**
 * Warmup & Fork: Browser-Like Page Load and Parallel Tab Simulation
 *
 * This example demonstrates:
 * - Warmup() - simulate a real browser page load (HTML + subresources)
 * - Fork(n)  - create parallel sessions sharing cookies and TLS cache (like browser tabs)
 */

using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Sensor;

class WarmupAndFork
{
    const string TEST_URL = "https://www.cloudflare.com/cdn-cgi/trace";

    static Dictionary<string, string> ParseTrace(string body)
    {
        var result = new Dictionary<string, string>();
        foreach (var line in body.Trim().Split('\n'))
        {
            var idx = line.IndexOf('=');
            if (idx != -1)
            {
                result[line.Substring(0, idx)] = line.Substring(idx + 1);
            }
        }
        return result;
    }

    static async Task Main()
    {
        Console.WriteLine(new string('=', 60));
        Console.WriteLine("Example 1: Warmup (Browser Page Load)");
        Console.WriteLine(new string('-', 60));

        using (var session = new Session(preset: "chrome-latest", timeout: 30))
        {
            session.Warmup("https://www.cloudflare.com");
            Console.WriteLine("Warmup complete - TLS tickets, cookies, and cache populated");

            var resp = session.Get(TEST_URL);
            var trace = ParseTrace(resp.Text);
            trace.TryGetValue("ip", out var ip);
            Console.WriteLine($"Follow-up request: Protocol={resp.Protocol}, IP={ip ?? "N/A"}");
        }

        Console.WriteLine();
        Console.WriteLine(new string('=', 60));
        Console.WriteLine("Example 2: Fork (Parallel Browser Tabs)");
        Console.WriteLine(new string('-', 60));

        using (var session = new Session(preset: "chrome-latest", timeout: 30))
        {
            session.Warmup("https://www.cloudflare.com");
            Console.WriteLine("Parent session warmed up");

            var tabs = session.Fork(3);
            Console.WriteLine($"Forked into {tabs.Length} tabs");

            var tasks = new Task<(int Index, string Protocol, string Ip)>[tabs.Length];
            for (int i = 0; i < tabs.Length; i++)
            {
                var tabIndex = i;
                var tab = tabs[i];
                tasks[i] = Task.Run(() =>
                {
                    var r = tab.Get(TEST_URL);
                    var t = ParseTrace(r.Text);
                    t.TryGetValue("ip", out var tabIp);
                    return (tabIndex, r.Protocol, tabIp ?? "N/A");
                });
            }

            var results = await Task.WhenAll(tasks);
            foreach (var (index, protocol, tabIp) in results)
            {
                Console.WriteLine($"  Tab {index}: Protocol={protocol}, IP={tabIp}");
            }

            foreach (var tab in tabs)
            {
                tab.Dispose();
            }
        }

        Console.WriteLine();
        Console.WriteLine(new string('=', 60));
        Console.WriteLine("Example 3: Warmup + Fork (Recommended Pattern)");
        Console.WriteLine(new string('-', 60));

        Console.WriteLine(@"
The recommended pattern for parallel scraping:

1. Create one session
2. Warmup to establish TLS tickets and cookies
3. Fork into N parallel sessions
4. Use each fork for independent requests

    using var session = new Session(preset: ""chrome-latest"");
    session.Warmup(""https://example.com"");

    var tabs = session.Fork(10);
    var tasks = tabs.Select((tab, i) =>
        Task.Run(() => tab.Get($""https://example.com/page/{i}""))
    );
    await Task.WhenAll(tasks);

All forks share the same TLS fingerprint, cookies, and TLS session
cache (for 0-RTT resumption), but have independent TCP/QUIC connections.
This looks exactly like a single browser with multiple tabs.
");

        Console.WriteLine(new string('=', 60));
        Console.WriteLine("Warmup & Fork examples completed!");
        Console.WriteLine(new string('=', 60));
    }
}
