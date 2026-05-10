/**
 * New Features: Refresh, Local Address Binding, TLS Key Logging
 *
 * This example demonstrates:
 * - Refresh() - simulate browser page refresh (close connections, keep TLS cache)
 * - Local Address Binding - bind to specific local IP (IPv4 or IPv6)
 * - TLS Key Logging - write TLS keys for Wireshark decryption
 */

using System;
using System.IO;
using System.Collections.Generic;
using Sensor;

class NewFeatures
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

    static void Main()
    {
        Console.WriteLine(new string('=', 60));
        Console.WriteLine("Example 1: Refresh (Browser Page Refresh)");
        Console.WriteLine(new string('-', 60));

        using (var session = new Session(preset: "chrome-latest", timeout: 30))
        {
            var resp = session.Get(TEST_URL);
            var trace = ParseTrace(resp.Text);
            trace.TryGetValue("ip", out var ip);
            Console.WriteLine($"First request: Protocol={resp.Protocol}, IP={ip ?? "N/A"}");

            session.Refresh();
            Console.WriteLine("Called Refresh() - connections closed, TLS cache kept");

            resp = session.Get(TEST_URL);
            trace = ParseTrace(resp.Text);
            trace.TryGetValue("ip", out ip);
            Console.WriteLine($"After refresh: Protocol={resp.Protocol}, IP={ip ?? "N/A"} (TLS resumption)");
        }

        Console.WriteLine();
        Console.WriteLine(new string('=', 60));
        Console.WriteLine("Example 2: TLS Key Logging");
        Console.WriteLine(new string('-', 60));

        var keylogPath = "/tmp/csharp_keylog_example.txt";

        if (File.Exists(keylogPath))
            File.Delete(keylogPath);

        using (var session = new Session(
            preset: "chrome-latest",
            timeout: 30,
            keyLogFile: keylogPath))
        {
            var resp = session.Get(TEST_URL);
            Console.WriteLine($"Request completed: Protocol={resp.Protocol}");
        }

        if (File.Exists(keylogPath))
        {
            var info = new FileInfo(keylogPath);
            Console.WriteLine($"Key log file created: {keylogPath} ({info.Length} bytes)");
            Console.WriteLine("Use in Wireshark: Edit -> Preferences -> Protocols -> TLS -> Pre-Master-Secret log filename");
        }
        else
        {
            Console.WriteLine("Key log file not found");
        }

        Console.WriteLine();
        Console.WriteLine(new string('=', 60));
        Console.WriteLine("Example 3: Local Address Binding");
        Console.WriteLine(new string('-', 60));

        Console.WriteLine(@"
Local address binding allows you to specify which local IP to use
for outgoing connections. This is essential for IPv6 rotation scenarios.

Usage:

using var session = new Session(
    preset: ""chrome-latest"",
    localAddress: ""2001:db8::1""
);

using var session = new Session(
    preset: ""chrome-latest"",
    localAddress: ""192.168.1.100""
);

Note: When local address is set, target IPs are filtered to match
the address family (IPv6 local -> only connects to IPv6 targets).

Example with your machine's IPs:
");

        Console.WriteLine();
        Console.WriteLine(new string('=', 60));
        Console.WriteLine("New features examples completed!");
        Console.WriteLine(new string('=', 60));
    }
}
