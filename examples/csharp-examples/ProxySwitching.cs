/**
 * Runtime Proxy Switching
 *
 * This example demonstrates:
 * - Switching proxies mid-session without creating new sessions
 * - Split proxy configuration (different proxies for TCP and UDP)
 * - Getting current proxy configuration
 * - H2 and H3 proxy switching
 */

using Sensor;

const string TEST_URL = "https://www.cloudflare.com/cdn-cgi/trace";

Dictionary<string, string> ParseTrace(string body)
{
    var result = new Dictionary<string, string>();
    foreach (var line in body.Trim().Split('\n'))
    {
        var idx = line.IndexOf('=');
        if (idx != -1)
            result[line[..idx]] = line[(idx + 1)..];
    }
    return result;
}

Console.WriteLine(new string('=', 60));
Console.WriteLine("Example 1: Basic Proxy Switching");
Console.WriteLine(new string('-', 60));

using (var session = new Session(preset: "chrome-latest"))
{
    var r = await session.GetAsync(TEST_URL);
    var trace = ParseTrace(r.Text);
    Console.WriteLine("Direct connection:");
    Console.WriteLine($"  Protocol: {r.Protocol}, IP: {trace.GetValueOrDefault("ip", "N/A")}, Colo: {trace.GetValueOrDefault("colo", "N/A")}");

}

Console.WriteLine("\n" + new string('=', 60));
Console.WriteLine("Example 2: Getting Current Proxy Configuration");
Console.WriteLine(new string('-', 60));

using (var session = new Session(preset: "chrome-latest"))
{
    Console.WriteLine($"Initial proxy: '{session.GetProxy()}' (empty = direct)");
    Console.WriteLine($"TCP proxy: '{session.GetTcpProxy()}'");
    Console.WriteLine($"UDP proxy: '{session.GetUdpProxy()}'");

    Console.WriteLine($"Proxy (via property): '{session.Proxy}'");
}

Console.WriteLine("\n" + new string('=', 60));
Console.WriteLine("Example 3: Split Proxy Configuration (TCP vs UDP)");
Console.WriteLine(new string('-', 60));

Console.WriteLine(@"

using var session = new Session(preset: ""chrome-latest"");

session.SetTcpProxy(""http://tcp-proxy.example.com:8080"");

session.SetUdpProxy(""socks5://udp-proxy.example.com:1080"");

Console.WriteLine($""TCP proxy: {session.GetTcpProxy()}"");
Console.WriteLine($""UDP proxy: {session.GetUdpProxy()}"");
");

Console.WriteLine("\n" + new string('=', 60));
Console.WriteLine("Example 4: HTTP/3 Proxy Switching");
Console.WriteLine(new string('-', 60));

Console.WriteLine(@"

using var session = new Session(preset: ""chrome-latest"", httpVersion: ""h3"");

var r = await session.GetAsync(""https://example.com"");
Console.WriteLine($""Direct: {r.Protocol}"");

session.SetUdpProxy(""socks5://user:pass@proxy.example.com:1080"");
r = await session.GetAsync(""https://example.com"");
Console.WriteLine($""Via SOCKS5: {r.Protocol}"");

session.SetUdpProxy(""https://user:pass@brd.superproxy.io:10001"");
r = await session.GetAsync(""https://example.com"");
Console.WriteLine($""Via MASQUE: {r.Protocol}"");
");

Console.WriteLine("\n" + new string('=', 60));
Console.WriteLine("Example 5: Proxy Rotation Pattern");
Console.WriteLine(new string('-', 60));

Console.WriteLine(@"

var proxies = new[]
{
    ""http://proxy1.example.com:8080"",
    ""http://proxy2.example.com:8080"",
    ""http://proxy3.example.com:8080"",
};

using var session = new Session(preset: ""chrome-latest"");

for (int i = 0; i < proxies.Length; i++)
{
    session.SetProxy(proxies[i]);
    var r = await session.GetAsync(""https://api.ipify.org"");
    Console.WriteLine($""Request {i + 1} via {proxies[i]}: IP = {r.Text}"");
}
");

Console.WriteLine("\n" + new string('=', 60));
Console.WriteLine("Example 6: Speculative TLS Optimization");
Console.WriteLine(new string('-', 60));

Console.WriteLine(@"

using var session = new Session(
    preset: ""chrome-latest"",
    proxy: ""http://user:pass@proxy.example.com:8080"",
    disableSpeculativeTls: true
);
");

Console.WriteLine("\n" + new string('=', 60));
Console.WriteLine("Proxy switching examples completed!");
Console.WriteLine(new string('=', 60));
