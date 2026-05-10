/**
 * Local Proxy for Transparent HttpClient Integration
 *
 * This example shows how to use sensor's LocalProxy feature to enable
 * TLS fingerprinting with standard .NET HttpClient - no FFI limitations!
 *
 * What you'll learn:
 * - Starting a local proxy server
 * - Using HttpClient with the proxy
 * - True streaming uploads/downloads
 * - Working with third-party libraries
 * - HTTPS tunneling via CONNECT
 *
 * Why use LocalProxy?
 * - Works with ANY HttpClient-based code (including third-party libs)
 * - True streaming - request/response bodies are never buffered in memory
 * - High performance (~3GB/s throughput on localhost)
 * - Simple integration - just set the proxy URL
 *
 * Requirements:
 *   dotnet add package Sensor
 *
 * Run:
 *   dotnet run
 */

using Sensor;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;

class LocalProxyExamples
{
    static async Task Main(string[] args)
    {
        Console.WriteLine(new string('=', 60));
        Console.WriteLine("Sensor Local Proxy Examples");
        Console.WriteLine(new string('=', 60));

        await Example1_BasicUsage();
        await Example2_WithExistingHttpClient();
        await Example3_PostWithLargeBody();
        await Example4_ConcurrentRequests();
        await Example5_HttpsConnectTunnel();
        await Example6_ProxyWithConfiguration();
        await Example7_MonitoringStats();
        await Example8_ThirdPartyLibraryIntegration();

        Console.WriteLine("\n" + new string('=', 60));
        Console.WriteLine("All examples completed!");
        Console.WriteLine(new string('=', 60));
    }

    static async Task Example1_BasicUsage()
    {
        Console.WriteLine("\n[Example 1] Basic Usage");
        Console.WriteLine(new string('-', 50));

        using var proxy = new LocalProxy(preset: "chrome-latest");
        Console.WriteLine($"Proxy started on port: {proxy.Port}");

        var handler = proxy.CreateHandler();
        using var client = new HttpClient(handler);

        var response = await client.GetAsync("https://httpbin.org/get");
        Console.WriteLine($"Status: {response.StatusCode}");

        var body = await response.Content.ReadAsStringAsync();
        Console.WriteLine($"Response length: {body.Length} bytes");
    }

    static async Task Example2_WithExistingHttpClient()
    {
        Console.WriteLine("\n[Example 2] With Existing HttpClient");
        Console.WriteLine(new string('-', 50));

        using var proxy = new LocalProxy(preset: "chrome-latest");

        var handler = new HttpClientHandler
        {
            Proxy = new WebProxy(proxy.ProxyUrl),
            UseProxy = true
        };

        using var client = new HttpClient(handler);
        client.DefaultRequestHeaders.Add("User-Agent", "MyApp/1.0");

        var response = await client.GetAsync("https://httpbin.org/headers");
        Console.WriteLine($"Status: {response.StatusCode}");
    }

    static async Task Example3_PostWithLargeBody()
    {
        Console.WriteLine("\n[Example 3] POST with Large Body (True Streaming)");
        Console.WriteLine(new string('-', 50));

        using var proxy = new LocalProxy(preset: "chrome-latest");
        var handler = proxy.CreateHandler();
        using var client = new HttpClient(handler);
        client.Timeout = TimeSpan.FromMinutes(5);

        var data = new byte[1024 * 1024];
        Random.Shared.NextBytes(data);

        Console.WriteLine("Uploading 1MB of data...");
        var content = new ByteArrayContent(data);
        content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream");

        var response = await client.PostAsync("https://httpbin.org/post", content);
        Console.WriteLine($"Upload status: {response.StatusCode}");

    }

    static async Task Example4_ConcurrentRequests()
    {
        Console.WriteLine("\n[Example 4] Concurrent Requests");
        Console.WriteLine(new string('-', 50));

        using var proxy = new LocalProxy(preset: "chrome-latest", maxConnections: 100);
        var handler = proxy.CreateHandler();
        using var client = new HttpClient(handler);

        var tasks = Enumerable.Range(1, 10)
            .Select(i => client.GetAsync($"https://httpbin.org/get?id={i}"))
            .ToArray();

        var responses = await Task.WhenAll(tasks);
        var successCount = responses.Count(r => r.IsSuccessStatusCode);

        Console.WriteLine($"Completed: {successCount}/10 successful");

        var stats = proxy.GetStats();
        Console.WriteLine($"Total requests processed: {stats.TotalRequests}");
    }

    static async Task Example5_HttpsConnectTunnel()
    {
        Console.WriteLine("\n[Example 5] HTTPS CONNECT Tunnel");
        Console.WriteLine(new string('-', 50));

        using var proxy = new LocalProxy(preset: "chrome-latest");
        var handler = proxy.CreateHandler();
        using var client = new HttpClient(handler);

        var response = await client.GetAsync("https://api.github.com/zen");

        Console.WriteLine($"GitHub Zen: {await response.Content.ReadAsStringAsync()}");
        Console.WriteLine("(HTTPS traffic tunneled via CONNECT method)");
    }

    static async Task Example6_ProxyWithConfiguration()
    {
        Console.WriteLine("\n[Example 6] Proxy with Configuration");
        Console.WriteLine(new string('-', 50));

        using var proxy = new LocalProxy(
            port: 0,              // 0 = auto-select available port
            preset: "chrome-latest", // Browser fingerprint
            timeout: 60,          // Request timeout in seconds
            maxConnections: 500   // Max concurrent connections
        );

        Console.WriteLine($"Proxy URL: {proxy.ProxyUrl}");
        Console.WriteLine($"Running: {proxy.IsRunning}");

        var handler = proxy.CreateHandler();
        using var client = new HttpClient(handler);

        var response = await client.GetAsync("https://httpbin.org/ip");
        var ip = await response.Content.ReadAsStringAsync();
        Console.WriteLine($"Your IP: {ip.Trim()}");
    }

    static async Task Example7_MonitoringStats()
    {
        Console.WriteLine("\n[Example 7] Monitoring Stats");
        Console.WriteLine(new string('-', 50));

        using var proxy = new LocalProxy(preset: "chrome-latest");
        var handler = proxy.CreateHandler();
        using var client = new HttpClient(handler);

        for (int i = 0; i < 5; i++)
        {
            await client.GetAsync("https://httpbin.org/get");
        }

        var stats = proxy.GetStats();
        Console.WriteLine($"Running: {stats.Running}");
        Console.WriteLine($"Port: {stats.Port}");
        Console.WriteLine($"Preset: {stats.Preset}");
        Console.WriteLine($"Active Connections: {stats.ActiveConnections}");
        Console.WriteLine($"Total Requests: {stats.TotalRequests}");
        Console.WriteLine($"Max Connections: {stats.MaxConnections}");
    }

    static async Task Example8_ThirdPartyLibraryIntegration()
    {
        Console.WriteLine("\n[Example 8] Third-Party Library Integration");
        Console.WriteLine(new string('-', 50));

        using var proxy = new LocalProxy(preset: "chrome-latest");

        var handler = proxy.CreateHandler();
        using var client = new HttpClient(handler);

        client.BaseAddress = new Uri("https://jsonplaceholder.typicode.com");
        client.DefaultRequestHeaders.Accept.Add(
            new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));

        var response = await client.GetAsync("/posts/1");
        var json = await response.Content.ReadAsStringAsync();

        var post = JsonDocument.Parse(json);
        Console.WriteLine($"Post title: {post.RootElement.GetProperty("title").GetString()}");

        Console.WriteLine("Works with RestSharp, Refit, Flurl, and more!");
    }
}
