using System;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using Sensor;

namespace Sensor.Tests;

public static class LocalProxyTest
{
    public static async Task RunAsync()
    {
        Console.WriteLine(new string('=', 70));
        Console.WriteLine("C#: Local Proxy Test");
        Console.WriteLine(new string('=', 70));

        Console.WriteLine("\n--- Test 1: Basic Proxy Startup ---");
        try
        {
            using var proxy = new LocalProxy(port: 0, preset: "chrome-143");
            Console.WriteLine($"Proxy started on port: {proxy.Port}");
            Console.WriteLine($"Proxy URL: {proxy.ProxyUrl}");
            Console.WriteLine($"IsRunning: {proxy.IsRunning}");

            var stats = proxy.GetStats();
            Console.WriteLine($"Stats: running={stats.Running}, preset={stats.Preset}");
            Console.WriteLine("PASS: Proxy started successfully");
        }
        catch (Exception e)
        {
            Console.WriteLine($"FAIL: {e.Message}");
        }

        Console.WriteLine("\n--- Test 2: HTTP Request Through Proxy ---");
        try
        {
            using var proxy = new LocalProxy(port: 0, preset: "chrome-143");
            Console.WriteLine($"Proxy running on: {proxy.ProxyUrl}");

            var handler = proxy.CreateHandler();
            using var client = new HttpClient(handler);
            client.Timeout = TimeSpan.FromSeconds(30);

            var response = await client.GetAsync("http://httpbin.org/get");
            Console.WriteLine($"HTTP Status: {response.StatusCode}");

            if (response.IsSuccessStatusCode)
            {
                var body = await response.Content.ReadAsStringAsync();
                Console.WriteLine($"Response length: {body.Length} bytes");
                Console.WriteLine("PASS: HTTP request through proxy succeeded");
            }
            else
            {
                Console.WriteLine($"FAIL: HTTP status {response.StatusCode}");
            }
        }
        catch (Exception e)
        {
            Console.WriteLine($"FAIL: {e.Message}");
        }

        Console.WriteLine("\n--- Test 3: HTTPS CONNECT Tunnel ---");
        try
        {
            using var proxy = new LocalProxy(port: 0, preset: "chrome-143");
            Console.WriteLine($"Proxy running on: {proxy.ProxyUrl}");

            var handler = proxy.CreateHandler();
            using var client = new HttpClient(handler);
            client.Timeout = TimeSpan.FromSeconds(30);

            var response = await client.GetAsync("https://httpbin.org/get");
            Console.WriteLine($"HTTPS Status: {response.StatusCode}");

            if (response.IsSuccessStatusCode)
            {
                var body = await response.Content.ReadAsStringAsync();
                Console.WriteLine($"Response length: {body.Length} bytes");
                Console.WriteLine("PASS: HTTPS CONNECT tunnel succeeded");
            }
            else
            {
                Console.WriteLine($"FAIL: HTTPS status {response.StatusCode}");
            }
        }
        catch (Exception e)
        {
            Console.WriteLine($"FAIL: {e.Message}");
        }

        Console.WriteLine("\n--- Test 4: Concurrent Requests ---");
        try
        {
            using var proxy = new LocalProxy(port: 0, preset: "chrome-143", maxConnections: 100);

            var handler = proxy.CreateHandler();
            using var client = new HttpClient(handler);
            client.Timeout = TimeSpan.FromSeconds(60);

            var tasks = new Task<HttpResponseMessage>[5];
            for (int i = 0; i < 5; i++)
            {
                tasks[i] = client.GetAsync("http://httpbin.org/get");
            }

            await Task.WhenAll(tasks);

            int successCount = 0;
            foreach (var task in tasks)
            {
                if (task.Result.IsSuccessStatusCode)
                    successCount++;
            }

            Console.WriteLine($"Successful requests: {successCount}/5");

            var stats = proxy.GetStats();
            Console.WriteLine($"Total requests: {stats.TotalRequests}");

            if (successCount == 5)
                Console.WriteLine("PASS: All concurrent requests succeeded");
            else
                Console.WriteLine($"FAIL: Only {successCount}/5 requests succeeded");
        }
        catch (Exception e)
        {
            Console.WriteLine($"FAIL: {e.Message}");
        }

        Console.WriteLine("\n" + new string('=', 70));
        Console.WriteLine("Local Proxy Test Complete");
        Console.WriteLine(new string('=', 70));
    }
}
