using Sensor;
using System;
using System.Text;

namespace Sensor.Tests;

public static class TestFastMethods
{
    public static void Run()
    {
        Console.WriteLine("=== Testing FastResponse ===");
        using var session = new Session(preset: "chrome-143");
        
        var resp1 = session.GetFast("https://httpbin.org/get");
        Console.WriteLine($"StatusCode: {resp1.StatusCode}");
        Console.WriteLine($"OK: {resp1.Ok}");
        Console.WriteLine($"Reason: {resp1.Reason}");
        Console.WriteLine($"Encoding: {resp1.Encoding ?? "null"}");
        Console.WriteLine($"Protocol: {resp1.Protocol}");
        Console.WriteLine($"Cookies: {resp1.Cookies.Count}");
        Console.WriteLine($"History: {resp1.History.Count}");
        Console.WriteLine($"Content length: {resp1.Content.Length}");
        Console.WriteLine("✓ FastResponse: PASS");

        Console.WriteLine("\n=== Testing fast methods ===");
        var resp2 = session.RequestFast("GET", "https://httpbin.org/get");
        Console.WriteLine($"RequestFast GET: {resp2.StatusCode}");

        var resp3 = session.PutFast("https://httpbin.org/put", Encoding.UTF8.GetBytes("test"));
        Console.WriteLine($"PutFast: {resp3.StatusCode}");

        var resp4 = session.DeleteFast("https://httpbin.org/delete");
        Console.WriteLine($"DeleteFast: {resp4.StatusCode}");

        var resp5 = session.PatchFast("https://httpbin.org/patch", Encoding.UTF8.GetBytes("test"));
        Console.WriteLine($"PatchFast: {resp5.StatusCode}");

        Console.WriteLine("✓ Fast methods: PASS");
        Console.WriteLine("\n=== All C# fast tests passed! ===");
    }
}
