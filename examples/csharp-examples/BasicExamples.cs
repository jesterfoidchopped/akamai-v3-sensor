/**
 * Basic HTTP Requests with Sensor for C#
 *
 * This is the simplest example - perfect for beginners!
 *
 * What you'll learn:
 * - Making GET and POST requests
 * - Sending headers and reading responses
 * - Using sessions for cookies
 * - Async operations
 * - Header order customization
 *
 * Requirements:
 *   dotnet add package Sensor
 *
 * Run:
 *   dotnet run
 */

using Sensor;
using System.Text.Json;

class BasicExamples
{
    static async Task Main(string[] args)
    {
        Console.WriteLine(new string('=', 60));
        Console.WriteLine("Sensor C# Examples");
        Console.WriteLine(new string('=', 60));

        await Example1_SimpleGet();
        await Example2_PostWithJson();
        await Example3_CustomHeaders();
        await Example4_SessionWithCookies();
        await Example5_AsyncRequests();
        await Example6_ErrorHandling();
        Example7_DifferentPresets();
        Example8_HeaderOrderCustomization();

        Console.WriteLine("\n" + new string('=', 60));
        Console.WriteLine("All examples completed!");
        Console.WriteLine(new string('=', 60));
    }

    static async Task Example1_SimpleGet()
    {
        Console.WriteLine("\n[Example 1] Simple GET Request");
        Console.WriteLine(new string('-', 50));

        using var session = new Session(preset: Presets.Chrome145);

        var response = session.Get("https://httpbin.org/get");

        Console.WriteLine($"Status Code: {response.StatusCode}");
        Console.WriteLine($"Protocol: {response.Protocol}");
        Console.WriteLine($"OK: {response.Ok}");
    }

    static async Task Example2_PostWithJson()
    {
        Console.WriteLine("\n[Example 2] POST with JSON Body");
        Console.WriteLine(new string('-', 50));

        using var session = new Session(preset: Presets.Chrome145);

        var jsonBody = """{"name": "sensor", "version": "1.5.0"}""";
        var response = session.Post(
            "https://httpbin.org/post",
            body: jsonBody,
            headers: new Dictionary<string, string>
            {
                ["Content-Type"] = "application/json"
            }
        );

        Console.WriteLine($"Status: {response.StatusCode}");

        var data = JsonDocument.Parse(response.Text);
        Console.WriteLine($"Echoed JSON: {data.RootElement.GetProperty("json")}");
    }

    static async Task Example3_CustomHeaders()
    {
        Console.WriteLine("\n[Example 3] Custom Headers");
        Console.WriteLine(new string('-', 50));

        using var session = new Session(preset: Presets.Chrome145);

        var response = session.Get(
            "https://httpbin.org/headers",
            headers: new Dictionary<string, string>
            {
                ["X-Custom-Header"] = "my-value",
                ["X-Request-ID"] = "abc-123-xyz"
            }
        );

        Console.WriteLine($"Status: {response.StatusCode}");
        var data = JsonDocument.Parse(response.Text);
        var headers = data.RootElement.GetProperty("headers");
        Console.WriteLine($"Custom header: {headers.GetProperty("X-Custom-Header")}");
    }

    static async Task Example4_SessionWithCookies()
    {
        Console.WriteLine("\n[Example 4] Session with Cookies");
        Console.WriteLine(new string('-', 50));

        using var session = new Session(preset: Presets.Chrome145);

        session.Get("https://httpbin.org/cookies/set/session_id/abc123");

        session.SetCookie("user_id", "12345");

        var cookies = session.GetCookies();
        Console.WriteLine($"Cookies in session: {cookies}");

        var response = session.Get("https://httpbin.org/cookies");
        Console.WriteLine($"Cookies endpoint: {response.Text}");
    }

    static async Task Example5_AsyncRequests()
    {
        Console.WriteLine("\n[Example 5] Async Requests");
        Console.WriteLine(new string('-', 50));

        using var session = new Session(preset: Presets.Chrome145);

        var response = await session.GetAsync("https://httpbin.org/get");
        Console.WriteLine($"Async GET: {response.StatusCode}");

        var tasks = new[]
        {
            session.GetAsync("https://httpbin.org/get"),
            session.GetAsync("https://httpbin.org/headers"),
            session.GetAsync("https://httpbin.org/ip")
        };

        var results = await Task.WhenAll(tasks);
        Console.WriteLine($"Concurrent results: [{string.Join(", ", results.Select(r => r.StatusCode))}]");
    }

    static async Task Example6_ErrorHandling()
    {
        Console.WriteLine("\n[Example 6] Error Handling");
        Console.WriteLine(new string('-', 50));

        using var session = new Session(preset: Presets.Chrome145);

        var response = session.Get("https://httpbin.org/status/404");
        Console.WriteLine($"404 Status: {response.StatusCode}, OK: {response.Ok}");

        try
        {
            response.RaiseForStatus();
        }
        catch (SensorException e)
        {
            Console.WriteLine($"Caught error: {e.Message}");
        }
    }

    static void Example7_DifferentPresets()
    {
        Console.WriteLine("\n[Example 7] Different Browser Presets");
        Console.WriteLine(new string('-', 50));

        var presets = new[]
        {
            Presets.Chrome145,
            Presets.Chrome145Windows,
            Presets.Chrome145Linux,
            Presets.Firefox133,
            Presets.Safari18
        };

        foreach (var preset in presets)
        {
            using var session = new Session(preset: preset);
            var response = session.Get("https://httpbin.org/user-agent");
            var ua = response.Text.Length > 60
                ? response.Text.Substring(0, 60) + "..."
                : response.Text;
            Console.WriteLine($"{preset,-25}: {ua}");
        }
    }

    static void Example8_HeaderOrderCustomization()
    {
        Console.WriteLine("\n[Example 8] Header Order Customization");
        Console.WriteLine(new string('-', 50));

        using var session = new Session(preset: Presets.Chrome145);

        var defaultOrder = session.GetHeaderOrder();
        Console.WriteLine($"Default header order ({defaultOrder.Length} headers):");
        for (int i = 0; i < Math.Min(5, defaultOrder.Length); i++)
        {
            Console.WriteLine($"  {i + 1}. {defaultOrder[i]}");
        }
        Console.WriteLine($"  ... and {defaultOrder.Length - 5} more");

        var customOrder = new[] { "accept", "user-agent", "sec-ch-ua", "accept-language", "accept-encoding" };
        session.SetHeaderOrder(customOrder);
        Console.WriteLine($"\nCustom order set: [{string.Join(", ", session.GetHeaderOrder())}]");

        var response = session.Get("https://httpbin.org/headers");
        Console.WriteLine($"Request with custom order - Status: {response.StatusCode}, Protocol: {response.Protocol}");

        session.SetHeaderOrder(null);
        var resetOrder = session.GetHeaderOrder();
        Console.WriteLine($"Reset to default ({resetOrder.Length} headers): [{string.Join(", ", resetOrder.Take(3))}]...");
    }
}
