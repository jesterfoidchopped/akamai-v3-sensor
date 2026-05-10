/**
 * QUIC Idle Timeout Configuration
 *
 * This example demonstrates:
 * - Configuring QUIC idle timeout for HTTP/3 connections
 * - Preventing connection drops on long-lived idle connections
 * - When to use higher idle timeouts
 *
 * By default, QUIC connections have a 30-second idle timeout. If your application
 * keeps connections open for longer periods without activity (e.g., connection pooling,
 * long polling), you may need to increase this value.
 *
 * The keepalive is automatically set to half of the idle timeout to prevent
 * connection closure.
 *
 * Run: dotnet run
 */

using Sensor;

class QuicIdleTimeoutExamples
{
    static async Task Main(string[] args)
    {
        Console.WriteLine(new string('=', 60));
        Console.WriteLine("QUIC Idle Timeout Configuration Examples");
        Console.WriteLine(new string('=', 60));

        await Example1_DefaultIdleTimeout();
        await Example2_ExtendedIdleTimeout();
        await Example3_VeryLongIdleTimeout();
        await Example4_CombinedOptions();
        PrintUsageGuidance();

        Console.WriteLine(new string('=', 60));
        Console.WriteLine("QUIC idle timeout examples completed!");
        Console.WriteLine(new string('=', 60));
    }

    static async Task Example1_DefaultIdleTimeout()
    {
        Console.WriteLine("\n[Example 1] Default QUIC Idle Timeout");
        Console.WriteLine(new string('-', 50));

        using var session = new Session(
            preset: Presets.Chrome145,
            httpVersion: "h3"  // Force HTTP/3 to use QUIC
        );

        var response = await session.GetAsync("https://cloudflare.com");
        Console.WriteLine($"Status: {response.StatusCode}");
        Console.WriteLine($"Protocol: {response.Protocol}");
        Console.WriteLine("Default idle timeout: 30 seconds");
        Console.WriteLine("Default keepalive: 15 seconds (half of idle timeout)");
    }

    static async Task Example2_ExtendedIdleTimeout()
    {
        Console.WriteLine("\n[Example 2] Extended QUIC Idle Timeout (2 minutes)");
        Console.WriteLine(new string('-', 50));

        using var session = new Session(
            preset: Presets.Chrome145,
            httpVersion: "h3",
            quicIdleTimeout: 120  // 2 minutes
        );

        var response = await session.GetAsync("https://cloudflare.com");
        Console.WriteLine($"Status: {response.StatusCode}");
        Console.WriteLine($"Protocol: {response.Protocol}");
        Console.WriteLine("Custom idle timeout: 120 seconds");
        Console.WriteLine("Custom keepalive: 60 seconds (half of idle timeout)");

        Console.WriteLine("\nSimulating 5 second idle period...");
        await Task.Delay(5000);

        response = await session.GetAsync("https://cloudflare.com");
        Console.WriteLine($"After idle - Status: {response.StatusCode}, Protocol: {response.Protocol}");
    }

    static async Task Example3_VeryLongIdleTimeout()
    {
        Console.WriteLine("\n[Example 3] Very Long Idle Timeout (5 minutes)");
        Console.WriteLine(new string('-', 50));

        using var session = new Session(
            preset: Presets.Chrome145,
            httpVersion: "h3",
            quicIdleTimeout: 300  // 5 minutes
        );

        var response = await session.GetAsync("https://cloudflare.com");
        Console.WriteLine($"Status: {response.StatusCode}");
        Console.WriteLine($"Protocol: {response.Protocol}");
        Console.WriteLine("Custom idle timeout: 300 seconds (5 minutes)");
        Console.WriteLine("Custom keepalive: 150 seconds (2.5 minutes)");
    }

    static async Task Example4_CombinedOptions()
    {
        Console.WriteLine("\n[Example 4] Combined with Other Options");
        Console.WriteLine(new string('-', 50));

        using var session = new Session(
            preset: Presets.Chrome145,
            httpVersion: "h3",
            quicIdleTimeout: 180,  // 3 minutes
            timeout: 60,          // Request timeout
            retry: 3              // Retry count
        );

        var response = await session.GetAsync("https://cloudflare.com");
        Console.WriteLine($"Status: {response.StatusCode}");
        Console.WriteLine($"Protocol: {response.Protocol}");
        Console.WriteLine("QUIC idle timeout: 180s, Request timeout: 60s, Retries: 3");
    }

    static void PrintUsageGuidance()
    {
        Console.WriteLine("\n" + new string('=', 60));
        Console.WriteLine("When to Adjust QUIC Idle Timeout");
        Console.WriteLine(new string('=', 60));

        Console.WriteLine(@"
Use HIGHER idle timeout (60-300s) when:
  - Your app keeps connections pooled for reuse
  - Making periodic requests with gaps > 30 seconds
  - Using long polling or server-sent events over HTTP/3
  - Experiencing ""connection closed"" errors after idle periods

Use DEFAULT idle timeout (30s) when:
  - Making quick, one-off requests
  - Request patterns have < 30 second gaps
  - Memory is constrained (longer timeouts = more memory)

Note: The keepalive is automatically set to half of idle timeout.
This ensures keepalive packets are sent before the connection
would otherwise be closed due to inactivity.
");
    }
}
