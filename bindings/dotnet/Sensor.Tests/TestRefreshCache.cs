using System;
using Sensor;

class TestRefreshCache
{
    static void Main()
    {
        using var session = new Session(preset: "chrome-144");

        Console.WriteLine("=== Request 1 (before Refresh) ===");
        var resp = session.Get("https://tls3.peet.ws/api/all");
        if (resp.Text.Contains("max-age=0"))
            Console.WriteLine("  cache-control: max-age=0 FOUND (unexpected!)");
        else
            Console.WriteLine("  cache-control: max-age=0 NOT present (correct)");

        Console.WriteLine("\n=== Calling Refresh() ===");
        session.Refresh();

        Console.WriteLine("\n=== Request 2 (after Refresh) ===");
        resp = session.Get("https://tls3.peet.ws/api/all");
        if (resp.Text.Contains("max-age=0"))
            Console.WriteLine("  cache-control: max-age=0 FOUND (correct)");
        else
            Console.WriteLine("  cache-control: max-age=0 NOT present (unexpected!)");
    }
}
