/**
 * Session Resumption (0-RTT)
 *
 * This example demonstrates TLS session resumption which dramatically
 * improves bot detection scores by making connections look like
 * returning visitors rather than new connections.
 *
 * Key concepts:
 * - First connection: Bot score ~43 (new TLS handshake)
 * - Resumed connection: Bot score ~99 (looks like returning visitor)
 * - Cross-domain warming: Session tickets work across same-infrastructure sites
 *
 * Run: dotnet run
 */

using Sensor;
using System.Text.Json;

class SessionResumption
{
    const string SessionFile = "session_state.json";

    static void Main(string[] args)
    {
        Console.WriteLine(new string('=', 60));
        Console.WriteLine("Session Resumption Examples");
        Console.WriteLine(new string('=', 60));

        Example1_SaveLoad();
        Example2_MarshalUnmarshal();
        Example3_CrossDomainWarming();
        Example4_ProductionPattern();

        if (File.Exists(SessionFile)) File.Delete(SessionFile);
        if (File.Exists("my_scraper.json")) File.Delete("my_scraper.json");

        Console.WriteLine("\n" + new string('=', 60));
        Console.WriteLine("Session resumption examples completed!");
        Console.WriteLine(new string('=', 60));
    }

    static void Example1_SaveLoad()
    {
        Console.WriteLine("\n[1] Save and Load Session (File)");
        Console.WriteLine(new string('-', 50));

        Session session;

        if (File.Exists(SessionFile))
        {
            Console.WriteLine("Loading existing session...");
            session = Session.Load(SessionFile);
            Console.WriteLine("Session loaded with TLS tickets!");
        }
        else
        {
            Console.WriteLine("Creating new session...");
            session = new Session(preset: Presets.Chrome145);

            Console.WriteLine("Warming up session...");
            var r = session.Get("https://cloudflare.com/cdn-cgi/trace");
            Console.WriteLine($"Warmup complete - Protocol: {r.Protocol}");
        }

        var resp = session.Get("https://www.cloudflare.com/cdn-cgi/trace");
        Console.WriteLine($"Request - Protocol: {resp.Protocol}");

        session.Save(SessionFile);
        Console.WriteLine($"Session saved to {SessionFile}");

        session.Dispose();
    }

    static void Example2_MarshalUnmarshal()
    {
        Console.WriteLine("\n[2] Marshal/Unmarshal Session (String)");
        Console.WriteLine(new string('-', 50));

        using var session = new Session(preset: Presets.Chrome145);
        session.Get("https://cloudflare.com/");

        string sessionData = session.Marshal();
        Console.WriteLine($"Marshaled session: {sessionData.Length} bytes");

        using var restored = Session.Unmarshal(sessionData);
        var resp = restored.Get("https://www.cloudflare.com/cdn-cgi/trace");
        Console.WriteLine($"Restored session request - Protocol: {resp.Protocol}");
    }

    static void Example3_CrossDomainWarming()
    {
        Console.WriteLine("\n[3] Cross-Domain Warming");
        Console.WriteLine(new string('-', 50));

        using var session = new Session(preset: Presets.Chrome145);

        Console.WriteLine("Warming up on cloudflare.com...");
        var resp = session.Get("https://cloudflare.com/cdn-cgi/trace");
        Console.WriteLine($"Warmup - Protocol: {resp.Protocol}");

        Console.WriteLine("\nUsing warmed session on cf.erisa.uk (CF-protected)...");
        resp = session.Get("https://cf.erisa.uk/");

        var json = JsonDocument.Parse(resp.Text);
        var botScore = json.RootElement
            .GetProperty("botManagement")
            .GetProperty("score")
            .GetInt32();

        Console.WriteLine($"Bot Score: {botScore}");
        Console.WriteLine($"Protocol: {resp.Protocol}");
    }

    static void Example4_ProductionPattern()
    {
        Console.WriteLine("\n[4] Production Pattern");
        Console.WriteLine(new string('-', 50));

        using var session = GetOrCreateSession("my_scraper");

        var resp = session.Get("https://cf.erisa.uk/");
        var json = JsonDocument.Parse(resp.Text);
        var botScore = json.RootElement
            .GetProperty("botManagement")
            .GetProperty("score")
            .GetInt32();

        Console.WriteLine($"Bot Score: {botScore}");
    }

    static Session GetOrCreateSession(string sessionKey)
    {
        string sessionPath = $"{sessionKey}.json";

        if (File.Exists(sessionPath))
        {
            return Session.Load(sessionPath);
        }

        var session = new Session(preset: Presets.Chrome145);

        session.Get("https://cloudflare.com/cdn-cgi/trace");

        session.Save(sessionPath);

        return session;
    }
}
