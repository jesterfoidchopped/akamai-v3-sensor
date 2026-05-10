using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Sensor;

public sealed class LocalProxy : IDisposable
{
    private readonly long _handle;
    private bool _disposed;

    public LocalProxy(
        int port = 0,
        string preset = "chrome-146",
        int timeout = 30,
        int maxConnections = 1000,
        string? tcpProxy = null,
        string? udpProxy = null,
        bool tlsOnly = false)
    {
        var config = new LocalProxyConfig
        {
            Port = port,
            Preset = preset,
            Timeout = timeout,
            MaxConnections = maxConnections,
            TcpProxy = tcpProxy,
            UdpProxy = udpProxy,
            TlsOnly = tlsOnly
        };

        string configJson = JsonSerializer.Serialize(config, LocalProxyJsonContext.Default.LocalProxyConfig);
        _handle = Native.LocalProxyStart(configJson);

        if (_handle < 0)
        {
            throw new SensorException("Failed to start local proxy");
        }
    }

    public int Port
    {
        get
        {
            ThrowIfDisposed();
            return Native.LocalProxyGetPort(_handle);
        }
    }

    public bool IsRunning
    {
        get
        {
            ThrowIfDisposed();
            return Native.LocalProxyIsRunning(_handle) != 0;
        }
    }

    public string ProxyUrl
    {
        get
        {
            ThrowIfDisposed();
            return $"http://localhost:{Port}";
        }
    }

    public WebProxy CreateWebProxy()
    {
        ThrowIfDisposed();
        return new WebProxy(ProxyUrl);
    }

    public HttpClientHandler CreateHandler()
    {
        ThrowIfDisposed();
        return new HttpClientHandler
        {
            Proxy = CreateWebProxy(),
            UseProxy = true
        };
    }

    public LocalProxyStats GetStats()
    {
        ThrowIfDisposed();

        IntPtr ptr = Native.LocalProxyGetStats(_handle);
        string? json = Native.PtrToStringAndFree(ptr);

        if (string.IsNullOrEmpty(json))
        {
            return new LocalProxyStats();
        }

        if (json.Contains("\"error\""))
        {
            return new LocalProxyStats();
        }

        try
        {
            return JsonSerializer.Deserialize(json, LocalProxyJsonContext.Default.LocalProxyStats)
                ?? new LocalProxyStats();
        }
        catch
        {
            return new LocalProxyStats();
        }
    }

    public void RegisterSession(string sessionId, Session session)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(session);

        if (string.IsNullOrEmpty(sessionId))
            throw new ArgumentException("Session ID cannot be null or empty", nameof(sessionId));

        IntPtr errorPtr = Native.LocalProxyRegisterSession(_handle, sessionId, session.Handle);
        string? error = Native.PtrToStringAndFree(errorPtr);

        if (!string.IsNullOrEmpty(error))
        {
            throw new SensorException(error);
        }
    }

    public bool UnregisterSession(string sessionId)
    {
        ThrowIfDisposed();

        if (string.IsNullOrEmpty(sessionId))
            return false;

        int result = Native.LocalProxyUnregisterSession(_handle, sessionId);
        return result == 1;
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(LocalProxy));
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        Native.LocalProxyStop(_handle);
        GC.SuppressFinalize(this);
    }

    ~LocalProxy()
    {
        Dispose();
    }
}

internal class LocalProxyConfig
{
    [JsonPropertyName("port")]
    public int Port { get; set; }

    [JsonPropertyName("preset")]
    public string Preset { get; set; } = "chrome-146";

    [JsonPropertyName("timeout")]
    public int Timeout { get; set; } = 30;

    [JsonPropertyName("max_connections")]
    public int MaxConnections { get; set; } = 1000;

    [JsonPropertyName("tcp_proxy")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? TcpProxy { get; set; }

    [JsonPropertyName("udp_proxy")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? UdpProxy { get; set; }

    [JsonPropertyName("tls_only")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool TlsOnly { get; set; }
}

public class LocalProxyStats
{
    [JsonPropertyName("running")]
    public bool Running { get; set; }

    [JsonPropertyName("port")]
    public int Port { get; set; }

    [JsonPropertyName("active_conns")]
    public long ActiveConnections { get; set; }

    [JsonPropertyName("total_requests")]
    public long TotalRequests { get; set; }

    [JsonPropertyName("preset")]
    public string? Preset { get; set; }

    [JsonPropertyName("max_connections")]
    public int MaxConnections { get; set; }
}

[JsonSerializable(typeof(LocalProxyConfig))]
[JsonSerializable(typeof(LocalProxyStats))]
internal partial class LocalProxyJsonContext : JsonSerializerContext
{
}
