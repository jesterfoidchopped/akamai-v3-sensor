using System.Collections.Concurrent;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Sensor;

internal sealed class AsyncCallbackManager
{
    private static readonly Lazy<AsyncCallbackManager> _instance = new(() => new AsyncCallbackManager());
    public static AsyncCallbackManager Instance => _instance.Value;

    private readonly ConcurrentDictionary<long, TaskCompletionSource<Response>> _pendingRequests = new();
    private readonly Native.AsyncCallback _callback;
    private readonly object _lock = new();

    private AsyncCallbackManager()
    {
        _callback = OnCallback;
    }

    private void OnCallback(long callbackId, IntPtr responseJsonPtr, IntPtr errorPtr)
    {
        if (!_pendingRequests.TryRemove(callbackId, out var tcs))
            return;

        try
        {
            string? error = Native.PtrToString(errorPtr);
            string? responseJson = Native.PtrToString(responseJsonPtr);

            if (!string.IsNullOrEmpty(error))
            {
                string errorMsg = error;
                try
                {
                    var errorData = JsonSerializer.Deserialize(error, JsonContext.Default.ErrorResponse);
                    if (errorData?.Error != null)
                        errorMsg = errorData.Error;
                }
                catch { }

                tcs.TrySetException(new SensorException(errorMsg));
            }
            else if (!string.IsNullOrEmpty(responseJson))
            {
                try
                {
                    if (responseJson.Contains("\"error\""))
                    {
                        var errorResponse = JsonSerializer.Deserialize(responseJson, JsonContext.Default.ErrorResponse);
                        if (errorResponse?.Error != null)
                        {
                            tcs.TrySetException(new SensorException(errorResponse.Error));
                            return;
                        }
                    }

                    var responseData = JsonSerializer.Deserialize(responseJson, JsonContext.Default.ResponseData);
                    if (responseData == null)
                    {
                        tcs.TrySetException(new SensorException("Failed to parse response"));
                        return;
                    }

                    tcs.TrySetResult(new Response(responseData));
                }
                catch (Exception ex)
                {
                    tcs.TrySetException(new SensorException($"Failed to parse response: {ex.Message}"));
                }
            }
            else
            {
                tcs.TrySetException(new SensorException("No response received"));
            }
        }
        catch (Exception ex)
        {
            tcs.TrySetException(ex);
        }
    }

    public (long CallbackId, Task<Response> Task) RegisterRequest(CancellationToken cancellationToken = default)
    {
        var tcs = new TaskCompletionSource<Response>(TaskCreationOptions.RunContinuationsAsynchronously);

        long callbackId = Native.RegisterCallback(_callback);

        _pendingRequests[callbackId] = tcs;

        if (cancellationToken.CanBeCanceled)
        {
            var id = callbackId;
            cancellationToken.Register(() =>
            {
                Native.CancelRequest(id);
                if (_pendingRequests.TryRemove(id, out var removed))
                    removed.TrySetCanceled(cancellationToken);
            });
        }

        return (callbackId, tcs.Task);
    }
}

public sealed class Session : IDisposable
{
    private long _handle;
    private bool _disposed;

    private static readonly JsonSerializerOptions _relaxedJsonOptions = new()
    {
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    internal long Handle => _handle;

    public (string Username, string Password)? Auth { get; set; }

    public Session(
        string preset = "chrome-146",
        string? proxy = null,
        string? tcpProxy = null,
        string? udpProxy = null,
        int timeout = 30,
        string httpVersion = "auto",
        bool verify = true,
        bool allowRedirects = true,
        int maxRedirects = 10,
        int retry = 0,
        int[]? retryOnStatus = null,
        int retryWaitMin = 500,
        int retryWaitMax = 10000,
        bool preferIpv4 = false,
        (string Username, string Password)? auth = null,
        Dictionary<string, string>? connectTo = null,
        string? echConfigDomain = null,
        bool tlsOnly = false,
        int quicIdleTimeout = 0,
        string? localAddress = null,
        string? keyLogFile = null,
        bool enableSpeculativeTls = false,
        string? switchProtocol = null,
        bool withoutCookieJar = false,
        string? ja3 = null,
        string? akamai = null,
        Dictionary<string, object>? extraFp = null,
        int? tcpTtl = null,
        int? tcpMss = null,
        int? tcpWindowSize = null,
        int? tcpWindowScale = null,
        bool? tcpDf = null)
    {
        Auth = auth;

        var config = new SessionConfig
        {
            Preset = preset,
            Proxy = proxy,
            TcpProxy = tcpProxy,
            UdpProxy = udpProxy,
            Timeout = timeout,
            HttpVersion = httpVersion,
            Verify = verify,
            AllowRedirects = allowRedirects,
            MaxRedirects = maxRedirects,
            Retry = retry,
            RetryOnStatus = retryOnStatus,
            RetryWaitMin = retryWaitMin,
            RetryWaitMax = retryWaitMax,
            PreferIpv4 = preferIpv4,
            ConnectTo = connectTo,
            EchConfigDomain = echConfigDomain,
            TlsOnly = tlsOnly,
            QuicIdleTimeout = quicIdleTimeout,
            LocalAddress = localAddress,
            KeyLogFile = keyLogFile,
            EnableSpeculativeTls = enableSpeculativeTls,
            SwitchProtocol = switchProtocol,
            WithoutCookieJar = withoutCookieJar,
            Ja3 = ja3,
            Akamai = akamai,
            ExtraFp = extraFp,
            TcpTtl = tcpTtl,
            TcpMss = tcpMss,
            TcpWindowSize = tcpWindowSize,
            TcpWindowScale = tcpWindowScale,
            TcpDf = tcpDf
        };

        string configJson = JsonSerializer.Serialize(config, JsonContext.Relaxed.SessionConfig);
        _handle = Native.SessionNew(configJson);

        if (_handle == 0)
            throw new SensorException("Failed to create session");
    }

    private Dictionary<string, string> ApplyAuth(Dictionary<string, string>? headers, (string Username, string Password)? auth)
    {
        var effectiveAuth = auth ?? Auth;
        headers ??= new Dictionary<string, string>();

        if (effectiveAuth != null)
        {
            var credentials = $"{effectiveAuth.Value.Username}:{effectiveAuth.Value.Password}";
            var base64 = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(credentials));
            headers["Authorization"] = $"Basic {base64}";
        }

        return headers;
    }

    private static string AddParamsToUrl(string url, IEnumerable<KeyValuePair<string, string>>? parameters)
    {
        if (parameters == null || !parameters.Any())
            return url;

        var sb = new System.Text.StringBuilder(url);
        sb.Append(url.Contains('?') ? '&' : '?');
        bool first = true;
        foreach (var param in parameters)
        {
            if (!first) sb.Append('&');
            sb.Append(Uri.EscapeDataString(param.Key));
            sb.Append('=');
            sb.Append(Uri.EscapeDataString(param.Value));
            first = false;
        }
        return sb.ToString();
    }

    private static Dictionary<string, string> ApplyCookies(Dictionary<string, string> headers, Dictionary<string, string>? cookies)
    {
        if (cookies == null || cookies.Count == 0)
            return headers;

        var cookieStr = string.Join("; ", cookies.Select(c => $"{c.Key}={c.Value}"));
        if (headers.TryGetValue("Cookie", out var existing) && !string.IsNullOrEmpty(existing))
        {
            headers["Cookie"] = $"{existing}; {cookieStr}";
        }
        else
        {
            headers["Cookie"] = cookieStr;
        }
        return headers;
    }

    private static void InferContentType(string? body, Dictionary<string, string> headers)
    {
        if (string.IsNullOrEmpty(body))
            return;

        foreach (var key in headers.Keys)
        {
            if (key.Equals("Content-Type", StringComparison.OrdinalIgnoreCase))
                return;
        }

        var trimmed = body.AsSpan().TrimStart();
        if (trimmed.Length > 0 && (trimmed[0] == '{' || trimmed[0] == '['))
        {
            headers["Content-Type"] = "application/json";
        }
    }

    public Response Get(string url, Dictionary<string, string>? headers = null, IEnumerable<KeyValuePair<string, string>>? parameters = null, Dictionary<string, string>? cookies = null, (string, string)? auth = null, int? timeout = null, string? fetchMode = null)
    {
        ThrowIfDisposed();

        url = AddParamsToUrl(url, parameters);
        headers = ApplyAuth(headers, auth);
        headers = ApplyCookies(headers, cookies);

        if (timeout != null)
            return Request("GET", url, null, headers, timeout, auth, fetchMode: fetchMode);

        string? optionsJson = (headers.Count > 0 || fetchMode != null)
            ? JsonSerializer.Serialize(new RequestOptions { Headers = headers.Count > 0 ? headers : null, FetchMode = fetchMode }, JsonContext.Relaxed.RequestOptions)
            : null;

        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        long responseHandle = Native.GetRaw(_handle, url, optionsJson);
        stopwatch.Stop();

        if (responseHandle < 0)
            throw new SensorException("Request failed");

        return ParseRawResponse(responseHandle, stopwatch.Elapsed);
    }

    public Response Post(string url, string? body = null, Dictionary<string, string>? headers = null, IEnumerable<KeyValuePair<string, string>>? parameters = null, Dictionary<string, string>? cookies = null, (string, string)? auth = null, int? timeout = null, string? fetchMode = null)
    {
        ThrowIfDisposed();

        url = AddParamsToUrl(url, parameters);
        headers = ApplyAuth(headers, auth);
        headers = ApplyCookies(headers, cookies);
        InferContentType(body, headers);

        if (timeout != null)
            return Request("POST", url, body, headers, timeout, auth, fetchMode: fetchMode);

        string? optionsJson = (headers.Count > 0 || fetchMode != null)
            ? JsonSerializer.Serialize(new RequestOptions { Headers = headers.Count > 0 ? headers : null, FetchMode = fetchMode }, JsonContext.Relaxed.RequestOptions)
            : null;

        byte[] bodyBytes = body != null ? System.Text.Encoding.UTF8.GetBytes(body) : Array.Empty<byte>();

        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        long responseHandle;

        if (bodyBytes.Length > 0)
        {
            unsafe
            {
                fixed (byte* bodyPtr = bodyBytes)
                {
                    responseHandle = Native.PostRaw(_handle, url, (IntPtr)bodyPtr, bodyBytes.Length, optionsJson);
                }
            }
        }
        else
        {
            responseHandle = Native.PostRaw(_handle, url, IntPtr.Zero, 0, optionsJson);
        }
        stopwatch.Stop();

        if (responseHandle < 0)
            throw new SensorException("Request failed");

        return ParseRawResponse(responseHandle, stopwatch.Elapsed);
    }

    public Response PostJson<T>(string url, T data, Dictionary<string, string>? headers = null, IEnumerable<KeyValuePair<string, string>>? parameters = null, Dictionary<string, string>? cookies = null, (string, string)? auth = null, int? timeout = null, string? fetchMode = null)
    {
        headers ??= new Dictionary<string, string>();
        if (!headers.ContainsKey("Content-Type"))
            headers["Content-Type"] = "application/json";

        string body = JsonSerializer.Serialize(data, _relaxedJsonOptions);
        return Post(url, body, headers, parameters, cookies, auth, timeout, fetchMode);
    }

    public Response PostForm(string url, Dictionary<string, string> formData, Dictionary<string, string>? headers = null, IEnumerable<KeyValuePair<string, string>>? parameters = null, Dictionary<string, string>? cookies = null, (string, string)? auth = null, int? timeout = null, string? fetchMode = null)
    {
        headers ??= new Dictionary<string, string>();
        if (!headers.ContainsKey("Content-Type"))
            headers["Content-Type"] = "application/x-www-form-urlencoded";

        string body = string.Join("&", formData.Select(kvp => $"{Uri.EscapeDataString(kvp.Key)}={Uri.EscapeDataString(kvp.Value)}"));
        return Post(url, body, headers, parameters, cookies, auth, timeout, fetchMode);
    }

    public Response PostMultipart(string url, Dictionary<string, string>? fields = null, Dictionary<string, MultipartFile>? files = null, Dictionary<string, string>? headers = null, IEnumerable<KeyValuePair<string, string>>? parameters = null, Dictionary<string, string>? cookies = null, (string Username, string Password)? auth = null, int? timeout = null, string? fetchMode = null)
    {
        var boundary = "----SensorBoundary" + Guid.NewGuid().ToString("N");
        var ms = new MemoryStream();
        var encoding = new System.Text.UTF8Encoding(false);
        void WriteStr(string s) { var b = encoding.GetBytes(s); ms.Write(b, 0, b.Length); }

        if (fields != null)
            foreach (var kvp in fields)
                WriteStr($"--{boundary}\r\nContent-Disposition: form-data; name=\"{kvp.Key}\"\r\n\r\n{kvp.Value}\r\n");

        if (files != null)
            foreach (var kvp in files)
            {
                WriteStr($"--{boundary}\r\nContent-Disposition: form-data; name=\"{kvp.Key}\"; filename=\"{kvp.Value.Filename}\"\r\nContent-Type: {kvp.Value.ContentType}\r\n\r\n");
                ms.Write(kvp.Value.Content, 0, kvp.Value.Content.Length);
                WriteStr("\r\n");
            }

        WriteStr($"--{boundary}--\r\n");

        headers ??= new Dictionary<string, string>();
        headers["Content-Type"] = $"multipart/form-data; boundary={boundary}";
        return Post(url, ms.ToArray(), headers, parameters, cookies, auth, timeout, fetchMode);
    }

    public Response Request(string method, string url, string? body = null, Dictionary<string, string>? headers = null, int? timeout = null, (string, string)? auth = null, IEnumerable<KeyValuePair<string, string>>? parameters = null, Dictionary<string, string>? cookies = null, string? fetchMode = null)
    {
        ThrowIfDisposed();

        url = AddParamsToUrl(url, parameters);
        headers = ApplyAuth(headers, auth);
        headers = ApplyCookies(headers, cookies);
        InferContentType(body, headers);

        var request = new RequestConfig
        {
            Method = method.ToUpperInvariant(),
            Url = url,
            Headers = headers.Count > 0 ? headers : null,
            Timeout = timeout * 1000,
            FetchMode = fetchMode,
        };

        string requestJson = JsonSerializer.Serialize(request, JsonContext.Relaxed.RequestConfig);
        byte[] bodyBytes = body != null ? System.Text.Encoding.UTF8.GetBytes(body) : Array.Empty<byte>();

        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        long responseHandle;

        if (bodyBytes.Length > 0)
        {
            unsafe
            {
                fixed (byte* bodyPtr = bodyBytes)
                {
                    responseHandle = Native.RequestRaw(_handle, requestJson, (IntPtr)bodyPtr, bodyBytes.Length);
                }
            }
        }
        else
        {
            responseHandle = Native.RequestRaw(_handle, requestJson, IntPtr.Zero, 0);
        }
        stopwatch.Stop();

        if (responseHandle < 0)
            throw new SensorException("Request failed");

        return ParseRawResponse(responseHandle, stopwatch.Elapsed);
    }

    public Response Put(string url, string? body = null, Dictionary<string, string>? headers = null, IEnumerable<KeyValuePair<string, string>>? parameters = null, Dictionary<string, string>? cookies = null, (string, string)? auth = null, int? timeout = null, string? fetchMode = null)
        => Request("PUT", url, body, headers, timeout, auth, parameters, cookies, fetchMode);

    public Response PutJson<T>(string url, T data, Dictionary<string, string>? headers = null, IEnumerable<KeyValuePair<string, string>>? parameters = null, Dictionary<string, string>? cookies = null, (string, string)? auth = null, int? timeout = null, string? fetchMode = null)
    {
        headers ??= new Dictionary<string, string>();
        if (!headers.ContainsKey("Content-Type"))
            headers["Content-Type"] = "application/json";

        string body = JsonSerializer.Serialize(data, _relaxedJsonOptions);
        return Put(url, body, headers, parameters, cookies, auth, timeout, fetchMode);
    }

    public Response Delete(string url, Dictionary<string, string>? headers = null, IEnumerable<KeyValuePair<string, string>>? parameters = null, Dictionary<string, string>? cookies = null, (string, string)? auth = null, int? timeout = null, string? fetchMode = null)
        => Request("DELETE", url, null, headers, timeout, auth, parameters, cookies, fetchMode);

    public Response Patch(string url, string? body = null, Dictionary<string, string>? headers = null, IEnumerable<KeyValuePair<string, string>>? parameters = null, Dictionary<string, string>? cookies = null, (string, string)? auth = null, int? timeout = null, string? fetchMode = null)
        => Request("PATCH", url, body, headers, timeout, auth, parameters, cookies, fetchMode);

    public Response PatchJson<T>(string url, T data, Dictionary<string, string>? headers = null, IEnumerable<KeyValuePair<string, string>>? parameters = null, Dictionary<string, string>? cookies = null, (string, string)? auth = null, int? timeout = null, string? fetchMode = null)
    {
        headers ??= new Dictionary<string, string>();
        if (!headers.ContainsKey("Content-Type"))
            headers["Content-Type"] = "application/json";

        string body = JsonSerializer.Serialize(data, _relaxedJsonOptions);
        return Patch(url, body, headers, parameters, cookies, auth, timeout, fetchMode);
    }

    public Response Head(string url, Dictionary<string, string>? headers = null, IEnumerable<KeyValuePair<string, string>>? parameters = null, Dictionary<string, string>? cookies = null, (string, string)? auth = null, int? timeout = null, string? fetchMode = null)
        => Request("HEAD", url, null, headers, timeout, auth, parameters, cookies, fetchMode);

    public Response Options(string url, Dictionary<string, string>? headers = null, IEnumerable<KeyValuePair<string, string>>? parameters = null, Dictionary<string, string>? cookies = null, (string, string)? auth = null, int? timeout = null, string? fetchMode = null)
        => Request("OPTIONS", url, null, headers, timeout, auth, parameters, cookies, fetchMode);

    public Response Post(string url, byte[] body, Dictionary<string, string>? headers = null, IEnumerable<KeyValuePair<string, string>>? parameters = null, Dictionary<string, string>? cookies = null, (string, string)? auth = null, int? timeout = null, string? fetchMode = null)
        => RequestBinary("POST", url, body, headers, timeout, auth, parameters, cookies, fetchMode);

    public Response Put(string url, byte[] body, Dictionary<string, string>? headers = null, IEnumerable<KeyValuePair<string, string>>? parameters = null, Dictionary<string, string>? cookies = null, (string, string)? auth = null, int? timeout = null, string? fetchMode = null)
        => RequestBinary("PUT", url, body, headers, timeout, auth, parameters, cookies, fetchMode);

    public Response Patch(string url, byte[] body, Dictionary<string, string>? headers = null, IEnumerable<KeyValuePair<string, string>>? parameters = null, Dictionary<string, string>? cookies = null, (string, string)? auth = null, int? timeout = null, string? fetchMode = null)
        => RequestBinary("PATCH", url, body, headers, timeout, auth, parameters, cookies, fetchMode);

    public Response Post(string url, Stream bodyStream, Dictionary<string, string>? headers = null, IEnumerable<KeyValuePair<string, string>>? parameters = null, Dictionary<string, string>? cookies = null, (string, string)? auth = null, int? timeout = null, string? fetchMode = null)
        => RequestStream("POST", url, bodyStream, headers, timeout, auth, parameters, cookies, fetchMode);

    public Response Put(string url, Stream bodyStream, Dictionary<string, string>? headers = null, IEnumerable<KeyValuePair<string, string>>? parameters = null, Dictionary<string, string>? cookies = null, (string, string)? auth = null, int? timeout = null, string? fetchMode = null)
        => RequestStream("PUT", url, bodyStream, headers, timeout, auth, parameters, cookies, fetchMode);

    public Response Patch(string url, Stream bodyStream, Dictionary<string, string>? headers = null, IEnumerable<KeyValuePair<string, string>>? parameters = null, Dictionary<string, string>? cookies = null, (string, string)? auth = null, int? timeout = null, string? fetchMode = null)
        => RequestStream("PATCH", url, bodyStream, headers, timeout, auth, parameters, cookies, fetchMode);

    public Response RequestBinary(string method, string url, byte[] body, Dictionary<string, string>? headers = null, int? timeout = null, (string, string)? auth = null, IEnumerable<KeyValuePair<string, string>>? parameters = null, Dictionary<string, string>? cookies = null, string? fetchMode = null)
    {
        ThrowIfDisposed();

        url = AddParamsToUrl(url, parameters);
        headers = ApplyAuth(headers, auth);
        headers = ApplyCookies(headers, cookies);

        var request = new RequestConfig
        {
            Method = method.ToUpperInvariant(),
            Url = url,
            Headers = headers.Count > 0 ? headers : null,
            Timeout = timeout,
            FetchMode = fetchMode,
        };

        string requestJson = JsonSerializer.Serialize(request, JsonContext.Relaxed.RequestConfig);

        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        long responseHandle;

        if (body != null && body.Length > 0)
        {
            unsafe
            {
                fixed (byte* bodyPtr = body)
                {
                    responseHandle = Native.RequestRaw(_handle, requestJson, (IntPtr)bodyPtr, body.Length);
                }
            }
        }
        else
        {
            responseHandle = Native.RequestRaw(_handle, requestJson, IntPtr.Zero, 0);
        }
        stopwatch.Stop();

        if (responseHandle < 0)
            throw new SensorException("Request failed");

        return ParseRawResponse(responseHandle, stopwatch.Elapsed);
    }

    public Response RequestStream(string method, string url, Stream bodyStream, Dictionary<string, string>? headers = null, int? timeout = null, (string, string)? auth = null, IEnumerable<KeyValuePair<string, string>>? parameters = null, Dictionary<string, string>? cookies = null, string? fetchMode = null)
    {
        using var ms = new MemoryStream();
        bodyStream.CopyTo(ms);
        return RequestBinary(method, url, ms.ToArray(), headers, timeout, auth, parameters, cookies, fetchMode);
    }

    public Task<Response> GetAsync(string url, Dictionary<string, string>? headers = null, IEnumerable<KeyValuePair<string, string>>? parameters = null, Dictionary<string, string>? cookies = null, (string, string)? auth = null, int? timeout = null, CancellationToken cancellationToken = default, string? fetchMode = null)
    {
        ThrowIfDisposed();

        url = AddParamsToUrl(url, parameters);
        headers = ApplyAuth(headers, auth);
        headers = ApplyCookies(headers, cookies);

        if (timeout != null)
            return RequestAsync("GET", url, null, headers, timeout, null, null, null, cancellationToken, fetchMode);

        var options = new RequestOptions { Headers = headers.Count > 0 ? headers : null, FetchMode = fetchMode };
        string? optionsJson = (options.Headers != null || options.FetchMode != null)
            ? JsonSerializer.Serialize(options, JsonContext.Relaxed.RequestOptions)
            : null;

        var (callbackId, task) = AsyncCallbackManager.Instance.RegisterRequest(cancellationToken);
        Native.GetAsync(_handle, url, optionsJson, callbackId);

        return task;
    }

    public Task<Response> PostAsync(string url, string? body = null, Dictionary<string, string>? headers = null, IEnumerable<KeyValuePair<string, string>>? parameters = null, Dictionary<string, string>? cookies = null, (string, string)? auth = null, int? timeout = null, CancellationToken cancellationToken = default, string? fetchMode = null)
    {
        ThrowIfDisposed();

        url = AddParamsToUrl(url, parameters);
        headers = ApplyAuth(headers, auth);
        headers = ApplyCookies(headers, cookies);
        InferContentType(body, headers);

        if (timeout != null)
            return RequestAsync("POST", url, body, headers, timeout, null, null, null, cancellationToken, fetchMode);

        var options = new RequestOptions { Headers = headers.Count > 0 ? headers : null, FetchMode = fetchMode };
        string? optionsJson = (options.Headers != null || options.FetchMode != null)
            ? JsonSerializer.Serialize(options, JsonContext.Relaxed.RequestOptions)
            : null;

        var (callbackId, task) = AsyncCallbackManager.Instance.RegisterRequest(cancellationToken);
        Native.PostAsync(_handle, url, body, optionsJson, callbackId);

        return task;
    }

    public Task<Response> PostJsonAsync<T>(string url, T data, Dictionary<string, string>? headers = null, IEnumerable<KeyValuePair<string, string>>? parameters = null, Dictionary<string, string>? cookies = null, (string, string)? auth = null, int? timeout = null, CancellationToken cancellationToken = default, string? fetchMode = null)
    {
        headers ??= new Dictionary<string, string>();
        if (!headers.ContainsKey("Content-Type"))
            headers["Content-Type"] = "application/json";

        string body = JsonSerializer.Serialize(data, _relaxedJsonOptions);
        return PostAsync(url, body, headers, parameters, cookies, auth, timeout, cancellationToken, fetchMode);
    }

    public Task<Response> PostFormAsync(string url, Dictionary<string, string> formData, Dictionary<string, string>? headers = null, IEnumerable<KeyValuePair<string, string>>? parameters = null, Dictionary<string, string>? cookies = null, (string, string)? auth = null, int? timeout = null, CancellationToken cancellationToken = default, string? fetchMode = null)
    {
        headers ??= new Dictionary<string, string>();
        if (!headers.ContainsKey("Content-Type"))
            headers["Content-Type"] = "application/x-www-form-urlencoded";

        string body = string.Join("&", formData.Select(kvp => $"{Uri.EscapeDataString(kvp.Key)}={Uri.EscapeDataString(kvp.Value)}"));
        return PostAsync(url, body, headers, parameters, cookies, auth, timeout, cancellationToken, fetchMode);
    }

    public Task<Response> RequestAsync(string method, string url, string? body = null, Dictionary<string, string>? headers = null, int? timeout = null, (string, string)? auth = null, IEnumerable<KeyValuePair<string, string>>? parameters = null, Dictionary<string, string>? cookies = null, CancellationToken cancellationToken = default, string? fetchMode = null)
    {
        ThrowIfDisposed();

        url = AddParamsToUrl(url, parameters);
        headers = ApplyAuth(headers, auth);
        headers = ApplyCookies(headers, cookies);
        InferContentType(body, headers);

        var request = new RequestConfig
        {
            Method = method.ToUpperInvariant(),
            Url = url,
            Body = body,
            Headers = headers.Count > 0 ? headers : null,
            Timeout = timeout,
            FetchMode = fetchMode,
        };

        string requestJson = JsonSerializer.Serialize(request, JsonContext.Relaxed.RequestConfig);

        var (callbackId, task) = AsyncCallbackManager.Instance.RegisterRequest(cancellationToken);
        Native.RequestAsync(_handle, requestJson, callbackId);

        return task;
    }

    public Task<Response> PutAsync(string url, string? body = null, Dictionary<string, string>? headers = null, IEnumerable<KeyValuePair<string, string>>? parameters = null, Dictionary<string, string>? cookies = null, (string, string)? auth = null, int? timeout = null, CancellationToken cancellationToken = default, string? fetchMode = null)
        => RequestAsync("PUT", url, body, headers, timeout, auth, parameters, cookies, cancellationToken, fetchMode);

    public Task<Response> PutJsonAsync<T>(string url, T data, Dictionary<string, string>? headers = null, IEnumerable<KeyValuePair<string, string>>? parameters = null, Dictionary<string, string>? cookies = null, (string, string)? auth = null, int? timeout = null, CancellationToken cancellationToken = default, string? fetchMode = null)
    {
        headers ??= new Dictionary<string, string>();
        if (!headers.ContainsKey("Content-Type"))
            headers["Content-Type"] = "application/json";

        string body = JsonSerializer.Serialize(data, _relaxedJsonOptions);
        return PutAsync(url, body, headers, parameters, cookies, auth, timeout, cancellationToken, fetchMode);
    }

    public Task<Response> DeleteAsync(string url, Dictionary<string, string>? headers = null, IEnumerable<KeyValuePair<string, string>>? parameters = null, Dictionary<string, string>? cookies = null, (string, string)? auth = null, int? timeout = null, CancellationToken cancellationToken = default, string? fetchMode = null)
        => RequestAsync("DELETE", url, null, headers, timeout, auth, parameters, cookies, cancellationToken, fetchMode);

    public Task<Response> PatchAsync(string url, string? body = null, Dictionary<string, string>? headers = null, IEnumerable<KeyValuePair<string, string>>? parameters = null, Dictionary<string, string>? cookies = null, (string, string)? auth = null, int? timeout = null, CancellationToken cancellationToken = default, string? fetchMode = null)
        => RequestAsync("PATCH", url, body, headers, timeout, auth, parameters, cookies, cancellationToken, fetchMode);

    public Task<Response> PatchJsonAsync<T>(string url, T data, Dictionary<string, string>? headers = null, IEnumerable<KeyValuePair<string, string>>? parameters = null, Dictionary<string, string>? cookies = null, (string, string)? auth = null, int? timeout = null, CancellationToken cancellationToken = default, string? fetchMode = null)
    {
        headers ??= new Dictionary<string, string>();
        if (!headers.ContainsKey("Content-Type"))
            headers["Content-Type"] = "application/json";

        string body = JsonSerializer.Serialize(data, _relaxedJsonOptions);
        return PatchAsync(url, body, headers, parameters, cookies, auth, timeout, cancellationToken, fetchMode);
    }

    public Task<Response> HeadAsync(string url, Dictionary<string, string>? headers = null, IEnumerable<KeyValuePair<string, string>>? parameters = null, Dictionary<string, string>? cookies = null, (string, string)? auth = null, int? timeout = null, CancellationToken cancellationToken = default, string? fetchMode = null)
        => RequestAsync("HEAD", url, null, headers, timeout, auth, parameters, cookies, cancellationToken, fetchMode);

    public Task<Response> OptionsAsync(string url, Dictionary<string, string>? headers = null, IEnumerable<KeyValuePair<string, string>>? parameters = null, Dictionary<string, string>? cookies = null, (string, string)? auth = null, int? timeout = null, CancellationToken cancellationToken = default, string? fetchMode = null)
        => RequestAsync("OPTIONS", url, null, headers, timeout, auth, parameters, cookies, cancellationToken, fetchMode);

    public List<Cookie> GetCookiesDetailed()
    {
        ThrowIfDisposed();

        IntPtr resultPtr = Native.GetCookies(_handle);
        string? json = Native.PtrToStringAndFree(resultPtr);

        if (string.IsNullOrEmpty(json))
            return new List<Cookie>();

        var cookieDataList = JsonSerializer.Deserialize(json, JsonContext.Default.ListCookieData)
            ?? new List<CookieData>();

        return cookieDataList.Select(c => new Cookie(
            c.Name ?? "", c.Value ?? "", c.Domain ?? "", c.Path ?? "",
            c.Expires ?? "", c.MaxAge, c.Secure, c.HttpOnly, c.SameSite ?? ""))
            .ToList();
    }

    public List<Cookie> GetCookies()
    {
        return GetCookiesDetailed();
    }

    public void SetCookie(string name, string value, string? domain = null, string? path = null,
        bool secure = false, bool httpOnly = false, string? sameSite = null, long maxAge = 0, string? expires = null)
    {
        ThrowIfDisposed();
        var cookie = new CookieData
        {
            Name = name,
            Value = value,
            Domain = domain ?? "",
            Path = path ?? "/",
            Secure = secure,
            HttpOnly = httpOnly,
            SameSite = sameSite ?? "",
            MaxAge = maxAge,
            Expires = expires ?? "",
        };
        string cookieJson = JsonSerializer.Serialize(cookie, JsonContext.Default.CookieData);
        Native.SetCookie(_handle, cookieJson);
    }

    public Cookie? GetCookieDetailed(string name)
    {
        ThrowIfDisposed();
        var cookies = GetCookiesDetailed();
        return cookies.FirstOrDefault(c => c.Name == name);
    }

    public Cookie? GetCookie(string name)
    {
        return GetCookieDetailed(name);
    }

    public void DeleteCookie(string name, string domain = "")
    {
        ThrowIfDisposed();
        Native.DeleteCookie(_handle, name, domain);
    }

    public void ClearCookies()
    {
        ThrowIfDisposed();
        Native.ClearCookies(_handle);
    }

    public void SetProxy(string? proxyUrl)
    {
        ThrowIfDisposed();
        Native.SessionSetProxy(_handle, proxyUrl ?? "");
    }

    public void SetTcpProxy(string? proxyUrl)
    {
        ThrowIfDisposed();
        Native.SessionSetTcpProxy(_handle, proxyUrl ?? "");
    }

    public void SetUdpProxy(string? proxyUrl)
    {
        ThrowIfDisposed();
        Native.SessionSetUdpProxy(_handle, proxyUrl ?? "");
    }

    public string GetProxy()
    {
        ThrowIfDisposed();
        IntPtr resultPtr = Native.SessionGetProxy(_handle);
        return Native.PtrToStringAndFree(resultPtr) ?? "";
    }

    public string GetTcpProxy()
    {
        ThrowIfDisposed();
        IntPtr resultPtr = Native.SessionGetTcpProxy(_handle);
        return Native.PtrToStringAndFree(resultPtr) ?? "";
    }

    public string GetUdpProxy()
    {
        ThrowIfDisposed();
        IntPtr resultPtr = Native.SessionGetUdpProxy(_handle);
        return Native.PtrToStringAndFree(resultPtr) ?? "";
    }

    public void SetHeaderOrder(string[]? order)
    {
        ThrowIfDisposed();
        var orderJson = order != null && order.Length > 0
            ? System.Text.Json.JsonSerializer.Serialize(order)
            : "[]";
        IntPtr resultPtr = Native.SessionSetHeaderOrder(_handle, orderJson);
        var result = Native.PtrToStringAndFree(resultPtr);
        if (!string.IsNullOrEmpty(result) && result.Contains("error"))
        {
            var data = System.Text.Json.JsonDocument.Parse(result);
            if (data.RootElement.TryGetProperty("error", out var errorElement))
            {
                throw new InvalidOperationException(errorElement.GetString());
            }
        }
    }

    public string[] GetHeaderOrder()
    {
        ThrowIfDisposed();
        IntPtr resultPtr = Native.SessionGetHeaderOrder(_handle);
        var result = Native.PtrToStringAndFree(resultPtr);
        if (!string.IsNullOrEmpty(result))
        {
            return System.Text.Json.JsonSerializer.Deserialize<string[]>(result) ?? Array.Empty<string>();
        }
        return Array.Empty<string>();
    }

    public void SetSessionIdentifier(string? sessionId)
    {
        ThrowIfDisposed();
        Native.SessionSetIdentifier(_handle, sessionId);
    }

    public string Proxy
    {
        get => GetProxy();
        set => SetProxy(value);
    }

    public void Save(string path)
    {
        ThrowIfDisposed();

        IntPtr resultPtr = Native.SessionSave(_handle, path);
        string? result = Native.PtrToStringAndFree(resultPtr);

        if (!string.IsNullOrEmpty(result))
        {
            if (result.Contains("\"error\""))
            {
                var error = JsonSerializer.Deserialize(result, JsonContext.Default.ErrorResponse);
                if (error?.Error != null)
                    throw new SensorException(error.Error);
            }
        }
    }

    public string Marshal()
    {
        ThrowIfDisposed();

        IntPtr resultPtr = Native.SessionMarshal(_handle);
        string? result = Native.PtrToStringAndFree(resultPtr);

        if (string.IsNullOrEmpty(result))
            throw new SensorException("Failed to marshal session");

        if (result.Contains("\"error\""))
        {
            var error = JsonSerializer.Deserialize(result, JsonContext.Default.ErrorResponse);
            if (error?.Error != null)
                throw new SensorException(error.Error);
        }

        return result;
    }

    public static Session Load(string path)
    {
        long handle = Native.SessionLoad(path);

        if (handle < 0 || handle == 0)
            throw new SensorException($"Failed to load session from {path}");

        return new Session(handle);
    }

    public static Session Unmarshal(string data)
    {
        long handle = Native.SessionUnmarshal(data);

        if (handle < 0 || handle == 0)
            throw new SensorException("Failed to unmarshal session");

        return new Session(handle);
    }

    private Session(long handle)
    {
        _handle = handle;
        Auth = null;
    }

    public StreamResponse GetStream(string url, Dictionary<string, string>? headers = null, IEnumerable<KeyValuePair<string, string>>? parameters = null, Dictionary<string, string>? cookies = null, (string, string)? auth = null, int? timeout = null, string? fetchMode = null)
    {
        ThrowIfDisposed();

        url = AddParamsToUrl(url, parameters);
        headers = ApplyAuth(headers, auth);
        headers = ApplyCookies(headers, cookies);

        var options = new StreamOptions { Headers = headers.Count > 0 ? headers : null, Timeout = timeout, FetchMode = fetchMode };
        string? optionsJson = JsonSerializer.Serialize(options, JsonContext.Relaxed.StreamOptions);

        long streamHandle = Native.StreamGet(_handle, url, optionsJson);
        if (streamHandle < 0)
            throw new SensorException("Failed to start streaming request");

        return CreateStreamResponse(streamHandle);
    }

    public StreamResponse PostStream(string url, string? body = null, Dictionary<string, string>? headers = null, IEnumerable<KeyValuePair<string, string>>? parameters = null, Dictionary<string, string>? cookies = null, (string, string)? auth = null, int? timeout = null, string? fetchMode = null)
    {
        ThrowIfDisposed();

        url = AddParamsToUrl(url, parameters);
        headers = ApplyAuth(headers, auth);
        headers = ApplyCookies(headers, cookies);
        InferContentType(body, headers);

        var options = new StreamOptions { Headers = headers.Count > 0 ? headers : null, Timeout = timeout, FetchMode = fetchMode };
        string? optionsJson = JsonSerializer.Serialize(options, JsonContext.Relaxed.StreamOptions);

        long streamHandle = Native.StreamPost(_handle, url, body, optionsJson);
        if (streamHandle < 0)
            throw new SensorException("Failed to start streaming request");

        return CreateStreamResponse(streamHandle);
    }

    public StreamResponse RequestStream(string method, string url, string? body = null, Dictionary<string, string>? headers = null, IEnumerable<KeyValuePair<string, string>>? parameters = null, Dictionary<string, string>? cookies = null, (string, string)? auth = null, int? timeout = null, string? fetchMode = null)
    {
        ThrowIfDisposed();

        url = AddParamsToUrl(url, parameters);
        headers = ApplyAuth(headers, auth);
        headers = ApplyCookies(headers, cookies);
        InferContentType(body, headers);

        var request = new RequestConfig
        {
            Method = method.ToUpperInvariant(),
            Url = url,
            Body = body,
            Headers = headers.Count > 0 ? headers : null,
            Timeout = timeout,
            FetchMode = fetchMode,
        };

        string requestJson = JsonSerializer.Serialize(request, JsonContext.Relaxed.RequestConfig);

        long streamHandle = Native.StreamRequest(_handle, requestJson);
        if (streamHandle < 0)
            throw new SensorException("Failed to start streaming request");

        return CreateStreamResponse(streamHandle);
    }

    private static StreamResponse CreateStreamResponse(long streamHandle)
    {
        IntPtr metadataPtr = Native.StreamGetMetadata(streamHandle);
        string? metadataJson = Native.PtrToStringAndFree(metadataPtr);

        if (string.IsNullOrEmpty(metadataJson))
        {
            Native.StreamClose(streamHandle);
            throw new SensorException("Failed to get stream metadata");
        }

        if (metadataJson.Contains("\"error\""))
        {
            var error = JsonSerializer.Deserialize(metadataJson, JsonContext.Default.ErrorResponse);
            if (error?.Error != null)
            {
                Native.StreamClose(streamHandle);
                throw new SensorException(error.Error);
            }
        }

        var metadata = JsonSerializer.Deserialize(metadataJson, JsonContext.Default.StreamMetadata);
        if (metadata == null)
        {
            Native.StreamClose(streamHandle);
            throw new SensorException("Failed to parse stream metadata");
        }

        return new StreamResponse(streamHandle, metadata);
    }

    private static Response ParseRawResponse(long responseHandle, TimeSpan elapsed = default)
    {
        try
        {
            IntPtr metaPtr = Native.ResponseGetMetadata(responseHandle);
            string? metaJson = Native.PtrToStringAndFree(metaPtr);

            if (string.IsNullOrEmpty(metaJson))
                throw new SensorException("No response metadata received");

            if (metaJson.Contains("\"error\""))
            {
                var error = JsonSerializer.Deserialize(metaJson, JsonContext.Default.ErrorResponse);
                if (error?.Error != null)
                    throw new SensorException(error.Error);
            }

            var metadata = JsonSerializer.Deserialize(metaJson, JsonContext.Default.FastResponseMetadata);
            if (metadata == null)
                throw new SensorException("Failed to parse response metadata");

            int bodyLen = Native.ResponseGetBodyLen(responseHandle);
            byte[] content;

            if (bodyLen > 0)
            {
                content = new byte[bodyLen];
                unsafe
                {
                    fixed (byte* bufPtr = content)
                    {
                        Native.ResponseCopyBodyTo(responseHandle, (IntPtr)bufPtr, bodyLen);
                    }
                }
            }
            else
            {
                content = Array.Empty<byte>();
            }

            return new Response(metadata, content, elapsed);
        }
        finally
        {
            Native.ResponseFree(responseHandle);
        }
    }

    private static FastResponse ParseFastResponse(long responseHandle, TimeSpan elapsed = default)
    {
        try
        {
            IntPtr metaPtr = Native.ResponseGetMetadata(responseHandle);
            string? metaJson = Native.PtrToStringAndFree(metaPtr);

            if (string.IsNullOrEmpty(metaJson))
                throw new SensorException("No response metadata received");

            if (metaJson.Contains("\"error\""))
            {
                var error = JsonSerializer.Deserialize(metaJson, JsonContext.Default.ErrorResponse);
                if (error?.Error != null)
                    throw new SensorException(error.Error);
            }

            var metadata = JsonSerializer.Deserialize(metaJson, JsonContext.Default.FastResponseMetadata);
            if (metadata == null)
                throw new SensorException("Failed to parse response metadata");

            int bodyLen = Native.ResponseGetBodyLen(responseHandle);
            byte[] content;

            if (bodyLen > 0)
            {
                content = new byte[bodyLen];
                unsafe
                {
                    fixed (byte* bufPtr = content)
                    {
                        Native.ResponseCopyBodyTo(responseHandle, (IntPtr)bufPtr, bodyLen);
                    }
                }
            }
            else
            {
                content = Array.Empty<byte>();
            }

            return new FastResponse(metadata, content, elapsed);
        }
        finally
        {
            Native.ResponseFree(responseHandle);
        }
    }

    public FastResponse GetFast(string url, Dictionary<string, string>? headers = null, IEnumerable<KeyValuePair<string, string>>? parameters = null, Dictionary<string, string>? cookies = null, (string, string)? auth = null, string? fetchMode = null)
    {
        ThrowIfDisposed();

        url = AddParamsToUrl(url, parameters);
        headers = ApplyAuth(headers, auth);
        headers = ApplyCookies(headers, cookies);

        var options = new RequestOptions { Headers = headers.Count > 0 ? headers : null, FetchMode = fetchMode };
        string? optionsJson = (headers.Count > 0 || fetchMode != null)
            ? JsonSerializer.Serialize(options, JsonContext.Relaxed.RequestOptions)
            : null;

        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        long responseHandle = Native.GetRaw(_handle, url, optionsJson);
        stopwatch.Stop();

        if (responseHandle < 0)
            throw new SensorException("Request failed");

        return ParseFastResponse(responseHandle, stopwatch.Elapsed);
    }

    public FastResponse PostFast(string url, byte[]? body = null, Dictionary<string, string>? headers = null, IEnumerable<KeyValuePair<string, string>>? parameters = null, Dictionary<string, string>? cookies = null, (string, string)? auth = null, string? fetchMode = null)
    {
        ThrowIfDisposed();

        url = AddParamsToUrl(url, parameters);
        headers = ApplyAuth(headers, auth);
        headers = ApplyCookies(headers, cookies);

        var options = new RequestOptions { Headers = headers.Count > 0 ? headers : null, FetchMode = fetchMode };
        string? optionsJson = (headers.Count > 0 || fetchMode != null)
            ? JsonSerializer.Serialize(options, JsonContext.Relaxed.RequestOptions)
            : null;

        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        long responseHandle;

        if (body != null && body.Length > 0)
        {
            unsafe
            {
                fixed (byte* bodyPtr = body)
                {
                    responseHandle = Native.PostRaw(_handle, url, (IntPtr)bodyPtr, body.Length, optionsJson);
                }
            }
        }
        else
        {
            responseHandle = Native.PostRaw(_handle, url, IntPtr.Zero, 0, optionsJson);
        }
        stopwatch.Stop();

        if (responseHandle < 0)
            throw new SensorException("Request failed");

        return ParseFastResponse(responseHandle, stopwatch.Elapsed);
    }

    public FastResponse RequestFast(string method, string url, byte[]? body = null, Dictionary<string, string>? headers = null, IEnumerable<KeyValuePair<string, string>>? parameters = null, Dictionary<string, string>? cookies = null, (string, string)? auth = null, int? timeout = null, string? fetchMode = null)
    {
        ThrowIfDisposed();

        url = AddParamsToUrl(url, parameters);
        headers = ApplyAuth(headers, auth);
        headers = ApplyCookies(headers, cookies);

        var request = new RequestConfig
        {
            Method = method.ToUpperInvariant(),
            Url = url,
            Headers = headers.Count > 0 ? headers : null,
            Timeout = timeout,
            FetchMode = fetchMode,
        };

        string requestJson = JsonSerializer.Serialize(request, JsonContext.Relaxed.RequestConfig);

        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        long responseHandle;

        if (body != null && body.Length > 0)
        {
            unsafe
            {
                fixed (byte* bodyPtr = body)
                {
                    responseHandle = Native.RequestRaw(_handle, requestJson, (IntPtr)bodyPtr, body.Length);
                }
            }
        }
        else
        {
            responseHandle = Native.RequestRaw(_handle, requestJson, IntPtr.Zero, 0);
        }
        stopwatch.Stop();

        if (responseHandle < 0)
            throw new SensorException("Request failed");

        return ParseFastResponse(responseHandle, stopwatch.Elapsed);
    }

    public FastResponse PutFast(string url, byte[]? body = null, Dictionary<string, string>? headers = null, IEnumerable<KeyValuePair<string, string>>? parameters = null, Dictionary<string, string>? cookies = null, (string, string)? auth = null, int? timeout = null, string? fetchMode = null)
        => RequestFast("PUT", url, body, headers, parameters, cookies, auth, timeout, fetchMode);

    public FastResponse DeleteFast(string url, Dictionary<string, string>? headers = null, IEnumerable<KeyValuePair<string, string>>? parameters = null, Dictionary<string, string>? cookies = null, (string, string)? auth = null, int? timeout = null, string? fetchMode = null)
        => RequestFast("DELETE", url, null, headers, parameters, cookies, auth, timeout, fetchMode);

    public FastResponse PatchFast(string url, byte[]? body = null, Dictionary<string, string>? headers = null, IEnumerable<KeyValuePair<string, string>>? parameters = null, Dictionary<string, string>? cookies = null, (string, string)? auth = null, int? timeout = null, string? fetchMode = null)
        => RequestFast("PATCH", url, body, headers, parameters, cookies, auth, timeout, fetchMode);

    public void Warmup(string url, long timeoutMs = 0)
    {
        ThrowIfDisposed();
        IntPtr resultPtr = Native.SessionWarmup(_handle, url, timeoutMs);
        if (resultPtr != IntPtr.Zero)
        {
            string? result = Native.PtrToStringAndFree(resultPtr);
            if (!string.IsNullOrEmpty(result))
            {
                var error = JsonSerializer.Deserialize(result, JsonContext.Default.ErrorResponse);
                if (error?.Error != null)
                    throw new SensorException(error.Error);
            }
        }
    }

    public Session[] Fork(int n = 1)
    {
        ThrowIfDisposed();
        var forks = new Session[n];
        for (int i = 0; i < n; i++)
        {
            long handle = Native.SessionFork(_handle);
            if (handle < 0 || handle == 0)
                throw new SensorException("Failed to fork session");
            forks[i] = new Session(handle);
        }
        return forks;
    }

    public void Refresh(string? switchProtocol = null)
    {
        ThrowIfDisposed();
        if (switchProtocol != null)
        {
            IntPtr resultPtr = Native.SessionRefreshProtocol(_handle, switchProtocol);
            if (resultPtr != IntPtr.Zero)
            {
                string? result = Native.PtrToStringAndFree(resultPtr);
                if (!string.IsNullOrEmpty(result))
                {
                    var error = JsonSerializer.Deserialize(result, JsonContext.Default.ErrorResponse);
                    if (error?.Error != null)
                        throw new SensorException(error.Error);
                }
            }
        }
        else
        {
            Native.SessionRefresh(_handle);
        }
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(Session));
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            if (_handle != 0)
            {
                Native.SessionFree(_handle);
                _handle = 0;
            }
            _disposed = true;
            GC.SuppressFinalize(this);
        }
    }

    ~Session()
    {
        Dispose();
    }
}

public sealed class Cookie
{
    public string Name { get; }

    public string Value { get; }

    public string Domain { get; }

    public string Path { get; }

    public string Expires { get; }

    public long MaxAge { get; }

    public bool Secure { get; }

    public bool HttpOnly { get; }

    public string SameSite { get; }

    internal Cookie(string name, string value, string domain = "", string path = "",
        string expires = "", long maxAge = 0, bool secure = false, bool httpOnly = false, string sameSite = "")
    {
        Name = name;
        Value = value;
        Domain = domain ?? "";
        Path = path ?? "";
        Expires = expires ?? "";
        MaxAge = maxAge;
        Secure = secure;
        HttpOnly = httpOnly;
        SameSite = sameSite ?? "";
    }

    public override string ToString() => $"Cookie(Name={Name}, Value={Value}, Domain={Domain})";
}

public sealed class RedirectInfo
{
    public int StatusCode { get; }

    public string Url { get; }

    public Dictionary<string, string[]> Headers { get; }

    internal RedirectInfo(int statusCode, string url, Dictionary<string, string[]>? headers)
    {
        StatusCode = statusCode;
        Url = url;
        Headers = headers ?? new Dictionary<string, string[]>();
    }

    public string? GetHeader(string name)
    {
        if (Headers.TryGetValue(name, out var values) && values.Length > 0)
            return values[0];
        var key = Headers.Keys.FirstOrDefault(k => k.Equals(name, StringComparison.OrdinalIgnoreCase));
        if (key != null && Headers.TryGetValue(key, out values) && values.Length > 0)
            return values[0];
        return null;
    }

    public override string ToString() => $"RedirectInfo(StatusCode={StatusCode}, Url={Url})";
}

public sealed class Response
{
    private static readonly Dictionary<int, string> HttpStatusPhrases = new()
    {
        { 100, "Continue" }, { 101, "Switching Protocols" }, { 102, "Processing" },
        { 200, "OK" }, { 201, "Created" }, { 202, "Accepted" }, { 203, "Non-Authoritative Information" },
        { 204, "No Content" }, { 205, "Reset Content" }, { 206, "Partial Content" }, { 207, "Multi-Status" },
        { 300, "Multiple Choices" }, { 301, "Moved Permanently" }, { 302, "Found" }, { 303, "See Other" },
        { 304, "Not Modified" }, { 305, "Use Proxy" }, { 307, "Temporary Redirect" }, { 308, "Permanent Redirect" },
        { 400, "Bad Request" }, { 401, "Unauthorized" }, { 402, "Payment Required" }, { 403, "Forbidden" },
        { 404, "Not Found" }, { 405, "Method Not Allowed" }, { 406, "Not Acceptable" },
        { 407, "Proxy Authentication Required" }, { 408, "Request Timeout" }, { 409, "Conflict" },
        { 410, "Gone" }, { 411, "Length Required" }, { 412, "Precondition Failed" },
        { 413, "Payload Too Large" }, { 414, "URI Too Long" }, { 415, "Unsupported Media Type" },
        { 416, "Range Not Satisfiable" }, { 417, "Expectation Failed" }, { 418, "I'm a teapot" },
        { 421, "Misdirected Request" }, { 422, "Unprocessable Entity" }, { 423, "Locked" },
        { 424, "Failed Dependency" }, { 425, "Too Early" }, { 426, "Upgrade Required" },
        { 428, "Precondition Required" }, { 429, "Too Many Requests" },
        { 431, "Request Header Fields Too Large" }, { 451, "Unavailable For Legal Reasons" },
        { 500, "Internal Server Error" }, { 501, "Not Implemented" }, { 502, "Bad Gateway" },
        { 503, "Service Unavailable" }, { 504, "Gateway Timeout" }, { 505, "HTTP Version Not Supported" },
        { 506, "Variant Also Negotiates" }, { 507, "Insufficient Storage" }, { 508, "Loop Detected" },
        { 510, "Not Extended" }, { 511, "Network Authentication Required" },
    };

    internal Response(ResponseData data, TimeSpan elapsed = default)
    {
        StatusCode = data.StatusCode;
        Headers = data.Headers ?? new Dictionary<string, string[]>();
        var bodyStr = data.Body ?? "";
        if (data.BodyEncoding == "base64")
        {
            _content = Convert.FromBase64String(bodyStr);
            Text = System.Text.Encoding.UTF8.GetString(_content); // best-effort text view
        }
        else
        {
            Text = bodyStr;
            _content = System.Text.Encoding.UTF8.GetBytes(bodyStr);
        }
        Url = data.FinalUrl ?? "";
        Protocol = data.Protocol ?? "";
        Elapsed = elapsed;

        Cookies = data.Cookies?.Select(c => new Cookie(c.Name ?? "", c.Value ?? "", c.Domain ?? "", c.Path ?? "", c.Expires ?? "", c.MaxAge, c.Secure, c.HttpOnly, c.SameSite ?? "")).ToList()
            ?? new List<Cookie>();

        History = data.History?.Select(h => new RedirectInfo(h.StatusCode, h.Url ?? "", h.Headers)).ToList()
            ?? new List<RedirectInfo>();
    }

    internal Response(FastResponseMetadata metadata, byte[] rawBody, TimeSpan elapsed = default)
    {
        StatusCode = metadata.StatusCode;
        Headers = metadata.Headers ?? new Dictionary<string, string[]>();
        _content = rawBody;
        Text = System.Text.Encoding.UTF8.GetString(rawBody);
        Url = metadata.FinalUrl ?? "";
        Protocol = metadata.Protocol ?? "";
        Elapsed = elapsed;

        Cookies = metadata.Cookies?.Select(c => new Cookie(c.Name ?? "", c.Value ?? "", c.Domain ?? "", c.Path ?? "", c.Expires ?? "", c.MaxAge, c.Secure, c.HttpOnly, c.SameSite ?? "")).ToList()
            ?? new List<Cookie>();

        History = metadata.History?.Select(h => new RedirectInfo(h.StatusCode, h.Url ?? "", h.Headers)).ToList()
            ?? new List<RedirectInfo>();
    }

    public int StatusCode { get; }

    public Dictionary<string, string[]> Headers { get; }

    public string? GetHeader(string name)
    {
        if (Headers.TryGetValue(name, out var values) && values.Length > 0)
            return values[0];

        var key = Headers.Keys.FirstOrDefault(k => k.Equals(name, StringComparison.OrdinalIgnoreCase));
        if (key != null && Headers.TryGetValue(key, out values) && values.Length > 0)
            return values[0];

        return null;
    }

    public string[] GetHeaders(string name)
    {
        if (Headers.TryGetValue(name, out var values))
            return values;

        var key = Headers.Keys.FirstOrDefault(k => k.Equals(name, StringComparison.OrdinalIgnoreCase));
        if (key != null && Headers.TryGetValue(key, out values))
            return values;

        return Array.Empty<string>();
    }

    private readonly byte[] _content;

    public string Text { get; }

    public byte[] Content => _content;

    public string Url { get; }

    public string Protocol { get; }

    public bool Ok => StatusCode < 400;

    public TimeSpan Elapsed { get; }

    public List<Cookie> Cookies { get; }

    public List<RedirectInfo> History { get; }

    public string Reason => HttpStatusPhrases.TryGetValue(StatusCode, out var phrase) ? phrase : "Unknown";

    public string? Encoding
    {
        get
        {
            string? contentType = GetHeader("Content-Type");
            if (string.IsNullOrEmpty(contentType))
                return null;

            if (contentType.Contains("charset="))
            {
                foreach (var part in contentType.Split(';'))
                {
                    var trimmed = part.Trim();
                    if (trimmed.StartsWith("charset=", StringComparison.OrdinalIgnoreCase))
                    {
                        return trimmed.Substring(8).Trim().Trim('"', '\'');
                    }
                }
            }
            return null;
        }
    }

    public T? Json<T>() => JsonSerializer.Deserialize<T>(Text);

    public void RaiseForStatus()
    {
        if (!Ok)
            throw new SensorException($"HTTP {StatusCode}: {Reason}");
    }
}

public sealed class FastResponse
{
    private static readonly Dictionary<int, string> HttpStatusPhrases = new()
    {
        { 100, "Continue" }, { 101, "Switching Protocols" }, { 102, "Processing" },
        { 200, "OK" }, { 201, "Created" }, { 202, "Accepted" }, { 203, "Non-Authoritative Information" },
        { 204, "No Content" }, { 205, "Reset Content" }, { 206, "Partial Content" }, { 207, "Multi-Status" },
        { 300, "Multiple Choices" }, { 301, "Moved Permanently" }, { 302, "Found" }, { 303, "See Other" },
        { 304, "Not Modified" }, { 305, "Use Proxy" }, { 307, "Temporary Redirect" }, { 308, "Permanent Redirect" },
        { 400, "Bad Request" }, { 401, "Unauthorized" }, { 402, "Payment Required" }, { 403, "Forbidden" },
        { 404, "Not Found" }, { 405, "Method Not Allowed" }, { 406, "Not Acceptable" },
        { 407, "Proxy Authentication Required" }, { 408, "Request Timeout" }, { 409, "Conflict" },
        { 410, "Gone" }, { 411, "Length Required" }, { 412, "Precondition Failed" },
        { 413, "Payload Too Large" }, { 414, "URI Too Long" }, { 415, "Unsupported Media Type" },
        { 416, "Range Not Satisfiable" }, { 417, "Expectation Failed" }, { 418, "I'm a teapot" },
        { 421, "Misdirected Request" }, { 422, "Unprocessable Entity" }, { 423, "Locked" },
        { 424, "Failed Dependency" }, { 425, "Too Early" }, { 426, "Upgrade Required" },
        { 428, "Precondition Required" }, { 429, "Too Many Requests" },
        { 431, "Request Header Fields Too Large" }, { 451, "Unavailable For Legal Reasons" },
        { 500, "Internal Server Error" }, { 501, "Not Implemented" }, { 502, "Bad Gateway" },
        { 503, "Service Unavailable" }, { 504, "Gateway Timeout" }, { 505, "HTTP Version Not Supported" },
        { 506, "Variant Also Negotiates" }, { 507, "Insufficient Storage" }, { 508, "Loop Detected" },
        { 510, "Not Extended" }, { 511, "Network Authentication Required" },
    };

    internal FastResponse(FastResponseMetadata metadata, byte[] content, TimeSpan elapsed = default)
    {
        StatusCode = metadata.StatusCode;
        Headers = metadata.Headers ?? new Dictionary<string, string[]>();
        Content = content;
        Url = metadata.FinalUrl ?? "";
        Protocol = metadata.Protocol ?? "";
        Elapsed = elapsed;

        Cookies = metadata.Cookies?.Select(c => new Cookie(c.Name ?? "", c.Value ?? "", c.Domain ?? "", c.Path ?? "", c.Expires ?? "", c.MaxAge, c.Secure, c.HttpOnly, c.SameSite ?? "")).ToList()
            ?? new List<Cookie>();

        History = metadata.History?.Select(h => new RedirectInfo(h.StatusCode, h.Url ?? "", h.Headers)).ToList()
            ?? new List<RedirectInfo>();
    }

    public int StatusCode { get; }

    public Dictionary<string, string[]> Headers { get; }

    public string? GetHeader(string name)
    {
        if (Headers.TryGetValue(name, out var values) && values.Length > 0)
            return values[0];

        var key = Headers.Keys.FirstOrDefault(k => k.Equals(name, StringComparison.OrdinalIgnoreCase));
        if (key != null && Headers.TryGetValue(key, out values) && values.Length > 0)
            return values[0];

        return null;
    }

    public string[] GetHeaders(string name)
    {
        if (Headers.TryGetValue(name, out var values))
            return values;

        var key = Headers.Keys.FirstOrDefault(k => k.Equals(name, StringComparison.OrdinalIgnoreCase));
        if (key != null && Headers.TryGetValue(key, out values))
            return values;

        return Array.Empty<string>();
    }

    public byte[] Content { get; }

    public string Text => System.Text.Encoding.UTF8.GetString(Content);

    public string Url { get; }

    public string Protocol { get; }

    public bool Ok => StatusCode < 400;

    public TimeSpan Elapsed { get; }

    public List<Cookie> Cookies { get; }

    public List<RedirectInfo> History { get; }

    public string Reason => HttpStatusPhrases.TryGetValue(StatusCode, out var phrase) ? phrase : "Unknown";

    public string? Encoding
    {
        get
        {
            string? contentType = GetHeader("Content-Type");
            if (string.IsNullOrEmpty(contentType))
                return null;

            if (contentType.Contains("charset="))
            {
                foreach (var part in contentType.Split(';'))
                {
                    var trimmed = part.Trim();
                    if (trimmed.StartsWith("charset=", StringComparison.OrdinalIgnoreCase))
                    {
                        return trimmed.Substring(8).Trim().Trim('"', '\'');
                    }
                }
            }
            return null;
        }
    }

    public T? Json<T>() => JsonSerializer.Deserialize<T>(Text);

    public void RaiseForStatus()
    {
        if (!Ok)
            throw new SensorException($"HTTP {StatusCode}: {Reason}");
    }
}

public class SensorException : Exception
{
    public SensorException(string message) : base(message) { }
}

public sealed class StreamResponse : IDisposable
{
    private static readonly Dictionary<int, string> HttpStatusPhrases = new()
    {
        { 100, "Continue" }, { 101, "Switching Protocols" }, { 102, "Processing" },
        { 200, "OK" }, { 201, "Created" }, { 202, "Accepted" },
        { 204, "No Content" }, { 206, "Partial Content" },
        { 301, "Moved Permanently" }, { 302, "Found" }, { 304, "Not Modified" },
        { 400, "Bad Request" }, { 401, "Unauthorized" }, { 403, "Forbidden" },
        { 404, "Not Found" }, { 405, "Method Not Allowed" }, { 408, "Request Timeout" },
        { 429, "Too Many Requests" },
        { 500, "Internal Server Error" }, { 502, "Bad Gateway" },
        { 503, "Service Unavailable" }, { 504, "Gateway Timeout" },
    };

    private readonly long _handle;
    private bool _disposed;
    private SensorContentStream? _contentStream;

    internal StreamResponse(long handle, StreamMetadata metadata)
    {
        _handle = handle;
        StatusCode = metadata.StatusCode;
        Headers = metadata.Headers ?? new Dictionary<string, string[]>();
        Url = metadata.FinalUrl ?? "";
        Protocol = metadata.Protocol ?? "";
        ContentLength = metadata.ContentLength;
        Cookies = metadata.Cookies?.Select(c => new Cookie(c.Name ?? "", c.Value ?? "", c.Domain ?? "", c.Path ?? "", c.Expires ?? "", c.MaxAge, c.Secure, c.HttpOnly, c.SameSite ?? "")).ToList()
            ?? new List<Cookie>();
    }

    public int StatusCode { get; }

    public Dictionary<string, string[]> Headers { get; }

    public string Url { get; }

    public string Protocol { get; }

    public long ContentLength { get; }

    public List<Cookie> Cookies { get; }

    public bool Ok => StatusCode < 400;

    public string Reason => HttpStatusPhrases.TryGetValue(StatusCode, out var phrase) ? phrase : "Unknown";

    public string? GetHeader(string name)
    {
        if (Headers.TryGetValue(name, out var values) && values.Length > 0)
            return values[0];
        var key = Headers.Keys.FirstOrDefault(k => k.Equals(name, StringComparison.OrdinalIgnoreCase));
        if (key != null && Headers.TryGetValue(key, out values) && values.Length > 0)
            return values[0];
        return null;
    }

    public string[] GetHeaders(string name)
    {
        if (Headers.TryGetValue(name, out var values))
            return values;
        var key = Headers.Keys.FirstOrDefault(k => k.Equals(name, StringComparison.OrdinalIgnoreCase));
        if (key != null && Headers.TryGetValue(key, out values))
            return values;
        return Array.Empty<string>();
    }

    public byte[]? ReadChunk(int chunkSize = 8192)
    {
        ThrowIfDisposed();

        IntPtr resultPtr = Native.StreamRead(_handle, chunkSize);
        string? base64 = Native.PtrToStringAndFree(resultPtr);

        if (string.IsNullOrEmpty(base64))
            return null; // EOF

        return Convert.FromBase64String(base64);
    }

    public IEnumerable<byte[]> ReadChunks(int chunkSize = 8192)
    {
        while (true)
        {
            var chunk = ReadChunk(chunkSize);
            if (chunk == null)
                yield break;
            yield return chunk;
        }
    }

    public Stream GetContentStream(int bufferSize = 65536)
    {
        ThrowIfDisposed();
        if (_contentStream != null)
            throw new InvalidOperationException("GetContentStream can only be called once per StreamResponse");

        _contentStream = new SensorContentStream(this, bufferSize);
        return _contentStream;
    }

    public byte[] ReadAll()
    {
        using var ms = new MemoryStream();
        foreach (var chunk in ReadChunks())
        {
            ms.Write(chunk, 0, chunk.Length);
        }
        return ms.ToArray();
    }

    public string Text => System.Text.Encoding.UTF8.GetString(ReadAll());

    public T? Json<T>() => JsonSerializer.Deserialize<T>(Text);

    public void RaiseForStatus()
    {
        if (!Ok)
            throw new SensorException($"HTTP {StatusCode}: {Reason}");
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(StreamResponse));
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            _contentStream?.MarkParentDisposed();
            Native.StreamClose(_handle);
            _disposed = true;
        }
    }
}

public sealed class SensorContentStream : Stream
{
    private readonly StreamResponse _parent;
    private readonly int _bufferSize;
    private byte[]? _buffer;
    private int _bufferPos;
    private int _bufferLen;
    private bool _eof;
    private bool _parentDisposed;
    private long _position;

    internal SensorContentStream(StreamResponse parent, int bufferSize)
    {
        _parent = parent;
        _bufferSize = bufferSize;
    }

    internal void MarkParentDisposed() => _parentDisposed = true;

    public override bool CanRead => !_parentDisposed;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => _parent.ContentLength;
    public override long Position
    {
        get => _position;
        set => throw new NotSupportedException("Seeking is not supported");
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        if (_parentDisposed)
            throw new ObjectDisposedException(nameof(SensorContentStream));
        if (_eof)
            return 0;

        int totalRead = 0;

        while (count > 0)
        {
            if (_buffer == null || _bufferPos >= _bufferLen)
            {
                var chunk = _parent.ReadChunk(_bufferSize);
                if (chunk == null || chunk.Length == 0)
                {
                    _eof = true;
                    break;
                }
                _buffer = chunk;
                _bufferPos = 0;
                _bufferLen = chunk.Length;
            }

            int available = _bufferLen - _bufferPos;
            int toCopy = Math.Min(available, count);
            Array.Copy(_buffer, _bufferPos, buffer, offset, toCopy);
            _bufferPos += toCopy;
            offset += toCopy;
            count -= toCopy;
            totalRead += toCopy;
            _position += toCopy;
        }

        return totalRead;
    }

    public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        return await Task.Run(() => Read(buffer, offset, count), cancellationToken);
    }

    public override void Flush() { }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}

public static class Presets
{
    public const string Chrome146 = "chrome-146";
    public const string Chrome146Windows = "chrome-146-windows";
    public const string Chrome146Linux = "chrome-146-linux";
    public const string Chrome146MacOS = "chrome-146-macos";
    public const string Chrome145 = "chrome-145";
    public const string Chrome145Windows = "chrome-145-windows";
    public const string Chrome145Linux = "chrome-145-linux";
    public const string Chrome145MacOS = "chrome-145-macos";
    public const string Chrome144 = "chrome-144";
    public const string Chrome144Windows = "chrome-144-windows";
    public const string Chrome144Linux = "chrome-144-linux";
    public const string Chrome144MacOS = "chrome-144-macos";
    public const string Chrome143 = "chrome-143";
    public const string Chrome143Windows = "chrome-143-windows";
    public const string Chrome143Linux = "chrome-143-linux";
    public const string Chrome143MacOS = "chrome-143-macos";
    public const string Chrome141 = "chrome-141";
    public const string Chrome133 = "chrome-133";
    public const string Firefox133 = "firefox-133";
    public const string Safari18 = "safari-18";
    public const string Chrome143Ios = "chrome-143-ios";
    public const string Chrome144Ios = "chrome-144-ios";
    public const string Chrome145Ios = "chrome-145-ios";
    public const string Chrome146Ios = "chrome-146-ios";
    public const string Safari17Ios = "safari-17-ios";
    public const string Safari18Ios = "safari-18-ios";
    public const string Chrome143Android = "chrome-143-android";
    public const string Chrome144Android = "chrome-144-android";
    public const string Chrome145Android = "chrome-145-android";
    public const string Chrome146Android = "chrome-146-android";

    public const string IosChrome143 = Chrome143Ios;
    public const string IosChrome144 = Chrome144Ios;
    public const string IosChrome145 = Chrome145Ios;
    public const string IosChrome146 = Chrome146Ios;
    public const string IosSafari17 = Safari17Ios;
    public const string IosSafari18 = Safari18Ios;
    public const string AndroidChrome143 = Chrome143Android;
    public const string AndroidChrome144 = Chrome144Android;
    public const string AndroidChrome145 = Chrome145Android;
    public const string AndroidChrome146 = Chrome146Android;
}

public static class SensorInfo
{
    public static string Version()
    {
        IntPtr ptr = Native.Version();
        return Native.PtrToStringAndFree(ptr) ?? "unknown";
    }

    public static Dictionary<string, PresetInfo> AvailablePresets()
    {
        IntPtr ptr = Native.AvailablePresets();
        string? json = Native.PtrToStringAndFree(ptr);

        if (string.IsNullOrEmpty(json))
            return new Dictionary<string, PresetInfo>();

        return JsonSerializer.Deserialize(json, JsonContext.Default.DictionaryStringPresetInfo)
            ?? new Dictionary<string, PresetInfo>();
    }

    public static void SetEchDnsServers(string[]? servers)
    {
        string? serversJson = null;
        if (servers != null && servers.Length > 0)
        {
            serversJson = JsonSerializer.Serialize(servers, JsonContext.Relaxed.StringArray);
        }

        IntPtr errorPtr = Native.SetEchDnsServers(serversJson);
        string? error = Native.PtrToStringAndFree(errorPtr);
        if (!string.IsNullOrEmpty(error))
        {
            throw new SensorException($"Failed to set ECH DNS servers: {error}");
        }
    }

    public static string[] GetEchDnsServers()
    {
        IntPtr ptr = Native.GetEchDnsServers();
        string? json = Native.PtrToStringAndFree(ptr);

        if (string.IsNullOrEmpty(json))
            return Array.Empty<string>();

        return JsonSerializer.Deserialize(json, JsonContext.Default.StringArray) ?? Array.Empty<string>();
    }

}

public class MultipartFile
{
    public byte[] Content { get; set; } = Array.Empty<byte>();

    public string Filename { get; set; } = "file";

    public string ContentType { get; set; } = "application/octet-stream";

    public MultipartFile(byte[] content, string filename = "file", string contentType = "application/octet-stream")
    {
        Content = content;
        Filename = filename;
        ContentType = contentType;
    }
}

internal class SessionConfig
{
    [JsonPropertyName("preset")]
    public string Preset { get; set; } = "chrome-146";

    [JsonPropertyName("proxy")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Proxy { get; set; }

    [JsonPropertyName("tcp_proxy")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? TcpProxy { get; set; }

    [JsonPropertyName("udp_proxy")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? UdpProxy { get; set; }

    [JsonPropertyName("timeout")]
    public int Timeout { get; set; } = 30;

    [JsonPropertyName("http_version")]
    public string HttpVersion { get; set; } = "auto";

    [JsonPropertyName("verify")]
    public bool Verify { get; set; } = true;

    [JsonPropertyName("allow_redirects")]
    public bool AllowRedirects { get; set; } = true;

    [JsonPropertyName("max_redirects")]
    public int MaxRedirects { get; set; } = 10;

    [JsonPropertyName("retry")]
    public int Retry { get; set; }

    [JsonPropertyName("retry_on_status")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public int[]? RetryOnStatus { get; set; }

    [JsonPropertyName("retry_wait_min")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public int RetryWaitMin { get; set; } = 500;

    [JsonPropertyName("retry_wait_max")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public int RetryWaitMax { get; set; } = 10000;

    [JsonPropertyName("prefer_ipv4")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool PreferIpv4 { get; set; }

    [JsonPropertyName("connect_to")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Dictionary<string, string>? ConnectTo { get; set; }

    [JsonPropertyName("ech_config_domain")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? EchConfigDomain { get; set; }

    [JsonPropertyName("tls_only")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool TlsOnly { get; set; }

    [JsonPropertyName("quic_idle_timeout")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public int QuicIdleTimeout { get; set; }

    [JsonPropertyName("local_address")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? LocalAddress { get; set; }

    [JsonPropertyName("key_log_file")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? KeyLogFile { get; set; }

    [JsonPropertyName("enable_speculative_tls")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool EnableSpeculativeTls { get; set; }

    [JsonPropertyName("switch_protocol")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? SwitchProtocol { get; set; }

    [JsonPropertyName("without_cookie_jar")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool WithoutCookieJar { get; set; }

    [JsonPropertyName("ja3")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Ja3 { get; set; }

    [JsonPropertyName("akamai")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Akamai { get; set; }

    [JsonPropertyName("extra_fp")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Dictionary<string, object>? ExtraFp { get; set; }

    [JsonPropertyName("tcp_ttl")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public int? TcpTtl { get; set; }

    [JsonPropertyName("tcp_mss")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public int? TcpMss { get; set; }

    [JsonPropertyName("tcp_window_size")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public int? TcpWindowSize { get; set; }

    [JsonPropertyName("tcp_window_scale")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public int? TcpWindowScale { get; set; }

    [JsonPropertyName("tcp_df")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? TcpDf { get; set; }
}

internal class RequestConfig
{
    [JsonPropertyName("method")]
    public string Method { get; set; } = "GET";

    [JsonPropertyName("url")]
    public string Url { get; set; } = "";

    [JsonPropertyName("headers")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Dictionary<string, string>? Headers { get; set; }

    [JsonPropertyName("body")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Body { get; set; }

    [JsonPropertyName("body_encoding")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? BodyEncoding { get; set; }

    [JsonPropertyName("timeout")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public int? Timeout { get; set; }

    [JsonPropertyName("fetch_mode")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? FetchMode { get; set; }
}

internal class CookieData
{
    [JsonPropertyName("name")]
    public string? Name { get; set; }

    [JsonPropertyName("value")]
    public string? Value { get; set; }

    [JsonPropertyName("domain")]
    public string? Domain { get; set; }

    [JsonPropertyName("path")]
    public string? Path { get; set; }

    [JsonPropertyName("expires")]
    public string? Expires { get; set; }

    [JsonPropertyName("max_age")]
    public long MaxAge { get; set; }

    [JsonPropertyName("secure")]
    public bool Secure { get; set; }

    [JsonPropertyName("http_only")]
    public bool HttpOnly { get; set; }

    [JsonPropertyName("same_site")]
    public string? SameSite { get; set; }
}

internal class RedirectInfoData
{
    [JsonPropertyName("status_code")]
    public int StatusCode { get; set; }

    [JsonPropertyName("url")]
    public string? Url { get; set; }

    [JsonPropertyName("headers")]
    public Dictionary<string, string[]>? Headers { get; set; }
}

internal class ResponseData
{
    [JsonPropertyName("status_code")]
    public int StatusCode { get; set; }

    [JsonPropertyName("headers")]
    public Dictionary<string, string[]>? Headers { get; set; }

    [JsonPropertyName("body")]
    public string? Body { get; set; }

    [JsonPropertyName("body_encoding")]
    public string? BodyEncoding { get; set; }

    [JsonPropertyName("final_url")]
    public string? FinalUrl { get; set; }

    [JsonPropertyName("protocol")]
    public string? Protocol { get; set; }

    [JsonPropertyName("cookies")]
    public List<CookieData>? Cookies { get; set; }

    [JsonPropertyName("history")]
    public List<RedirectInfoData>? History { get; set; }
}

internal class FastResponseMetadata
{
    [JsonPropertyName("status_code")]
    public int StatusCode { get; set; }

    [JsonPropertyName("headers")]
    public Dictionary<string, string[]>? Headers { get; set; }

    [JsonPropertyName("body_len")]
    public int BodyLen { get; set; }

    [JsonPropertyName("final_url")]
    public string? FinalUrl { get; set; }

    [JsonPropertyName("protocol")]
    public string? Protocol { get; set; }

    [JsonPropertyName("cookies")]
    public List<CookieData>? Cookies { get; set; }

    [JsonPropertyName("history")]
    public List<RedirectInfoData>? History { get; set; }
}

internal class ErrorResponse
{
    [JsonPropertyName("error")]
    public string? Error { get; set; }
}

public class PresetInfo
{
    [JsonPropertyName("protocols")]
    public string[] Protocols { get; set; } = Array.Empty<string>();
}

internal class RequestOptions
{
    [JsonPropertyName("headers")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Dictionary<string, string>? Headers { get; set; }

    [JsonPropertyName("timeout")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public int? Timeout { get; set; }

    [JsonPropertyName("fetch_mode")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? FetchMode { get; set; }
}

internal class StreamOptions
{
    [JsonPropertyName("headers")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Dictionary<string, string>? Headers { get; set; }

    [JsonPropertyName("timeout")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public int? Timeout { get; set; }

    [JsonPropertyName("fetch_mode")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? FetchMode { get; set; }
}

internal class StreamMetadata
{
    [JsonPropertyName("status_code")]
    public int StatusCode { get; set; }

    [JsonPropertyName("headers")]
    public Dictionary<string, string[]>? Headers { get; set; }

    [JsonPropertyName("final_url")]
    public string? FinalUrl { get; set; }

    [JsonPropertyName("protocol")]
    public string? Protocol { get; set; }

    [JsonPropertyName("content_length")]
    public long ContentLength { get; set; }

    [JsonPropertyName("cookies")]
    public List<CookieData>? Cookies { get; set; }
}

public sealed class SensorHandler : DelegatingHandler
{
    private readonly LocalProxy _proxy;
    private readonly bool _ownsProxy;
    private bool _disposed;

    public SensorHandler(
        string preset = "chrome-146",
        string? proxy = null,
        string? tcpProxy = null,
        string? udpProxy = null,
        int timeout = 30,
        int maxConnections = 1000)
    {
        _proxy = new LocalProxy(
            port: 0,
            preset: preset,
            timeout: timeout,
            maxConnections: maxConnections,
            tcpProxy: tcpProxy ?? proxy,
            udpProxy: udpProxy ?? proxy);
        _ownsProxy = true;

        InnerHandler = new HttpClientHandler
        {
            Proxy = _proxy.CreateWebProxy(),
            UseProxy = true
        };
    }

    public SensorHandler(LocalProxy proxy)
    {
        _proxy = proxy ?? throw new ArgumentNullException(nameof(proxy));
        _ownsProxy = false;

        InnerHandler = new HttpClientHandler
        {
            Proxy = _proxy.CreateWebProxy(),
            UseProxy = true
        };
    }

    public LocalProxy Proxy => _proxy;

    public string ProxyUrl => _proxy.ProxyUrl;

    public LocalProxyStats GetStats() => _proxy.GetStats();

    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(SensorHandler));

        return base.SendAsync(request, cancellationToken);
    }

    protected override HttpResponseMessage Send(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(SensorHandler));

        return base.Send(request, cancellationToken);
    }

    protected override void Dispose(bool disposing)
    {
        if (!_disposed)
        {
            if (disposing && _ownsProxy)
            {
                _proxy.Dispose();
            }
            _disposed = true;
        }
        base.Dispose(disposing);
    }
}

[JsonSerializable(typeof(SessionConfig))]
[JsonSerializable(typeof(RequestConfig))]
[JsonSerializable(typeof(ResponseData))]
[JsonSerializable(typeof(FastResponseMetadata))]
[JsonSerializable(typeof(ErrorResponse))]
[JsonSerializable(typeof(CookieData))]
[JsonSerializable(typeof(RedirectInfoData))]
[JsonSerializable(typeof(List<CookieData>))]
[JsonSerializable(typeof(List<RedirectInfoData>))]
[JsonSerializable(typeof(Dictionary<string, string>))]
[JsonSerializable(typeof(Dictionary<string, string[]>))]
[JsonSerializable(typeof(string[]))]
[JsonSerializable(typeof(RequestOptions))]
[JsonSerializable(typeof(StreamOptions))]
[JsonSerializable(typeof(StreamMetadata))]
[JsonSerializable(typeof(PresetInfo))]
[JsonSerializable(typeof(Dictionary<string, PresetInfo>))]
internal partial class JsonContext : JsonSerializerContext
{
    private static readonly Lazy<JsonContext> _relaxed = new(() =>
        new JsonContext(new JsonSerializerOptions
        {
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
        }));

    public static JsonContext Relaxed => _relaxed.Value;
}
