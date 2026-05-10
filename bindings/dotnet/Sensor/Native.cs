using System.Runtime.InteropServices;

namespace Sensor;

internal static class Native
{
    private const string LibraryName = "sensor";

    static Native()
    {
        NativeLibrary.SetDllImportResolver(typeof(Native).Assembly, DllImportResolver);
    }

    private static IntPtr DllImportResolver(string libraryName, System.Reflection.Assembly assembly, DllImportSearchPath? searchPath)
    {
        if (libraryName != LibraryName)
            return IntPtr.Zero;

        string? libPath = GetNativeLibraryPath();
        if (libPath != null && NativeLibrary.TryLoad(libPath, out IntPtr handle))
            return handle;

        return IntPtr.Zero;
    }

    private static string? GetNativeLibraryPath()
    {
        string arch = RuntimeInformation.ProcessArchitecture switch
        {
            Architecture.X64 => "x64",
            Architecture.Arm64 => "arm64",
            _ => "x64"
        };

        string rid;
        string libName;

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            rid = $"win-{arch}";
            libName = "libsensor-windows-amd64.dll";
            if (arch == "arm64") libName = "libsensor-windows-arm64.dll";
        }
        else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            rid = $"osx-{arch}";
            libName = arch == "arm64" ? "libsensor-darwin-arm64.dylib" : "libsensor-darwin-amd64.dylib";
        }
        else
        {
            rid = $"linux-{arch}";
            libName = arch == "arm64" ? "libsensor-linux-arm64.so" : "libsensor-linux-amd64.so";
        }

        string assemblyDir = Path.GetDirectoryName(typeof(Native).Assembly.Location) ?? ".";
        string[] searchPaths =
        {
            Path.Combine(assemblyDir, "runtimes", rid, "native", libName),
            Path.Combine(assemblyDir, libName),
            Path.Combine(assemblyDir, "native", libName),
        };

        foreach (string path in searchPaths)
        {
            if (File.Exists(path))
                return path;
        }

        return null;
    }

    [DllImport(LibraryName, EntryPoint = "sensor_session_new", CallingConvention = CallingConvention.Cdecl)]
    public static extern long SessionNew([MarshalAs(UnmanagedType.LPUTF8Str)] string? configJson);

    [DllImport(LibraryName, EntryPoint = "sensor_session_free", CallingConvention = CallingConvention.Cdecl)]
    public static extern void SessionFree(long handle);

    [DllImport(LibraryName, EntryPoint = "sensor_session_refresh", CallingConvention = CallingConvention.Cdecl)]
    public static extern void SessionRefresh(long handle);

    [DllImport(LibraryName, EntryPoint = "sensor_session_refresh_protocol", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr SessionRefreshProtocol(long handle, [MarshalAs(UnmanagedType.LPUTF8Str)] string protocol);

    [DllImport(LibraryName, EntryPoint = "sensor_session_warmup", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr SessionWarmup(long handle, [MarshalAs(UnmanagedType.LPUTF8Str)] string url, long timeoutMs);

    [DllImport(LibraryName, EntryPoint = "sensor_session_fork", CallingConvention = CallingConvention.Cdecl)]
    public static extern long SessionFork(long handle);

    [DllImport(LibraryName, EntryPoint = "sensor_get", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr Get(long handle, [MarshalAs(UnmanagedType.LPUTF8Str)] string url, [MarshalAs(UnmanagedType.LPUTF8Str)] string? headersJson);

    [DllImport(LibraryName, EntryPoint = "sensor_post", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr Post(long handle, [MarshalAs(UnmanagedType.LPUTF8Str)] string url, [MarshalAs(UnmanagedType.LPUTF8Str)] string? body, [MarshalAs(UnmanagedType.LPUTF8Str)] string? headersJson);

    [DllImport(LibraryName, EntryPoint = "sensor_request", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr Request(long handle, [MarshalAs(UnmanagedType.LPUTF8Str)] string requestJson);

    [DllImport(LibraryName, EntryPoint = "sensor_get_cookies", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr GetCookies(long handle);

    [DllImport(LibraryName, EntryPoint = "sensor_set_cookie", CallingConvention = CallingConvention.Cdecl)]
    public static extern void SetCookie(long handle, [MarshalAs(UnmanagedType.LPUTF8Str)] string cookieJson);

    [DllImport(LibraryName, EntryPoint = "sensor_delete_cookie", CallingConvention = CallingConvention.Cdecl)]
    public static extern void DeleteCookie(long handle, [MarshalAs(UnmanagedType.LPUTF8Str)] string name, [MarshalAs(UnmanagedType.LPUTF8Str)] string domain);

    [DllImport(LibraryName, EntryPoint = "sensor_clear_cookies", CallingConvention = CallingConvention.Cdecl)]
    public static extern void ClearCookies(long handle);

    [DllImport(LibraryName, EntryPoint = "sensor_free_string", CallingConvention = CallingConvention.Cdecl)]
    public static extern void FreeString(IntPtr str);

    [DllImport(LibraryName, EntryPoint = "sensor_version", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr Version();

    [DllImport(LibraryName, EntryPoint = "sensor_available_presets", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr AvailablePresets();

    [DllImport(LibraryName, EntryPoint = "sensor_set_ech_dns_servers", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr SetEchDnsServers([MarshalAs(UnmanagedType.LPUTF8Str)] string? serversJson);

    [DllImport(LibraryName, EntryPoint = "sensor_get_ech_dns_servers", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr GetEchDnsServers();

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate void AsyncCallback(long callbackId, IntPtr responseJson, IntPtr error);

    [DllImport(LibraryName, EntryPoint = "sensor_register_callback", CallingConvention = CallingConvention.Cdecl)]
    public static extern long RegisterCallback(AsyncCallback callback);

    [DllImport(LibraryName, EntryPoint = "sensor_unregister_callback", CallingConvention = CallingConvention.Cdecl)]
    public static extern void UnregisterCallback(long callbackId);

    [DllImport(LibraryName, EntryPoint = "sensor_cancel_request", CallingConvention = CallingConvention.Cdecl)]
    public static extern void CancelRequest(long callbackId);

    [DllImport(LibraryName, EntryPoint = "sensor_get_async", CallingConvention = CallingConvention.Cdecl)]
    public static extern void GetAsync(long handle, [MarshalAs(UnmanagedType.LPUTF8Str)] string url, [MarshalAs(UnmanagedType.LPUTF8Str)] string? headersJson, long callbackId);

    [DllImport(LibraryName, EntryPoint = "sensor_post_async", CallingConvention = CallingConvention.Cdecl)]
    public static extern void PostAsync(long handle, [MarshalAs(UnmanagedType.LPUTF8Str)] string url, [MarshalAs(UnmanagedType.LPUTF8Str)] string? body, [MarshalAs(UnmanagedType.LPUTF8Str)] string? headersJson, long callbackId);

    [DllImport(LibraryName, EntryPoint = "sensor_request_async", CallingConvention = CallingConvention.Cdecl)]
    public static extern void RequestAsync(long handle, [MarshalAs(UnmanagedType.LPUTF8Str)] string requestJson, long callbackId);

    [DllImport(LibraryName, EntryPoint = "sensor_stream_get", CallingConvention = CallingConvention.Cdecl)]
    public static extern long StreamGet(long handle, [MarshalAs(UnmanagedType.LPUTF8Str)] string url, [MarshalAs(UnmanagedType.LPUTF8Str)] string? optionsJson);

    [DllImport(LibraryName, EntryPoint = "sensor_stream_post", CallingConvention = CallingConvention.Cdecl)]
    public static extern long StreamPost(long handle, [MarshalAs(UnmanagedType.LPUTF8Str)] string url, [MarshalAs(UnmanagedType.LPUTF8Str)] string? body, [MarshalAs(UnmanagedType.LPUTF8Str)] string? optionsJson);

    [DllImport(LibraryName, EntryPoint = "sensor_stream_request", CallingConvention = CallingConvention.Cdecl)]
    public static extern long StreamRequest(long handle, [MarshalAs(UnmanagedType.LPUTF8Str)] string requestJson);

    [DllImport(LibraryName, EntryPoint = "sensor_stream_get_metadata", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr StreamGetMetadata(long streamHandle);

    [DllImport(LibraryName, EntryPoint = "sensor_stream_read", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr StreamRead(long streamHandle, long bufferSize);

    [DllImport(LibraryName, EntryPoint = "sensor_stream_close", CallingConvention = CallingConvention.Cdecl)]
    public static extern void StreamClose(long streamHandle);

    [DllImport(LibraryName, EntryPoint = "sensor_session_save", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr SessionSave(long handle, [MarshalAs(UnmanagedType.LPUTF8Str)] string path);

    [DllImport(LibraryName, EntryPoint = "sensor_session_load", CallingConvention = CallingConvention.Cdecl)]
    public static extern long SessionLoad([MarshalAs(UnmanagedType.LPUTF8Str)] string path);

    [DllImport(LibraryName, EntryPoint = "sensor_session_marshal", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr SessionMarshal(long handle);

    [DllImport(LibraryName, EntryPoint = "sensor_session_unmarshal", CallingConvention = CallingConvention.Cdecl)]
    public static extern long SessionUnmarshal([MarshalAs(UnmanagedType.LPUTF8Str)] string data);

    [DllImport(LibraryName, EntryPoint = "sensor_session_set_proxy", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr SessionSetProxy(long handle, [MarshalAs(UnmanagedType.LPUTF8Str)] string? proxyUrl);

    [DllImport(LibraryName, EntryPoint = "sensor_session_set_tcp_proxy", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr SessionSetTcpProxy(long handle, [MarshalAs(UnmanagedType.LPUTF8Str)] string? proxyUrl);

    [DllImport(LibraryName, EntryPoint = "sensor_session_set_udp_proxy", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr SessionSetUdpProxy(long handle, [MarshalAs(UnmanagedType.LPUTF8Str)] string? proxyUrl);

    [DllImport(LibraryName, EntryPoint = "sensor_session_get_proxy", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr SessionGetProxy(long handle);

    [DllImport(LibraryName, EntryPoint = "sensor_session_get_tcp_proxy", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr SessionGetTcpProxy(long handle);

    [DllImport(LibraryName, EntryPoint = "sensor_session_get_udp_proxy", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr SessionGetUdpProxy(long handle);

    [DllImport(LibraryName, EntryPoint = "sensor_session_set_header_order", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr SessionSetHeaderOrder(long handle, [MarshalAs(UnmanagedType.LPUTF8Str)] string orderJson);

    [DllImport(LibraryName, EntryPoint = "sensor_session_get_header_order", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr SessionGetHeaderOrder(long handle);

    [DllImport(LibraryName, EntryPoint = "sensor_session_set_identifier", CallingConvention = CallingConvention.Cdecl)]
    public static extern void SessionSetIdentifier(long handle, [MarshalAs(UnmanagedType.LPUTF8Str)] string? sessionId);

    [DllImport(LibraryName, EntryPoint = "sensor_local_proxy_start", CallingConvention = CallingConvention.Cdecl)]
    public static extern long LocalProxyStart([MarshalAs(UnmanagedType.LPUTF8Str)] string? configJson);

    [DllImport(LibraryName, EntryPoint = "sensor_local_proxy_stop", CallingConvention = CallingConvention.Cdecl)]
    public static extern void LocalProxyStop(long handle);

    [DllImport(LibraryName, EntryPoint = "sensor_local_proxy_get_port", CallingConvention = CallingConvention.Cdecl)]
    public static extern int LocalProxyGetPort(long handle);

    [DllImport(LibraryName, EntryPoint = "sensor_local_proxy_is_running", CallingConvention = CallingConvention.Cdecl)]
    public static extern int LocalProxyIsRunning(long handle);

    [DllImport(LibraryName, EntryPoint = "sensor_local_proxy_get_stats", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr LocalProxyGetStats(long handle);

    [DllImport(LibraryName, EntryPoint = "sensor_local_proxy_register_session", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr LocalProxyRegisterSession(long proxyHandle, [MarshalAs(UnmanagedType.LPUTF8Str)] string sessionId, long sessionHandle);

    [DllImport(LibraryName, EntryPoint = "sensor_local_proxy_unregister_session", CallingConvention = CallingConvention.Cdecl)]
    public static extern int LocalProxyUnregisterSession(long proxyHandle, [MarshalAs(UnmanagedType.LPUTF8Str)] string sessionId);

    [DllImport(LibraryName, EntryPoint = "sensor_preset_load_file", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr PresetLoadFile([MarshalAs(UnmanagedType.LPUTF8Str)] string path);

    [DllImport(LibraryName, EntryPoint = "sensor_preset_load_json", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr PresetLoadJson([MarshalAs(UnmanagedType.LPUTF8Str)] string jsonData);

    [DllImport(LibraryName, EntryPoint = "sensor_preset_unregister", CallingConvention = CallingConvention.Cdecl)]
    public static extern void PresetUnregister([MarshalAs(UnmanagedType.LPUTF8Str)] string name);

    [DllImport(LibraryName, EntryPoint = "sensor_describe_preset", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr DescribePreset([MarshalAs(UnmanagedType.LPUTF8Str)] string name);

    [DllImport(LibraryName, EntryPoint = "sensor_pool_load_file", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr PoolLoadFile([MarshalAs(UnmanagedType.LPUTF8Str)] string path);

    [DllImport(LibraryName, EntryPoint = "sensor_pool_load_json", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr PoolLoadJson([MarshalAs(UnmanagedType.LPUTF8Str)] string jsonData);

    [DllImport(LibraryName, EntryPoint = "sensor_pool_pick", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr PoolPick(long handle);

    [DllImport(LibraryName, EntryPoint = "sensor_pool_random", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr PoolRandom(long handle);

    [DllImport(LibraryName, EntryPoint = "sensor_pool_next", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr PoolNext(long handle);

    [DllImport(LibraryName, EntryPoint = "sensor_pool_get", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr PoolGet(long handle, long index);

    [DllImport(LibraryName, EntryPoint = "sensor_pool_size", CallingConvention = CallingConvention.Cdecl)]
    public static extern long PoolSize(long handle);

    [DllImport(LibraryName, EntryPoint = "sensor_pool_name", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr PoolName(long handle);

    [DllImport(LibraryName, EntryPoint = "sensor_pool_free", CallingConvention = CallingConvention.Cdecl)]
    public static extern void PoolFree(long handle);

    [DllImport(LibraryName, EntryPoint = "sensor_get_raw", CallingConvention = CallingConvention.Cdecl)]
    public static extern long GetRaw(long handle, [MarshalAs(UnmanagedType.LPUTF8Str)] string url, [MarshalAs(UnmanagedType.LPUTF8Str)] string? optionsJson);

    [DllImport(LibraryName, EntryPoint = "sensor_post_raw", CallingConvention = CallingConvention.Cdecl)]
    public static extern long PostRaw(long handle, [MarshalAs(UnmanagedType.LPUTF8Str)] string url, IntPtr body, int bodyLen, [MarshalAs(UnmanagedType.LPUTF8Str)] string? optionsJson);

    [DllImport(LibraryName, EntryPoint = "sensor_request_raw", CallingConvention = CallingConvention.Cdecl)]
    public static extern long RequestRaw(long handle, [MarshalAs(UnmanagedType.LPUTF8Str)] string requestJson, IntPtr body, int bodyLen);

    [DllImport(LibraryName, EntryPoint = "sensor_response_get_metadata", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr ResponseGetMetadata(long responseHandle);

    [DllImport(LibraryName, EntryPoint = "sensor_response_get_body_len", CallingConvention = CallingConvention.Cdecl)]
    public static extern int ResponseGetBodyLen(long responseHandle);

    [DllImport(LibraryName, EntryPoint = "sensor_response_copy_body_to", CallingConvention = CallingConvention.Cdecl)]
    public static extern int ResponseCopyBodyTo(long responseHandle, IntPtr buffer, int bufferLen);

    [DllImport(LibraryName, EntryPoint = "sensor_response_free", CallingConvention = CallingConvention.Cdecl)]
    public static extern void ResponseFree(long responseHandle);

    public static string? PtrToStringAndFree(IntPtr ptr)
    {
        if (ptr == IntPtr.Zero)
            return null;

        try
        {
            return Marshal.PtrToStringUTF8(ptr);
        }
        finally
        {
            FreeString(ptr);
        }
    }

    public static string? PtrToString(IntPtr ptr)
    {
        if (ptr == IntPtr.Zero)
            return null;

        return Marshal.PtrToStringUTF8(ptr);
    }
}
