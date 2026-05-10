using System.Text.Json;

namespace Sensor;

public static class CustomPresets
{
    public static string LoadFromFile(string path)
    {
        var resultPtr = Native.PresetLoadFile(path);
        return ParsePresetNameResult(resultPtr)
            ?? throw new SensorException("Failed to load preset from file");
    }

    public static string LoadFromJson(string jsonData)
    {
        var resultPtr = Native.PresetLoadJson(jsonData);
        return ParsePresetNameResult(resultPtr)
            ?? throw new SensorException("Failed to load preset from JSON");
    }

    public static void Unregister(string name)
    {
        Native.PresetUnregister(name);
    }

    public static string Describe(string name)
    {
        var resultPtr = Native.DescribePreset(name);
        var json = Native.PtrToStringAndFree(resultPtr);
        if (string.IsNullOrEmpty(json))
            throw new SensorException($"Failed to describe preset: {name}");

        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        if (root.TryGetProperty("error", out var errorElem) &&
            !root.TryGetProperty("preset", out _))
        {
            throw new SensorException(errorElem.GetString() ?? "Unknown error");
        }
        return json;
    }

    private static string? ParsePresetNameResult(IntPtr ptr)
    {
        var json = Native.PtrToStringAndFree(ptr);
        if (string.IsNullOrEmpty(json))
            return null;

        using var doc = JsonDocument.Parse(json);
        if (doc.RootElement.TryGetProperty("error", out var errorElem))
            throw new SensorException(errorElem.GetString() ?? "Unknown error");
        if (doc.RootElement.TryGetProperty("name", out var nameElem))
            return nameElem.GetString();

        return null;
    }
}

public sealed class PresetPool : IDisposable
{
    private long _handle;
    private bool _disposed;

    public PresetPool(string path)
    {
        _handle = ParsePoolLoadResult(Native.PoolLoadFile(path));
    }

    private PresetPool(long handle)
    {
        _handle = handle;
    }

    public static PresetPool FromJson(string jsonData)
    {
        var handle = ParsePoolLoadResult(Native.PoolLoadJson(jsonData));
        return new PresetPool(handle);
    }

    private static long ParsePoolLoadResult(IntPtr ptr)
    {
        var json = Native.PtrToStringAndFree(ptr);
        if (string.IsNullOrEmpty(json))
            throw new SensorException("Failed to load preset pool");

        using var doc = JsonDocument.Parse(json);
        if (doc.RootElement.TryGetProperty("error", out var errorElem))
            throw new SensorException(errorElem.GetString() ?? "Unknown error");
        if (doc.RootElement.TryGetProperty("handle", out var handleElem))
            return handleElem.GetInt64();

        throw new SensorException("Failed to load preset pool: invalid response");
    }

    public string Pick()
    {
        ThrowIfDisposed();
        return ParsePoolResult(Native.PoolPick(_handle));
    }

    public string Random()
    {
        ThrowIfDisposed();
        return ParsePoolResult(Native.PoolRandom(_handle));
    }

    public string Next()
    {
        ThrowIfDisposed();
        return ParsePoolResult(Native.PoolNext(_handle));
    }

    public string this[int index]
    {
        get
        {
            ThrowIfDisposed();
            return ParsePoolResult(Native.PoolGet(_handle, index));
        }
    }

    public int Count
    {
        get
        {
            ThrowIfDisposed();
            var size = Native.PoolSize(_handle);
            if (size < 0)
                throw new SensorException("Failed to get pool size");
            return (int)size;
        }
    }

    public string Name
    {
        get
        {
            ThrowIfDisposed();
            return ParsePoolResult(Native.PoolName(_handle));
        }
    }

    private static string ParsePoolResult(IntPtr ptr)
    {
        var result = Native.PtrToStringAndFree(ptr);
        if (string.IsNullOrEmpty(result))
            throw new SensorException("No result from preset pool");

        if (result.StartsWith("{"))
        {
            using var doc = JsonDocument.Parse(result);
            if (doc.RootElement.TryGetProperty("error", out var errorElem))
                throw new SensorException(errorElem.GetString() ?? "Unknown error");
        }

        return result;
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(PresetPool));
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            if (_handle > 0)
            {
                Native.PoolFree(_handle);
                _handle = 0;
            }
            _disposed = true;
            GC.SuppressFinalize(this);
        }
    }

    ~PresetPool()
    {
        Dispose();
    }
}
