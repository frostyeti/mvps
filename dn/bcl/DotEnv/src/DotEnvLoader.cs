using FrostYeti.DotEnv.Documents;
using FrostYeti.DotEnv.Serialization;

namespace FrostYeti.DotEnv;

/// <summary>
/// A class for loading and parsing .env files and content.
/// </summary>
public static class DotEnvLoader
{
    public static DotEnvDocument Parse(DotEnvLoadOptions options)
    {
        if (options.Files.Count == 1 && options.Content is null)
        {
            var fs = File.OpenRead(options.Files[0]);
            return Serializer.DeserializeDocument(fs, options);
        }
        else if (options.Files.Count == 0 && options.Content is not null)
        {
            return Serializer.DeserializeDocument(options.Content, options);
        }
        else if (options.Files.Count == 0 && options.Content is null)
        {
            return new DotEnvDocument();
        }

        DotEnvDocument doc = new();
        if (options.Files.Count > 0)
        {
            foreach (var file in options.Files)
            {
                var clone = (DotEnvLoadOptions)options.Clone();
                using var fs = File.OpenRead(file);
                var d = (IDictionary<string, string>)DotEnvSerializer.DeserializeDocument(fs, options);
                foreach (var pair in d)
                {
                    doc[pair.Key] = pair.Value;
                }
            }
        }

        if (options.Content is not null)
        {
            var clone = (DotEnvLoadOptions)options.Clone();
            var d = (IDictionary<string, string>)DotEnvSerializer.DeserializeDocument(options.Content, options);
            foreach (var pair in d)
            {
                doc[pair.Key] = pair.Value;
            }
        }

        return doc;
    }

    public static void Load(DotEnvLoadOptions options)
    {
        var doc = Parse(options);
        foreach (var entry in doc)
        {
            if (entry is DotEnvEntry var)
            {
                var hasValue = Environment.GetEnvironmentVariable(var.Name) is not null;
                if (options.OverrideEnvironment || !hasValue)
                {
                    Environment.SetEnvironmentVariable(var.Name, var.Value);
                }
            }
        }
    }

    public static void Load(DotEnvDocument document, bool overrideEnvironment = false)
    {
        foreach (var entry in document)
        {
            if (entry is DotEnvEntry var)
            {
                var hasValue = Environment.GetEnvironmentVariable(var.Name) is not null;
                if (overrideEnvironment || !hasValue)
                {
                    Environment.SetEnvironmentVariable(var.Name, var.Value);
                }
            }
        }
    }

    public static void Load(IEnumerable<KeyValuePair<string, string>> dictionary, bool overrideEnvironment = false)
    {
        foreach (var pair in dictionary)
        {
            var hasValue = Environment.GetEnvironmentVariable(pair.Key) is not null;
            if (overrideEnvironment || !hasValue)
            {
                Environment.SetEnvironmentVariable(pair.Key, pair.Value);
            }
        }
    }
}