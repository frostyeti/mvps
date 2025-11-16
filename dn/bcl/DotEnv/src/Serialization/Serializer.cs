using System.Collections;
using System.Diagnostics.CodeAnalysis;
using System.Text;

using FrostYeti.DotEnv.Documents;
using FrostYeti.DotEnv.Tokens;

namespace FrostYeti.DotEnv.Serialization;

internal static class Serializer
{
    public static void SerializeDictionary(
        IEnumerable<KeyValuePair<string, string>> dictionary,
        TextWriter writer,
        DotEnvSerializerOptions? options = null)
    {
        var first = true;
        foreach (var item in dictionary)
        {
            if (!first)
                writer.WriteLine();
            else
                first = false;

            var value = item.Value ?? string.Empty;
            var shouldQuote = value.IndexOfAny(['=', ' ', '\v', '\t', '\n', '\r', '"', '\'', '`']) >= 0;
            if (!shouldQuote)
            {
                writer.Write(item.Key);
                writer.Write('=');
                writer.Write(value);
            }
            else
            {
                var sb = new StringBuilder(value.Length + 2);
                foreach (var c in value)
                {
                    if (c == '"')
                    {
                        sb.Append('\\');
                    }

                    sb.Append(c);
                }

                writer.Write(item.Key);
                writer.Write('=');
                writer.Write('"');
                writer.Write(value);
                writer.Write('"');
            }
        }
    }

    public static void SerializeDictionary(
        IEnumerable<KeyValuePair<string, object?>> dictionary,
        TextWriter writer,
        DotEnvSerializerOptions? options = null)
    {
        bool first = true;
        foreach (var item in dictionary)
        {
            if (!first)
            {
                writer.WriteLine();
            }
            else
            {
                first = false;
            }

            var value = item.Value?.ToString() ?? string.Empty;

            var shouldQuote = value.IndexOfAny(['=', ' ', '\v', '\t', '\n', '\r', '"', '\'', '`']) >= 0;
            if (!shouldQuote)
            {
                writer.Write(item.Key);
                writer.Write('=');
                writer.Write(value);
            }
            else
            {
                var quote = value.Contains("\"") ? '\'' : '"';
                writer.Write(item.Key);
                writer.Write('=');
                writer.Write(quote);
                writer.Write(value);
                writer.Write(quote);
            }
        }
    }

    public static void SerializeDocument(
        DotEnvDocument document,
        TextWriter writer,
        DotEnvSerializerOptions? options = null)
    {
        var first = true;
        foreach (var item in document)
        {
            switch (item)
            {
                case DotEnvComment comment:
                    if (comment.Inline)
                    {
                        writer.Write(" # ");
                        writer.Write(comment.RawValue);
                    }
                    else
                    {
                        if (first)
                            first = false;
                        else
                            writer.WriteLine();
                        writer.Write("# ");
                        writer.Write(comment.RawValue);
                    }

                    break;

                case DotEnvEntry pair:
                    if (first)
                        first = false;
                    else
                        writer.WriteLine();

                    switch (pair.Quote)
                    {
                        case DotEnvQuote.Json:
                        case DotEnvQuote.Yaml:
                        case DotEnvQuote.None:
                            writer.Write(pair.Name);
                            writer.Write('=');
                            writer.Write(pair.Value);
                            break;

                        case DotEnvQuote.Auto:
                            {
                                var shouldQuote = pair.Value.IndexOfAny(['=', ' ', '\v', '\t', '\n', '\r', '"', '\'', '`']) >= 0;
                                if (!shouldQuote)
                                {
                                    writer.Write(pair.Name);
                                    writer.Write('=');
                                    writer.Write(pair.Value);
                                }
                                else
                                {
                                    writer.Write(pair.Name);
                                    writer.Write('=');
                                    writer.Write('"');
                                    var sb = new StringBuilder(pair.Value.Length + 2);
                                    foreach (var c in pair.Value)
                                    {
                                        if (c == '"')
                                        {
                                            writer.Write('\\');
                                        }

                                        writer.Write(c);
                                    }

                                    writer.Write('"');
                                }
                            }

                            break;

                        case DotEnvQuote.Double:
                            {
                                writer.Write(pair.Name);
                                writer.Write('=');
                                writer.Write('"');
                                for (var i = 0; i < pair.Value.Length; i++)
                                {
                                    var c = pair.Value[i];
                                    if (c == '\"')
                                    {
                                        var last = char.MinValue;
                                        if (i > 0)
                                            last = pair.Value[i - 1];

                                        if (last != '\\')
                                        {
                                            writer.Write('\\');
                                        }

                                        writer.Write(c);
                                    }

                                    writer.Write(c);
                                }

                                foreach (var c in pair.Value)
                                {
                                    switch (c)
                                    {
                                        case '\r':
                                            writer.Write("\\r");
                                            continue;
                                        case '\n':
                                            writer.Write("\\n");
                                            continue;
                                        case '\t':
                                            writer.Write("\\t");
                                            continue;
                                        case '\v':
                                            writer.Write("\\v");
                                            continue;
                                        case '\\':
                                            writer.Write("\\\\");
                                            continue;
                                        case '"':
                                            writer.Write("\\\"");
                                            continue;
                                    }

                                    writer.Write(c);
                                }

                                writer.Write('"');
                            }

                            break;

                        case DotEnvQuote.Single:
                            writer.Write(pair.Name);
                            writer.Write('=');
                            writer.Write('\'');
                            writer.Write(pair.Value);
                            writer.Write('\'');
                            break;

                        case DotEnvQuote.Backtick:
                            writer.Write(pair.Name);
                            writer.Write('=');
                            writer.Write('`');
                            writer.Write(pair.Value);
                            writer.Write('`');
                            break;
                    }

                    break;

                case DotEnvEmptyLine _:
                    writer.WriteLine();
                    break;

                default:
                    throw new NotSupportedException($"The type {item.GetType()} is not supported.");
            }
        }
    }

    public static DotEnvDocument DeserializeDocument(ReadOnlySpan<char> value, DotEnvSerializerOptions? options = null)
    {
        using var sr = new StringReader(value.AsString());
        return DeserializeDocument(sr, options);
    }

    public static DotEnvDocument DeserializeDocument(string value, DotEnvSerializerOptions? options = null)
    {
        using var sr = new StringReader(value);
        return DeserializeDocument(sr, options);
    }

    public static DotEnvDocument DeserializeDocument(Stream value, DotEnvSerializerOptions? options = null)
    {
        using var sr = new StreamReader(value, Encoding.UTF8, true, -1, true);
        return DeserializeDocument(sr, options);
    }

    public static DotEnvDocument DeserializeDocument(TextReader reader, DotEnvSerializerOptions? options = null)
    {
        options ??= new DotEnvSerializerOptions();
        var r = new DotEnvReader(reader, options);
        var doc = new DotEnvDocument();
        string? key = null;

        while (r.Read())
        {
            switch (r.Current)
            {
                case EnvCommentToken commentToken:
                    doc.Add(new DotEnvComment(commentToken.RawValue));
                    continue;

                case EnvNameToken nameToken:
                    key = nameToken.Value;
                    continue;

                case EnvScalarToken scalarToken:
                    var capture = scalarToken.Capture;

                    if (key is not null && key.Length > 0)
                    {
                        DotEnvEntry? entry = null;

                        if (doc.TryGetNameValuePair(key, out entry) && entry is not null)
                        {
                            entry.RawValue = scalarToken.RawValue;
                            key = null;
                            continue;
                        }
                        else
                        {
                            entry = new DotEnvEntry(key, scalarToken.RawValue);
                        }

                        switch (capture)
                        {
                            case Capture.DoubleQuote:
                                entry.Quote = DotEnvQuote.Double;
                                break;

                            case Capture.SingleQuote:
                                entry.Quote = DotEnvQuote.Single;
                                break;

                            case Capture.Backtick:
                                entry.Quote = DotEnvQuote.Backtick;
                                break;

                            case Capture.Brackets:
                                entry.Quote = DotEnvQuote.Json;
                                break;

                            case Capture.FrontMatter:
                                entry.Quote = DotEnvQuote.Yaml;
                                break;

                            default:
                                entry.Quote = DotEnvQuote.None;
                                break;
                        }

                        doc.Add(entry);
                        key = null;
                        continue;
                    }

                    throw new InvalidOperationException("Scalar token found without a name token before it.");
            }
        }

        return doc;
    }

    public static IDictionary DeserializeDictionary(DotEnvDocument document, [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)] Type type)
    {
        if (!type.IsAssignableFrom(type))
            throw new ArgumentException("Type must be assignable from IDictionary<string, string>.", nameof(type));

        var obj = Activator.CreateInstance(type);
        if (obj is null)
            throw new ArgumentException("Type must be instantiable.", nameof(type));

        var dict = (IDictionary)obj;
        foreach (var (name, value) in document.AsNameValuePairEnumerator())
            dict.Add(name, value);

        return dict;
    }

#if NET6_0_OR_GREATER

    public static T DeserializeDictionary<[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)] T>(DotEnvDocument document)
        where T : IDictionary<string, string?>
    {
        var type = typeof(T);
        var obj = Activator.CreateInstance<T>();
        if (obj is null)
            throw new InvalidOperationException($"Type {type.FullName} must be instantiable.");

        if (obj is not IDictionary<string, string?> dict)
            throw new InvalidOperationException($"Type {type.FullName} must be assignable from IDictionary<string, string>.");

        foreach (var (name, value) in document.AsNameValuePairEnumerator())
            dict.Add(name, value);

        return (T)dict;
    }

#else

    public static T DeserializeDictionary<T>(DotEnvDocument document)
        where T : IDictionary<string, string?>
    {
        var type = typeof(T);
        var obj = Activator.CreateInstance<T>();
        if (obj is null)
            throw new InvalidOperationException($"Type {type.FullName} must be instantiable.");

        if (obj is not IDictionary<string, string?> dict)
            throw new InvalidOperationException($"Type {type.FullName} must be assignable from IDictionary<string, string>.");

        foreach (var (name, value) in document.AsNameValuePairEnumerator())
            dict.Add(name, value);

        return (T)dict;
    }

#endif
}