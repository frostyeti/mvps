using System.Text;

using FrostYeti.DotEnv.Documents;
using FrostYeti.DotEnv.Serialization;

namespace FrostYeti.DotEnv;

public static class DotEnvSerializer
{
    public static string SerializeDocument(DotEnvDocument document, DotEnvSerializerOptions? options = null)
    {
        using var stringWriter = new StringWriter();
        Serializer.SerializeDocument(document, stringWriter, options);
        return stringWriter.ToString();
    }

    public static void SerializeDocument(DotEnvDocument document, TextWriter writer, DotEnvSerializerOptions? options = null)
        => Serializer.SerializeDocument(document, writer, options);

    public static void SerializeDocument(DotEnvDocument document, Stream stream, DotEnvSerializerOptions? options = null)
    {
        using var sw = new StreamWriter(stream, Encoding.UTF8);
        Serializer.SerializeDocument(document, sw, options);
    }

    public static string SerializeDictionary(IEnumerable<KeyValuePair<string, string>> dictionary, DotEnvSerializerOptions? options = null)
    {
        using var stringWriter = new StringWriter();
        Serializer.SerializeDictionary(dictionary, stringWriter, options);
        return stringWriter.ToString();
    }

    public static void SerializeDictionary(IEnumerable<KeyValuePair<string, string>> dictionary, Stream stream, DotEnvSerializerOptions? options = null)
    {
        using var sw = new StreamWriter(stream, Encoding.UTF8);
        Serializer.SerializeDictionary(dictionary, sw, options);
    }

    public static void SerializeDictionary(IEnumerable<KeyValuePair<string, string>> dictionary, TextWriter writer, DotEnvSerializerOptions? options = null)
        => Serializer.SerializeDictionary(dictionary, writer, options);

    public static OrderedDictionary<string, string> DeserializeDictionary(string value, DotEnvSerializerOptions? options = null)
    {
        using var sr = new StringReader(value);
        return DeserializeDictionary(sr, options);
    }

    public static OrderedDictionary<string, string> DeserializeDictionary(Stream stream, DotEnvSerializerOptions? options = null)
    {
        using var sr = new StreamReader(stream, Encoding.UTF8);
        return DeserializeDictionary(sr, options);
    }

    public static OrderedDictionary<string, string> DeserializeDictionary(TextReader writer, DotEnvSerializerOptions? options = null)
    {
        var doc = Serializer.DeserializeDocument(writer, options);
        return doc.ToOrderedDictionary();
    }

    public static DotEnvDocument DeserializeDocument(string value, DotEnvSerializerOptions? options = null)
    {
        using var sr = new StringReader(value);
        return DeserializeDocument(sr, options);
    }

    public static DotEnvDocument DeserializeDocument(Stream stream, DotEnvSerializerOptions? options = null)
    {
        using var sr = new StreamReader(stream, Encoding.UTF8);
        return DeserializeDocument(sr, options);
    }

    public static DotEnvDocument DeserializeDocument(TextReader reader, DotEnvSerializerOptions? options = null)
        => Serializer.DeserializeDocument(reader, options);
}