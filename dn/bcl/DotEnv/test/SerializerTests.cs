using FrostYeti.DotEnv;
using FrostYeti.DotEnv.Documents;

namespace FrostYeti.DotEnv.Tests;

public static class SerializerTests
{

    [Fact]
    public static void Verify_Simple()
    {
        var env = DotEnvSerializer.DeserializeDictionary(
            """
TEST="Hello World"
""");
        Assert.NotNull(env);
        Assert.IsType<OrderedDictionary<string, string>>(env);
        Assert.Equal("Hello World", env["TEST"]);
    }

    [Fact]
    public static void Verify_Multiple()
    {
        var envContent = """
TEST=hello_world
NUMBER=1
PW=X232dwe)()_+!@
""";
        var env = DotEnvSerializer.DeserializeDictionary(
            envContent);

        Assert.NotNull(env);
        Assert.IsType<OrderedDictionary<string, string>>(env);
        Assert.Equal("hello_world", env["TEST"]);
        Assert.Equal("1", env["NUMBER"]);
        Assert.Equal("X232dwe)()_+!@", env["PW"]);
    }

    [Fact]
    public static void Verify_EmptyLinesAreIgnored()
    {
        var envContent = """
TEST=hello_world

PW=X232dwe)()_+!@

""";
        var env = DotEnvSerializer.DeserializeDocument(
            envContent);

        Assert.NotNull(env);
        Assert.IsType<DotEnvDocument>(env);

        Assert.Equal(2, env.Count);
        Assert.Equal("hello_world", env["TEST"]);
        Assert.Equal("X232dwe)()_+!@", env["PW"]);
    }

    [Fact]
    public static void Verify_ExpandWithCustomVariables()
    {
        var envContent = """
PW=X232dwe)()_+!@
TEST=hello_world
""";
        var env = DotEnvSerializer.DeserializeDocument(envContent);
        foreach (var node in env)
        {
            if (node is DotEnvEntry entry)
            {
                Console.WriteLine($"Key: {entry.Name}, Value: {entry.Value}");
            }
            else
            {
                Console.WriteLine(node.Value);
            }
        }

        Assert.NotNull(env);
        Assert.Equal(2, env.Count);
        Assert.Equal("hello_world", env["TEST"]);
        Assert.Equal("X232dwe)()_+!@", env["PW"]);
    }

    [Fact]
    public static void Verify_KeyCanSkipWhiteSpace()
    {
        var envContent = """
  TEST  =hello_world
  PW   =X232dwe)()_+!@
""";
        var env = DotEnvSerializer.DeserializeDocument(envContent);

        Assert.NotNull(env);
        Assert.Equal(2, env.Count);
        Assert.Equal("hello_world", env["TEST"]);
        Assert.Equal("X232dwe)()_+!@", env["PW"]);
    }

    [Fact]
    public static void Verify_OneMultilineValue()
    {
        var envContent = """
TEST="1
2
3"
""";
        var env = DotEnvSerializer.DeserializeDocument(envContent);

        Assert.NotNull(env);
        var r = "1\r\n2\r\n3";
        if (!OperatingSystem.IsWindows())
            r = "1\n2\n3";
        Assert.Equal(r, env["TEST"]);
    }

    [Fact]
    public static void Verify_MultipleMultilineValues()
    {
        var envContent = """
TEST="1
2
3"
PW='1
2
4'
""";
        var env = DotEnvSerializer.DeserializeDocument(envContent);

        Assert.NotNull(env);
        var r1 = "1\r\n2\r\n3";
        if (!OperatingSystem.IsWindows())
            r1 = "1\n2\n3";

        Assert.Equal(r1, env["TEST"]);

        var r2 = "1\r\n2\r\n4";
        if (!OperatingSystem.IsWindows())
            r2 = "1\n2\n4";

        Assert.Equal(r2, env["PW"]);
    }

    [Fact]
    public static void Verify_ValuesCanSkipWhiteSpace()
    {
        var envContent = """
TEST=  hello_world  
PW=  X232dwe)()_+!@  
""";
        var env = DotEnvSerializer.DeserializeDocument(envContent);

        Assert.NotNull(env);
        Assert.Equal(2, env.Count);
        Assert.Equal("hello_world", env["TEST"]);
        Assert.Equal("X232dwe)()_+!@", env["PW"]);
    }

    [Fact]
    public static void Verify_CommentsAreIgnored()
    {
        var envContent = """
# This is a comment
TEST=hello_world
  # this is a comment too
""";
        var env = DotEnvSerializer.DeserializeDocument(envContent);

        Assert.NotNull(env);
        Assert.True(env.Count is 3);
        Assert.Equal("hello_world", env["TEST"]);
    }

    [Fact]
    public static void Verify_DeserializeDocument()
    {
        Environment.SetEnvironmentVariable("WORD", "world");
        var envContent = """
# This is a comment
TEST=hello_world
  # this is a comment too
PW=X232dwe)()_+!@
## this is a comment woo hoo
MULTI="1
2
3
  4"
HW="Hello, ${WORD}"
""";
        var env = DotEnvSerializer.DeserializeDocument(
            envContent);

        Assert.NotNull(env);
        Assert.Equal("hello_world", env["TEST"]);
        Assert.Equal("X232dwe)()_+!@", env["PW"]);
        var r = "1\r\n2\r\n3\r\n  4";
        if (!OperatingSystem.IsWindows())
            r = "1\n2\n3\n  4";
        Assert.Equal(r, env["MULTI"]);
        Assert.Equal("Hello, ${WORD}", env["HW"]);
    }

    [Fact]
    public static void Verify_Json()
    {
        var envContent = """
JSON={
    ""test"": ""hello world"",
    ""test2"": ""hello world2""
}
""";
        var env = DotEnvSerializer.DeserializeDocument(
            envContent,
            new DotEnvSerializerOptions { Json = true });

        Assert.NotNull(env);
        Assert.True(env.Count is 1);
        Assert.Equal(
            """
{
    ""test"": ""hello world"",
    ""test2"": ""hello world2""
}
""",
            env["JSON"]);
    }

    [Fact]
    public static void Verify_Yaml()
    {
        var envContent = """
YAML=---
test: hello world
test2: hello world2
---
TEST=hello_world
""";
        var env = DotEnvSerializer.DeserializeDocument(
            envContent,
            new DotEnvSerializerOptions { Yaml = true });

        Assert.NotNull(env);
        Assert.Equal(2, env.Count);
        Assert.Equal(
            """
test: hello world
test2: hello world2

""",
            env["YAML"]);
        Assert.Equal("hello_world", env["TEST"]);
    }

    [Fact]
    public static void Serialize()
    {
        var dictionary = new OrderedDictionary<string, string>()
        {
            ["name"] = "John Doe",
            ["age"] = "21",
        };

        var result = DotEnvSerializer.SerializeDictionary(dictionary);
        var expected = $$"""
                         name="John Doe"
                         age=21
                         """;
        if (!OperatingSystem.IsWindows())
            expected = expected.Replace("\r\n", "\n");
        Assert.Equal(expected, result);
    }

    [Fact]
    public static void HandleEscapedCharacters()
    {
        var content =
"""
NAME="John \"Doe\""
AGE=21
ESCAPED="This is a \n test"
UNICODE="\u0041\u0042\u0043" # ABC
TAB="\t"
CARRIAGE_RETURN="\r"
""";

        var env = DotEnvSerializer.DeserializeDocument(content);
        Assert.NotNull(env);
        Assert.Equal("John \"Doe\"", env["NAME"]);
        Assert.Equal("21", env["AGE"]);
        Assert.Equal("This is a \n test", env["ESCAPED"]);
        Assert.Equal("ABC", env["UNICODE"]);
        Assert.Equal("\t", env["TAB"]);
        Assert.Equal("\r", env["CARRIAGE_RETURN"]);
    }

    [Fact]
    public static void SerializeEnvDocument()
    {
        var doc = new DotEnvDocument();
        doc.Add("name", "John Doe");
        doc.AddEmptyLine();
        doc.AddComment("Test");
        doc.Add("age", "21");

        var result = DotEnvSerializer.SerializeDocument(doc);
        var expected = $$"""
                         name="John Doe"
                         
                         # Test
                         age=21
                         """;
        if (!OperatingSystem.IsWindows())
            result = result.Replace("\r\n", "\n");

        Assert.Equal(expected, result);
    }

    [Fact]
    public static void ReadWithCommandSubstitution()
    {
        var content = """
PW=X232dwe)()_+!@
TEST="$(echo "world") yo"
""";
        var env = DotEnvSerializer.DeserializeDocument(
            content,
            new DotEnvSerializerOptions { QuotedCommandSubstitution = true });

        Assert.NotNull(env);
        Assert.Equal(2, env.Count);
        Assert.Equal("X232dwe)()_+!@", env["PW"]);
        Assert.Equal("$(echo \"world\") yo", env["TEST"]);
    }
}