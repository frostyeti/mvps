using Xunit;

namespace FrostYeti.Results.Tests;

public class Result1_Tests
{
    [Fact]
    public void Constructor_WithValue_SetsIsOkTrue()
    {
        var result = new Result<string>("test");
        Assert.True(result.IsOk);
        Assert.False(result.IsError);
        Assert.Equal("test", result.Value);
    }

    [Fact]
    public void Constructor_WithError_SetsIsOkFalse()
    {
        var error = new Exception("test error");
        var result = new Result<string>(error);
        Assert.False(result.IsOk);
        Assert.True(result.IsError);
        Assert.Equal(error, result.Error);
    }

    [Fact]
    public void Map_WhenOk_TransformsValue()
    {
        var result = new Result<string>("test");
        var mapped = result.Map(s => s.Length);
        Assert.True(mapped.IsOk);
        Assert.Equal(4, mapped.Value);
    }

    [Fact]
    public void Map_WhenError_PropagatesError()
    {
        var error = new Exception("test error");
        var result = new Result<string>(error);
        var mapped = result.Map(s => s.Length);
        Assert.True(mapped.IsError);
        Assert.Equal(error, mapped.Error);
    }

    [Fact]
    public void Or_WhenOk_ReturnsOriginal()
    {
        var result = new Result<string>("test");
        var or = result.Or("other");
        Assert.Equal("test", or.Value);
    }

    [Fact]
    public void Or_WhenError_ReturnsAlternative()
    {
        var result = new Result<string>(new Exception());
        var or = result.Or("other");
        Assert.Equal("other", or.Value);
    }

    [Fact]
    public void Equals_WithSameValue_ReturnsTrue()
    {
        var result1 = new Result<string>("test");
        var result2 = new Result<string>("test");
        Assert.True(result1.Equals(result2));
    }

    [Fact]
    public void Equals_WithDifferentValue_ReturnsFalse()
    {
        var result1 = new Result<string>("test1");
        var result2 = new Result<string>("test2");
        Assert.False(result1.Equals(result2));
    }

    [Fact]
    public void ImplicitOperator_FromValue_CreatesOkResult()
    {
        Result<string> result = "test";
        Assert.True(result.IsOk);
        Assert.Equal("test", result.Value);
    }

    [Fact]
    public void ImplicitOperator_FromError_CreatesErrorResult()
    {
        var error = new Exception("test error");
        Result<string> result = error;
        Assert.True(result.IsError);
        Assert.Equal(error, result.Error);
    }
}