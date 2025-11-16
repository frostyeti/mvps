using Xunit;

namespace FrostYeti.Results.Tests;

public class ValueResult1_Tests
{
    [Fact]
    public void Constructor_WithValue_SetsIsOkTrue()
    {
        var result = new ValueResult<string>("test");
        Assert.True(result.IsOk);
        Assert.False(result.IsError);
        Assert.Equal("test", result.Value);
    }

    [Fact]
    public void Constructor_WithError_SetsIsOkFalse()
    {
        var error = new Exception("error");
        var result = new ValueResult<string>(error);
        Assert.False(result.IsOk);
        Assert.True(result.IsError);
        Assert.Equal(error, result.Error);
    }

    [Fact]
    public void ImplicitConversion_FromValue_CreatesSuccessResult()
    {
        ValueResult<int> result = 42;
        Assert.True(result.IsOk);
        Assert.Equal(42, result.Value);
    }

    [Fact]
    public void ImplicitConversion_FromError_CreatesErrorResult()
    {
        var error = new Exception("test error");
        ValueResult<int> result = error;
        Assert.True(result.IsError);
        Assert.Equal(error, result.Error);
    }

    [Fact]
    public void Map_OnSuccess_TransformsValue()
    {
        ValueResult<int> result = 42;
        var mapped = result.Map(x => x.ToString());
        Assert.True(mapped.IsOk);
        Assert.Equal("42", mapped.Value);
    }

    [Fact]
    public void Map_OnError_PropagatesError()
    {
        var error = new Exception("test error");
        ValueResult<int> result = error;
        var mapped = result.Map(x => x.ToString());
        Assert.True(mapped.IsError);
        Assert.Equal(error, mapped.Error);
    }

    [Fact]
    public void OrDefault_OnSuccess_ReturnsValue()
    {
        ValueResult<int> result = 42;
        Assert.Equal(42, result.OrDefault(0));
    }

    [Fact]
    public void OrDefault_OnError_ReturnsDefault()
    {
        ValueResult<int> result = new Exception();
        Assert.Equal(0, result.OrDefault(0));
    }

    [Fact]
    public void TryGetValue_OnSuccess_ReturnsTrue()
    {
        ValueResult<int> result = 42;
        Assert.True(result.TryGetValue(out var value));
        Assert.Equal(42, value);
    }

    [Fact]
    public void TryGetValue_OnError_ReturnsFalse()
    {
        ValueResult<int> result = new Exception();
        Assert.False(result.TryGetValue(out var value));
        Assert.Equal(default, value);
    }

    [Fact]
    public void Equals_WithSameValue_ReturnsTrue()
    {
        ValueResult<int> result1 = 42;
        ValueResult<int> result2 = 42;
        Assert.True(result1.Equals(result2));
        Assert.True(result1 == result2);
    }

    [Fact]
    public void Equals_WithDifferentValue_ReturnsFalse()
    {
        ValueResult<int> result1 = 42;
        ValueResult<int> result2 = 24;
        Assert.False(result1.Equals(result2));
        Assert.True(result1 != result2);
    }
}