using Xunit;

using Res = FrostYeti.Results.Result<string, string>;

namespace FrostYeti.Results.Tests;

public class Resuls2Tests
{
    [Fact]
    public void ValueConstructor_CreatesSuccessResult()
    {
        var result = Result<string, string>.Ok("success");
        Assert.True(result.IsOk);
        Assert.False(result.IsError);
        Assert.Equal("success", result.Value);
    }

    [Fact]
    public void ErrorConstructor_CreatesErrorResult()
    {
        var result = Result<string, string>.Fail("error");
        Assert.False(result.IsOk);
        Assert.True(result.IsError);
        Assert.Equal("error", result.Error);
    }

    [Fact]
    public void TryGetValue_WhenSuccess_ReturnsTrue()
    {
        var result = Res.Ok("success");
        Assert.True(result.TryGetValue(out var value));
        Assert.Equal("success", value);
    }

    [Fact]
    public void TryGetError_WhenError_ReturnsTrue()
    {
        var result = Res.Fail("error");
        Assert.True(result.TryGetError(out var error));
        Assert.Equal("error", error);
    }

    [Fact]
    public void Map_WhenSuccess_TransformsValue()
    {
        var result = Res.Ok("5");
        var mapped = result.Map(int.Parse);
        Assert.True(mapped.IsOk);
        Assert.Equal(5, mapped.Value);
    }

    [Fact]
    public void MapError_WhenError_TransformsError()
    {
        var result = Res.Fail("error");
        var mapped = result.Map(o => o, e => e.Length);
        Assert.True(mapped.IsError);
        Assert.Equal(5, mapped.Error);
    }

    [Fact]
    public void Equals_WhenBothSuccess_ComparesByValue()
    {
        var result1 = Res.Ok("success");
        var result2 = Res.Ok("success");
        Assert.Equal(result1, result2);
    }

    [Fact]
    public void OrDefault_WhenError_ReturnsDefault()
    {
        var result = Res.Fail("error");
        var value = result.OrDefault("default");
        Assert.Equal("default", value);
    }
}