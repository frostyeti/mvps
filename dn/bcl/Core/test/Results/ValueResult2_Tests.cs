using Xunit;

namespace FrostYeti.Results.Tests;

public class ValueResult2Tests
{
    [Fact]
    public void Ok_WithValue_SetsIsOkTrue()
    {
        var result = ValueResult<string, int>.Ok("test");
        Assert.True(result.IsOk);
        Assert.False(result.IsError);
        Assert.Equal("test", result.Value);
    }

    [Fact]
    public void Fail_WithError_SetsIsOkFalse()
    {
        var result = ValueResult<string, int>.Fail(404);
        Assert.False(result.IsOk);
        Assert.True(result.IsError);
        Assert.Equal(404, result.Error);
    }

    [Fact]
    public void Value_WhenError_ThrowsException()
    {
        var result = ValueResult<string, int>.Fail(404);
        Assert.Throws<ResultException>(() => result.Value);
    }

    [Fact]
    public void Error_WhenOk_ThrowsException()
    {
        var result = ValueResult<string, int>.Ok("test");
        Assert.Throws<ResultException>(() => result.Error);
    }

    [Fact]
    public void Map_WhenOk_TransformsValue()
    {
        var result = ValueResult<int, string>.Ok(5);
        var mapped = result.Map(x => x * 2);
        Assert.Equal(10, mapped.Value);
    }

    [Fact]
    public void MapError_WhenError_TransformsError()
    {
        var result = ValueResult<int, string>.Fail("error");
        var mapped = result.Map(o => o, e => e.Length);
        Assert.Equal(5, mapped.Error);
    }

    [Fact]
    public void Equals_WhenBothOkWithSameValue_ReturnsTrue()
    {
        var result1 = ValueResult<string, int>.Ok("test");
        var result2 = ValueResult<string, int>.Ok("test");
        Assert.Equal(result1, result2);
    }

    [Fact]
    public void Equals_WhenBothErrorWithSameError_ReturnsTrue()
    {
        var result1 = ValueResult<string, int>.Fail(404);
        var result2 = ValueResult<string, int>.Fail(404);
        Assert.Equal(result1, result2);
    }

    [Fact]
    public void TryGetValue_WhenOk_ReturnsTrue()
    {
        var result = ValueResult<string, int>.Ok("test");
        Assert.True(result.TryGetValue(out var value));
        Assert.Equal("test", value);
    }

    [Fact]
    public void TryGetError_WhenError_ReturnsTrue()
    {
        var result = ValueResult<string, int>.Fail(404);
        Assert.True(result.TryGetError(out var error));
        Assert.Equal(404, error);
    }
}