using Xunit;

namespace FrostYeti.Results.Tests;

public class Result_Tests
{
    [Fact]
    public void Ok_CreatesSuccessResult()
    {
        var result = Result.Ok();

        Assert.True(result.IsOk);
        Assert.False(result.IsError);
    }

    [Fact]
    public void Fail_CreatesErrorResult()
    {
        var exception = new Exception("test");
        var result = Result.Fail(exception);

        Assert.False(result.IsOk);
        Assert.True(result.IsError);
        Assert.Same(exception, result.Error);
    }

    [Fact]
    public void TryCatch_Success_ReturnsOkResult()
    {
        var result = Result.TryCatch(() => { });

        Assert.True(result.IsOk);
    }

    [Fact]
    public void TryCatch_Exception_ReturnsErrorResult()
    {
        var result = Result.TryCatch(() => throw new InvalidOperationException("test"));

        Assert.True(result.IsError);
        Assert.IsType<InvalidOperationException>(result.Error);
    }

    [Fact]
    public async Task TryCatchAsync_Success_ReturnsOkResult()
    {
        var result = await Result.TryCatchAsync(async () => await Task.CompletedTask);

        Assert.True(result.IsOk);
    }

    [Fact]
    public async Task TryCatchAsync_Exception_ReturnsErrorResult()
    {
        var result = await Result.TryCatchAsync(() => throw new InvalidOperationException("test"));

        Assert.True(result.IsError);
        Assert.IsType<InvalidOperationException>(result.Error);
    }

    [Fact]
    public void TryGetError_OnError_ReturnsTrue()
    {
        var exception = new Exception("test");
        var result = Result.Fail(exception);

        Assert.True(result.TryGetError(out var error));
        Assert.Same(exception, error);
    }

    [Fact]
    public void TryGetError_OnSuccess_ReturnsFalse()
    {
        var result = Result.Ok();

        Assert.False(result.TryGetError(out var error));
        Assert.Null(error);
    }

    [Fact]
    public void Error_OnSuccess_ThrowsResultException()
    {
        var result = Result.Ok();

        Assert.Throws<ResultException>(() => result.Error);
    }
}