namespace FrostYeti.Results.Tests;

public class ValueResult_Tests
{
    [Fact]
    public void Default_ShouldBeOk()
    {
        var result = ValueResult.Default;
        Assert.True(result.IsOk);
        Assert.False(result.IsError);
    }

    [Fact]
    public void Constructor_WithError_ShouldCreateErrorResult()
    {
        var ex = new Exception("test");
        var result = new ValueResult(ex);
        Assert.False(result.IsOk);
        Assert.True(result.IsError);
        Assert.Same(ex, result.Error);
    }

    [Fact]
    public void Error_WhenOk_ShouldThrow()
    {
        var result = ValueResult.Default;
        Assert.Throws<ResultException>(() => result.Error);
    }

    [Fact]
    public void ImplicitConversion_ToException_ShouldReturnError()
    {
        var ex = new Exception("test");
        ValueResult result = ex;
        Assert.False(result.IsOk);
        Assert.Same(ex, result.Error);
    }

    [Fact]
    public async Task TryCatchRef_WhenActionSucceeds_ShouldReturnOk()
    {
        var result = ValueResult.TryCatchRef(() => { });
        Assert.True(result.IsOk);

        var asyncResult = await ValueResult.TryCatchRefAsync(async () => await Task.CompletedTask);
        Assert.True(asyncResult.IsOk);
    }

    [Fact]
    public void TryCatchRef_WhenActionThrows_ShouldReturnError()
    {
        var ex = new InvalidOperationException("test");
        var result = ValueResult.TryCatchRef(() => throw ex);
        Assert.False(result.IsOk);
        Assert.Same(ex, result.Error);
    }

    [Fact]
    public async Task TryCatchRefAsync_WhenActionThrows_ShouldReturnError()
    {
        var ex = new InvalidOperationException("test");
        var result = await ValueResult.TryCatchRefAsync(() => throw ex);
        Assert.False(result.IsOk);
        Assert.Same(ex, result.Error);
    }

    [Fact]
    public void Equals_WhenBothOk_ShouldReturnTrue()
    {
        var result1 = ValueResult.Default;
        var result2 = ValueResult.Default;
        Assert.True(result1.Equals(result2));
        Assert.True(result1 == result2);
    }

    [Fact]
    public void Equals_WhenBothError_WithSameException_ShouldReturnTrue()
    {
        var ex = new Exception("test");
        var result1 = new ValueResult(ex);
        var result2 = new ValueResult(ex);
        Assert.True(result1.Equals(result2));
        Assert.True(result1 == result2);
    }

    [Fact]
    public void TryGetError_WhenOk_ShouldReturnFalse()
    {
        var result = ValueResult.Default;
        Assert.False(result.TryGetError(out var error));
        Assert.Null(error);
    }

    [Fact]
    public void TryGetError_WhenError_ShouldReturnTrue()
    {
        var ex = new Exception("test");
        var result = new ValueResult(ex);
        Assert.True(result.TryGetError(out var error));
        Assert.Same(ex, error);
    }
}