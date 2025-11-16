using System.Runtime.CompilerServices;

using FrostYeti.Collections.Generic;
using FrostYeti.Results;

namespace FrostYeti.Blocks;

public abstract class AsyncBlock<T> : IAsyncBlock<T>
    where T : notnull
{
    public CancellationToken CancellationToken { get; set; }

    public TaskAwaiter<Result<T>> GetAwaiter()
    {
        return this.RunAsync(this.CancellationToken).GetAwaiter();
    }

    public virtual Task<Result<T>> RunAsync()
    {
        return this.RunAsync(this.CancellationToken);
    }

    public abstract Task<Result<T>> RunAsync(CancellationToken cancellationToken);
}

public abstract class AsyncBlock : AsyncBlock<Never>, IAsyncBlock
{

    public static AsyncBlock<T> New<T>(Func<CancellationToken, Task<Result<T>>> run)
        where T : notnull
    {
        return new FuncAsyncBlock<T>(run);
    }

    public static OutputAsyncBlock NewOutput(Func<CancellationToken, Task<Result<Outputs>>> run)
    {
        return new FuncOutputAsyncBlock(run);
    }

    async Task<Result> IAsyncBlock.RunAsync()
    {
        var result = await this.RunAsync(this.CancellationToken).ConfigureAwait(false);
        if (result.IsError)
            return Result.Fail(result.Error);

        return Result.Ok();
    }

    async Task<Result> IAsyncBlock.RunAsync(CancellationToken cancellationToken)
    {
        var result = await this.RunAsync(cancellationToken).ConfigureAwait(false);
        if (result.IsError)
            return Result.Fail(result.Error);

        return Result.Ok();
    }
}

public abstract class OutputAsyncBlock : AsyncBlock<Outputs>, IOutputAsyncBlock
{
}

internal sealed class FuncAsyncBlock<T> : AsyncBlock<T>
    where T : notnull
{
    private readonly Func<CancellationToken, Task<Result<T>>> run;

    public FuncAsyncBlock(Func<CancellationToken, Task<Result<T>>> run)
    {
        this.run = run;
    }

    public override Task<Result<T>> RunAsync(CancellationToken cancellationToken)
    {
        return this.run(cancellationToken);
    }
}

internal sealed class FuncOutputAsyncBlock : OutputAsyncBlock
{
    private readonly Func<CancellationToken, Task<Result<Outputs>>> run;

    public FuncOutputAsyncBlock(Func<CancellationToken, Task<Result<Outputs>>> run)
    {
        this.run = run;
    }

    public override Task<Result<Outputs>> RunAsync(CancellationToken cancellationToken)
    {
        return this.run(cancellationToken);
    }
}