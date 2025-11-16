using System.Runtime.CompilerServices;

using FrostYeti.Collections.Generic;
using FrostYeti.Results;

namespace FrostYeti.Blocks;

public abstract class Block<T> : SyncBlock<T>, IAsyncBlock<T>
    where T : notnull
{
    public virtual TaskAwaiter<Result<T>> GetAwaiter()
    {
        return this.RunAsync(this.CancellationToken).GetAwaiter();
    }

    public virtual Task<Result<T>> RunAsync()
    {
        return this.RunAsync(this.CancellationToken);
    }

    public abstract Task<Result<T>> RunAsync(CancellationToken cancellationToken);
}

public abstract class Block : Block<Never>, IAsyncBlock, ISyncBlock
{
    public static Block<T> New<T>(Func<CancellationToken, Result<T>> run)
        where T : notnull
    {
        return new FuncBlock<T>(run);
    }

    public static Block<T> New<T>(
        Func<CancellationToken, Result<T>> run,
        Func<CancellationToken, Task<Result<T>>> asyncRun)
        where T : notnull
    {
        return new FuncBlock<T>(run, asyncRun);
    }

    public static OutputBlock NewOutputBlock(Func<CancellationToken, Result<Outputs>> run)
    {
        return new FuncOutputBlock(run);
    }

    public static OutputBlock NewOutputBlock(
        Func<CancellationToken, Result<Outputs>> run,
        Func<CancellationToken, Task<Result<Outputs>>> asyncRun)
    {
        return new FuncOutputBlock(run, asyncRun);
    }

    Result ISyncBlock.Run()
    {
        return this.Run();
    }

    Result ISyncBlock.Run(CancellationToken cancellationToken)
    {
        return this.Run(cancellationToken);
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

public abstract class OutputBlock : Block<Outputs>, IOutputAsyncBlock, IOutputSyncBlock
{
}

internal sealed class FuncBlock<T> : Block<T>
    where T : notnull
{
    private readonly Func<CancellationToken, Result<T>> run;

    private readonly Func<CancellationToken, Task<Result<T>>>? asyncRun;

    public FuncBlock(Func<CancellationToken, Result<T>> run)
    {
        this.run = run;
    }

    public FuncBlock(Func<CancellationToken, Result<T>> run, Func<CancellationToken, Task<Result<T>>> asyncRun)
    {
        this.run = run;
        this.asyncRun = asyncRun;
    }

    public override Result<T> Run(CancellationToken cancellationToken)
    {
        return this.run(cancellationToken);
    }

    public override async Task<Result<T>> RunAsync(CancellationToken cancellationToken)
    {
        if (this.asyncRun is not null)
        {
            return await this.asyncRun(cancellationToken).ConfigureAwait(false);
        }

        return this.run(cancellationToken);
    }
}

internal sealed class FuncOutputBlock : OutputBlock
{
    private readonly Func<CancellationToken, Result<Outputs>> run;

    private readonly Func<CancellationToken, Task<Result<Outputs>>>? asyncRun;

    public FuncOutputBlock(Func<CancellationToken, Result<Outputs>> run)
    {
        this.run = run;
    }

    public FuncOutputBlock(Func<CancellationToken, Result<Outputs>> run, Func<CancellationToken, Task<Result<Outputs>>> asyncRun)
    {
        this.run = run;
        this.asyncRun = asyncRun;
    }

    public override Result<Outputs> Run(CancellationToken cancellationToken)
    {
        return this.run(cancellationToken);
    }

    public override async Task<Result<Outputs>> RunAsync(CancellationToken cancellationToken)
    {
        if (this.asyncRun is not null)
        {
            return await this.asyncRun(cancellationToken).ConfigureAwait(false);
        }

        return this.run(cancellationToken);
    }
}