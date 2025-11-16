using FrostYeti.Collections.Generic;
using FrostYeti.Results;

namespace FrostYeti.Blocks;

public abstract class SyncBlock<T> : ISyncBlock<T>
    where T : notnull
{
    public CancellationToken CancellationToken { get; set; }

    public virtual Result<T> Run()
    {
        return this.Run(this.CancellationToken);
    }

    public abstract Result<T> Run(CancellationToken cancellationToken);
}

public abstract class SyncBlock : SyncBlock<Never>, ISyncBlock
{
    public static SyncBlock<T> New<T>(Func<CancellationToken, Result<T>> run)
        where T : notnull
    {
        return new FuncSyncBlock<T>(run);
    }

    public static OutputSyncBlock NewOutput(Func<CancellationToken, Result<Outputs>> run)
    {
        return new FuncOutputSyncBlock(run);
    }

    Result ISyncBlock.Run()
        => this.Run(this.CancellationToken);

    Result ISyncBlock.Run(CancellationToken cancellationToken)
        => this.Run(cancellationToken);
}

public abstract class OutputSyncBlock : SyncBlock<Outputs>, IOutputSyncBlock
{
}

internal sealed class FuncSyncBlock<T> : SyncBlock<T>
    where T : notnull
{
    private readonly Func<CancellationToken, Result<T>> run;

    public FuncSyncBlock(Func<CancellationToken, Result<T>> run)
    {
        this.run = run;
    }

    public override Result<T> Run(CancellationToken cancellationToken)
    {
        return this.run(cancellationToken);
    }
}

internal sealed class FuncOutputSyncBlock : OutputSyncBlock
{
    private readonly Func<CancellationToken, Result<Outputs>> run;

    public FuncOutputSyncBlock(Func<CancellationToken, Result<Outputs>> run)
    {
        this.run = run;
    }

    public override Result<Outputs> Run(CancellationToken cancellationToken)
    {
        return this.run(cancellationToken);
    }
}