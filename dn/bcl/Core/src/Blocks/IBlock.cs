using FrostYeti.Collections.Generic;
using FrostYeti.Results;

namespace FrostYeti.Blocks;

public interface IBlock : ISyncBlock, IAsyncBlock
{
}

public interface IBlock<T> : ISyncBlock<T>, IAsyncBlock<T>
     where T : notnull
{
}

public interface IOutputBlock : IOutputSyncBlock, IOutputAsyncBlock
{
}

public interface IAsyncBlock
{
    CancellationToken CancellationToken { get; }

    Task<Result> RunAsync();

    Task<Result> RunAsync(CancellationToken cancellationToken);
}

public interface IAsyncBlock<T>
     where T : notnull
{
    CancellationToken CancellationToken { get; }

    Task<Result<T>> RunAsync();

    Task<Result<T>> RunAsync(CancellationToken cancellationToken);
}

public interface IOutputAsyncBlock : IAsyncBlock<Outputs>
{
}

public interface ISyncBlock
{
    CancellationToken CancellationToken { get; }

    Result Run();

    Result Run(CancellationToken cancellationToken);
}

public interface ISyncBlock<T>
     where T : notnull
{
    CancellationToken CancellationToken { get; }

    Result<T> Run();

    Result<T> Run(CancellationToken cancellationToken);
}

public interface IOutputSyncBlock : ISyncBlock<Outputs>
{
}