namespace FrostYeti.Results;

public interface IResult
{
    bool IsOk { get; }

    bool IsError { get; }

    object Error { get; }

    bool TryGetError(out object? error);
}

public interface IEmptyResult : IResult
{
}

public interface IValueResult : IResult
{
    object Value { get; }

    bool TryGetValue(out object? value);
}

public interface IResult<TError> : IResult
    where TError : notnull
{
    new TError Error { get; }

    bool TryGetError(out TError? error);
}

public interface IEmptyResult<TError> : IEmptyResult, IResult<TError>
    where TError : notnull
{
}

public interface IValueResult<TValue, TError> : IResult<TError>, IEquatable<IValueResult<TValue, TError>>, IValueResult
    where TValue : notnull
    where TError : notnull
{
    new TValue Value { get; }

    bool TryGetValue(out TValue? value);
}