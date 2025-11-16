namespace FrostYeti.Results;

public static class ResultExtensions
{
    public static bool IsOkAnd<TValue, TError>(this IValueResult<TValue, TError> r, Func<TValue, bool> predicate)
        where TValue : notnull
        where TError : notnull
        => r.IsOk && predicate(r.Value);

    public static bool IsErrorAnd<TError>(this IResult<TError> r, Func<TError, bool> predicate)
        where TError : notnull
        => r.IsError && predicate(r.Error);

    public static TValue Expect<TValue, TError>(this IValueResult<TValue, TError> r, string message)
        where TValue : notnull
        where TError : notnull
    {
        if (r.IsOk)
            return r.Value;

        throw new ResultException(message);
    }

    public static TError ExpectError<TError>(this IResult<TError> r, string message)
        where TError : notnull
    {
        if (!r.IsError)
            return r.Error;

        throw new ResultException(message);
    }
}