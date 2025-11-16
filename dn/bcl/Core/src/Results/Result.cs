namespace FrostYeti.Results;

public class Result : IEmptyResult<Exception>
{
    private readonly Exception? error;

    public Result()
    {
        this.IsOk = true;
        this.error = null;
    }

    public Result(Exception error)
    {
        this.error = error;
        this.IsOk = false;
    }

    public static implicit operator Result<Never>(Result result)
    {
        if (result.IsError)
            return new Result<Never>(result.Error);

        return new Result<Never>(Never.Value);
    }

    public static implicit operator Result(Result<Never> result)
    {
        if (result.IsError)
            return new Result(result.Error);

        return Result.Ok();
    }

    public static implicit operator Task<Result>(Result result)
    {
        return Task.FromResult(result);
    }

    public static implicit operator ValueTask<Result>(Result result)
    {
        return new ValueTask<Result>(result);
    }

    public static Result Ok()
    {
        return new Result();
    }

    public static Result<TValue> Ok<TValue>(TValue value)
        where TValue : notnull
    {
        return new Result<TValue>(value);
    }

    public static Result<TValue, TError> Ok<TValue, TError>(TValue value)
        where TValue : notnull
        where TError : notnull
    {
        return Result<TValue, TError>.Ok(value);
    }

    public static Result Fail(Exception error)
    {
        return new Result(error);
    }

    public static Result<TValue> Fail<TValue>(Exception error)
        where TValue : notnull
    {
        return new Result<TValue>(error);
    }

    public static Result<TValue, TError> Fail<TValue, TError>(TError error)
        where TValue : notnull
        where TError : notnull
    {
        return Result<TValue, TError>.Fail(error);
    }

    public static Result TryCatch(Action action)
    {
        try
        {
            action();
            return new();
        }
        catch (Exception ex)
        {
            return new Result(ex);
        }
    }

    public static Result<TValue> TryCatch<TValue>(Func<TValue> func)
        where TValue : notnull
    {
        try
        {
            return new Result<TValue>(func());
        }
        catch (Exception ex)
        {
            return new Result<TValue>(ex);
        }
    }

    public static Result<TValue, TError> TryCatch<TValue, TError>(
        Func<TValue> func,
        Func<Exception, TError> errorFactory)
        where TValue : notnull
        where TError : notnull
    {
        try
        {
            return Result<TValue, TError>.Ok(func());
        }
        catch (Exception ex)
        {
            return Result<TValue, TError>.Fail(errorFactory(ex));
        }
    }

    public static async Task<Result> TryCatchAsync(Func<Task> action)
    {
        try
        {
            await action().ConfigureAwait(false);
            return new Result();
        }
        catch (Exception ex)
        {
            return new Result(ex);
        }
    }

    public static async Task<Result<TValue>> TryCatchAsync<TValue>(Func<Task<TValue>> func)
        where TValue : notnull
    {
        try
        {
            var result = await func().ConfigureAwait(false);
            return new Result<TValue>(result);
        }
        catch (Exception ex)
        {
            return new Result<TValue>(ex);
        }
    }

    public static async Task<Result<TValue, TError>> TryCatchAsync<TValue, TError>(Func<Task<TValue>> func, Func<Exception, TError> errorFactory)
        where TValue : notnull
        where TError : notnull
    {
        try
        {
            var result = await func().ConfigureAwait(false);
            return Result<TValue, TError>.Ok(result);
        }
        catch (Exception ex)
        {
            return Result<TValue, TError>.Fail(errorFactory(ex));
        }
    }

    public bool IsOk { get; }

    public bool IsError => !this.IsOk;

    public Exception Error
    {
        get
        {
            if (this.IsError)
                return this.error!;

#pragma warning disable S2372 // Exceptions should not be thrown from property getters
            throw new ResultException("No error present");
        }
    }

    object IResult.Error => this.Error;

    public bool TryGetError(out Exception? error)
    {
        error = this.error;
        return this.IsError;
    }

    bool IResult.TryGetError(out object? error)
    {
        error = this.error;
        return this.IsError;
    }
}