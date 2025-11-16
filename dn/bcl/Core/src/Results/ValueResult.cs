using System.Security.Cryptography.X509Certificates;

namespace FrostYeti.Results;

public readonly struct ValueResult : IEmptyResult<System.Exception>,
    IEquatable<ValueResult>
{
    private readonly System.Exception? error;

    public ValueResult()
    {
        this.IsOk = true;
        this.error = default;
    }

    public ValueResult(System.Exception error)
    {
        this.IsOk = false;
        this.error = error;
    }

#pragma warning disable SA1129
    public static ValueResult Default { get; } = new ValueResult();

    public bool IsOk { get; }

    public bool IsError => !this.IsOk;

    public System.Exception Error
    {
        get
        {
            if (!this.IsOk)
                return this.error!;

#pragma warning disable S2372
            throw new ResultException("No error present");
        }
    }

    object IResult.Error => this.Error;

    public static implicit operator Exception(ValueResult valueResult)
        => valueResult.Error;

    public static implicit operator ValueResult(System.Exception error)
        => new(error);

    public static implicit operator Task<ValueResult>(ValueResult valueResult)
        => Task.FromResult(valueResult);

    public static implicit operator ValueTask<ValueResult>(ValueResult valueResult)
        => new(valueResult);

    public static implicit operator ValueResult<Never, Exception>(ValueResult valueResult)
        => valueResult.IsOk ? new(Never.Value, default, true) : new(default, valueResult.Error, false);

    public static bool operator ==(ValueResult left, ValueResult right)
        => left.Equals(right);

    public static bool operator !=(ValueResult left, ValueResult right)
        => !left.Equals(right);

    public static ValueResult OkRef()
        => Default;

    public static ValueResult<TValue> OkRef<TValue>(TValue value)
        where TValue : notnull
        => new(value);

    public static ValueResult<TValue, TError> OkRef<TValue, TError>(TValue value)
        where TValue : notnull
        where TError : notnull
        => new(value, default, true);

    public static ValueResult FailRef(System.Exception error)
        => new(error);

    public static ValueResult<TValue> FailRef<TValue>(System.Exception error)
        where TValue : notnull
        => new(error);

    public static ValueResult<TValue, TError> FailRef<TValue, TError>(TError error)
        where TValue : notnull
        where TError : notnull
        => new(default, error, false);

    public static ValueResult TryCatchRef(Action action)
    {
        try
        {
            action();
            return ValueResult.Default;
        }
        catch (System.Exception ex)
        {
            return new ValueResult(ex);
        }
    }

    public static ValueResult<TValue> TryCatchRef<TValue>(Func<TValue> func)
        where TValue : notnull
    {
        try
        {
            return new ValueResult<TValue>(func());
        }
        catch (System.Exception ex)
        {
            return new ValueResult<TValue>(ex);
        }
    }

    public static ValueResult<TValue, TError> TryCatchRef<TValue, TError>(Func<TValue> func, Func<System.Exception, TError> errorFactory)
        where TValue : notnull
        where TError : notnull
    {
        try
        {
            return new ValueResult<TValue, TError>(func(), default, true);
        }
        catch (System.Exception ex)
        {
            return new ValueResult<TValue, TError>(default, errorFactory(ex), false);
        }
    }

    public static async ValueTask<ValueResult> TryCatchRefAsync(Func<Task> action)
    {
        try
        {
            await action();
            return Default;
        }
        catch (System.Exception ex)
        {
            return new ValueResult(ex);
        }
    }

    public static async ValueTask<ValueResult<TValue>> TryCatchRefAsync<TValue>(Func<Task<TValue>> func)
        where TValue : notnull
    {
        try
        {
            return new ValueResult<TValue>(await func());
        }
        catch (System.Exception ex)
        {
            return new ValueResult<TValue>(ex);
        }
    }

    public static async ValueTask<ValueResult<TValue, TError>> TryCatchRefAsync<TValue, TError>(
        Func<Task<TValue>> func,
        Func<System.Exception, TError> errorFactory)
        where TValue : notnull
        where TError : notnull
    {
        try
        {
            return new ValueResult<TValue, TError>(await func(), default, true);
        }
        catch (System.Exception ex)
        {
            return new ValueResult<TValue, TError>(default, errorFactory(ex), false);
        }
    }

    public override int GetHashCode()
    {
        if (this.IsOk)
            return HashCode.Combine(this.IsOk);
        return this.error!.GetHashCode() ^ HashCode.Combine(this.IsError);
    }

    public override bool Equals(object? obj)
    {
        if (obj is null)
            return !this.IsOk;

        if (obj is Result other2)
            return this.Equals(other2);

        if (obj is IEmptyResult<Exception> other1)
            return this.Equals(other1);

        if (obj is IResult<Exception> other)
            return this.Equals(other);

        return false;
    }

    public bool Equals(IEmptyResult<Exception>? other)
    {
        if (other is null)
            return !this.IsOk;

        if (!this.IsOk)
            return !other.IsOk;

        return true;
    }

    public bool Equals(ValueResult other)
    {
        if (this.IsOk == other.IsOk)
            return true;

        if (this.IsError && other.IsError && this.error == other.error)
            return true;

        return false;
    }

    public ValueResult InspectError(Action<Exception> action)
    {
        if (!this.IsOk)
            action(this.error!);

        return this;
    }

    bool IResult.TryGetError(out object? error)
    {
        var res = this.TryGetError(out var e);
        error = e;
        return res;
    }

    public bool TryGetError(out System.Exception? error)
    {
        error = this.error;
        return !this.IsOk;
    }
}