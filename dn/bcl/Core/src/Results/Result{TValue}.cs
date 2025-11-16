// ReSharper disable ParameterHidesMember
namespace FrostYeti.Results;

public class Result<TValue> : IValueResult<TValue, Exception>,
    IEquatable<Result<TValue>>
    where TValue : notnull
{
    private readonly TValue? value;

    private readonly Exception? error;

    public Result()
    {
        this.value = default;
        this.IsOk = this.value is not null;
        if (this.IsError)
            this.error = new ResultException("No value present");
    }

    public Result(TValue value)
    {
        this.IsOk = true;
        this.value = value;
        this.error = default;
    }

    public Result(Exception error)
    {
        this.IsOk = false;
        this.value = default;
        this.error = error;
    }

    public bool IsOk { get; }

    public bool IsError => !this.IsOk;

    public TValue Value
    {
        get
        {
            if (this.IsOk)
                return this.value!;

#pragma warning disable S2372
            throw new ResultException("No value present");
        }
    }

    public Exception Error
    {
        get
        {
            if (!this.IsOk)
                return this.error!;

#pragma warning disable S2372
            throw new ResultException("No error present");
        }
    }

    object IValueResult.Value => this.Value;

    object IResult.Error => this.Error;

    public static implicit operator TValue(Result<TValue> result)
        => result.Value;

    public static implicit operator Exception(Result<TValue> result)
        => result.Error;

    public static implicit operator Result<TValue>(TValue value)
        => new(value);

    public static implicit operator Result<TValue>(Exception error)
        => new(error);

    public static implicit operator Task<Result<TValue>>(Result<TValue> result)
        => Task.FromResult(result);

    public static implicit operator ValueTask<Result<TValue>>(Result<TValue> result)
        => new(result);

    public static implicit operator Result<TValue, Exception>(Result<TValue> result)
        => result.IsOk ? new(result.Value, default, true) : new(default, result.Error, false);

    public static implicit operator Result<TValue>(Result<TValue, Exception> result)
        => result.IsOk ? new(result.Value) : new(result.Error);

    public static bool operator ==(Result<TValue> left, Result<TValue> right)
        => left.Equals(right);

    public static bool operator !=(Result<TValue> left, Result<TValue> right)
        => !left.Equals(right);

    public override int GetHashCode()
        => HashCode.Combine(
            this.IsOk,
            this.value,
            this.error);

    public override bool Equals(object? obj)
    {
        if (obj is null)
            return !this.IsOk;

        if (obj is Result<TValue, Exception> other2)
            return this.Equals(other2);

        if (obj is IValueResult<TValue, Exception> other)
            return this.Equals(other);

        return false;
    }

    public bool Equals(IValueResult<TValue, Exception>? other)
    {
        if (other is null)
            return !this.IsOk;

        if (!this.IsOk)
            return !other.IsOk;

        return this.value!.Equals(other.Value);
    }

    public bool Equals(Result<TValue>? other)
    {
        if (other is null)
            return false;

        if (this.IsOk != other.IsOk)
            return false;

        if (this.IsOk)
            return this.value!.Equals(other.value);

        return this.error!.Equals(other.error);
    }

    public Result<TValue> Inspect(Action<TValue> action)
    {
        if (this.IsOk)
            action(this.value!);

        return this;
    }

    public Result<TValue> InspectError(Action<Exception> action)
    {
        if (!this.IsOk)
            action(this.error!);

        return this;
    }

    public bool IsOkAnd(Func<TValue, bool> predicate)
        => this.IsOk && predicate(this.value!);

    public bool IsErrorAnd(Func<Exception, bool> predicate)
        => this.IsError && predicate(this.error!);

    public Result<TOther> Map<TOther>(Func<TValue, TOther> func)
        where TOther : notnull
        => this.IsOk ? new(func(this.value!)) : new(this.error!);

    public Result<TOther, TOtherError> Map<TOther, TOtherError>(Func<TValue, TOther> map, Func<Exception, TOtherError> mapError)
        where TOther : notnull
        where TOtherError : notnull
        => this.IsOk ? new(map(this.value!), default, true) : new(default, mapError(this.error!), false);

    public Result<TValue> Or(TValue other)
        => this.IsOk ? this : new(other);

    public Result<TValue> Or(Func<TValue> other)
        => this.IsOk ? this : new(other());

    public TValue OrDefault(TValue defaultValue)
        => this.IsOk ? this.value! : defaultValue;

    public TValue OrDefault(Func<TValue> defaultValue)
        => this.IsOk ? this.value! : defaultValue();

    public Result<TValue> OrError(Exception error)
        => this.IsError ? this : new(error);

    public Result<TValue> OrError(Func<Exception> error)
        => this.IsError ? this : new(error());

    public Exception OrErrorDefault(Exception defaultError)
        => this.IsError ? this.error! : defaultError;

    public Exception OrErrorDefault(Func<Exception> defaultError)
        => this.IsError ? this.error! : defaultError();

    bool IValueResult.TryGetValue(out object? value)
    {
        var res = this.TryGetValue(out var v);
        value = v;
        return res;
    }

    bool IResult.TryGetError(out object? error)
    {
        var res = this.TryGetError(out var e);
        error = e;
        return res;
    }

    public bool TryGetValue(out TValue? value)
    {
        value = this.value;
        return this.IsOk;
    }

    public bool TryGetError(out Exception? error)
    {
        error = this.error;
        return this.IsError;
    }
}