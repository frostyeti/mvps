namespace FrostYeti;

public class Observer<T>
{
    private readonly Action<T>? onNext;
    private readonly Action<Exception>? onError;
    private readonly Action? onCompleted;

    public Observer(Action<T>? onNext, Action<Exception>? onError, Action? onCompleted)
    {
        this.onNext = onNext;
        this.onError = onError;
        this.onCompleted = onCompleted;
    }

    public static Observer<T> Create(
        Action<T>? onNext = null,
        Action<Exception>? onError = null,
        Action? onCompleted = null)
        => new(onNext, onError, onCompleted);

    public void OnNext(T value)
        => this.onNext?.Invoke(value);

    public void OnError(Exception error)
        => this.onError?.Invoke(error);

    public void OnCompleted()
        => this.onCompleted?.Invoke();
}