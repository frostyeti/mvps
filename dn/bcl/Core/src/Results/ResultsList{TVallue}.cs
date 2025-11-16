namespace FrostYeti.Results;

public class ResultsList<TValue>
    where TValue : notnull
{
    public ResultsList()
    {
        this.Results = new List<Result<TValue>>();
    }

    public ResultsList(int capacity)
    {
        this.Results = new List<Result<TValue>>(capacity);
    }

    public ResultsList(IEnumerable<Result<TValue>> results)
    {
        this.Results = results.ToList();
    }

    public ResultsList(IList<Result<TValue>> results)
    {
        this.Results = results ?? throw new ArgumentNullException(nameof(results));
    }

    public IList<Result<TValue>> Results { get; }

    public bool IsError => this.Results.Any(r => r.IsError);

    public bool IsOk => !this.IsError;

    public List<TValue> ToValues(bool throwOnError = true)
    {
        if (this.IsError && throwOnError)
            throw this.ToAggregateException();

        return this.Results
            .Where(r => r.IsOk)
            .Select(r => r.Value)
            .ToList();
    }

    public AggregateException ToAggregateException()
    {
        var errors = this.Results
            .Where(r => r.IsError)
            .Select(r => r.Error)
            .ToList();

        if (errors.Count == 0)
            return new AggregateException("No errors present in results list.");

        return new AggregateException(errors);
    }
}