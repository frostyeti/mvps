namespace FrostYeti.Collections.Generic;

public class StringList : List<string>
{
    public StringList()
    {
    }

    public StringList(int capacity)
        : base(capacity)
    {
    }

    public StringList(IEnumerable<string> collection)
        : base(collection)
    {
    }

    public StringList(System.Collections.Specialized.StringCollection collection)
        : this(collection.GetEnumerator())
    {
    }

    public StringList(System.Collections.Specialized.StringEnumerator enumerator)
        : base()
    {
        while (enumerator.MoveNext())
        {
            if (enumerator.Current == null)
                continue;
            this.Add(enumerator.Current);
        }
    }

    public int IndexOfFold(string item)
    {
        return this.FindIndex(x => string.Equals(x, item, StringComparison.OrdinalIgnoreCase));
    }

    public bool ContainsFold(string item)
    {
        return this.IndexOfFold(item) >= 0;
    }
}