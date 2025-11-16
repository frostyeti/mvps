namespace FrostYeti.Exec;

public class PathHint
{
    public PathHint(string name)
    {
        this.Name = name;
    }

    public string Name { get; }

    public string? Executable { get; set; }

    public string? Variable { get; set; }

    public string? CachedPath { get; set; }

    /// <summary>
    /// Gets or sets the paths to search in for Windows.
    /// </summary>
    public HashSet<string> Windows { get; set; } = new();

    public HashSet<string> Linux { get; set; } = new();

    public HashSet<string> Darwin { get; set; } = new();
}