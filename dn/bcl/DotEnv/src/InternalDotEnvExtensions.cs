using System.Text;

namespace FrostYeti.DotEnv;

public static class InternalDotEnvExtensions
{
    public static char[] ToArray(this StringBuilder builder)
    {
        var copy = new char[builder.Length];
        builder.CopyTo(0, copy, 0, builder.Length);
        return copy;
    }

    public static string AsString(this ReadOnlySpan<char> span)
    {
#if NET5_0_OR_GREATER
        return span.ToString();
#else
        return new string(span.ToArray());
#endif
    }

    /// <summary>
    /// Returns a span of the characters in the string builder.
    /// </summary>
    /// <param name="builder">The string builder.</param>
    /// <returns>A span of characters.</returns>
    public static Span<char> AsSpan(this StringBuilder builder)
    {
        var set = new char[builder.Length];
        builder.CopyTo(
            0,
            set,
            0,
            set.Length);

        return new Span<char>(set);
    }
}