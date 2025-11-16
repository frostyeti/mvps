using System.Text;

namespace FrostYeti.Extras;

public static class StringBuilderExtensions
{

#if NETLEGACY
    public static void CopyTo(this StringBuilder builder, int sourceIndex, Span<char> span, int count)
    {
        if (sourceIndex + count > builder.Length)
        {
            throw new ArgumentOutOfRangeException(
                nameof(count),
                "Count must be less than or equal to the length of the string builder.");
        }

        if (count > span.Length)
        {
            throw new ArgumentOutOfRangeException(
                nameof(count),
                "Count must be less than or equal to the length of the span.");
        }

        var set = new char[count];
        builder.CopyTo(
            sourceIndex,
            set,
            0,
            count);
        set.CopyTo(span);
    }
#endif

    /// <summary>
    /// Copies the characters from a specified segment of this instance to a specified segment of a destination <see cref="Span{T}"/>.
    /// </summary>
    /// <param name="builder">The string builder.</param>
    /// <param name="span">The span to copy values into.</param>
    /// <param name="count">The number of characters to copy.</param>
    public static void CopyTo(this StringBuilder builder, Span<char> span, int count)
    {
        builder.CopyTo(0, span, count);
    }

    /// <summary>
    /// Copies the characters from a specified segment of this instance to a specified segment of a destination <see cref="Span{T}"/>.
    /// </summary>
    /// <param name="builder">The string builder.</param>
    /// <param name="span">The span to copy all the characters into.</param>
    public static void CopyTo(this StringBuilder builder, Span<char> span)
    {
        builder.CopyTo(0, span, span.Length);
    }

    /// <summary>
    ///    Converts the value of a <see cref="StringBuilder" /> to a <see cref="char" /> array.
    /// </summary>
    /// <param name="builder">The string builder.</param>
    /// <returns>An array with all the characters of the string builder.</returns>
    /// <exception cref="ArgumentNullException">Thrown when builder is null.</exception>
    public static char[] ToArray(this StringBuilder builder)
    {
        if (builder is null)
            throw new ArgumentNullException(nameof(builder));

        var set = new char[builder.Length];
        builder.CopyTo(
            0,
            set,
            0,
            set.Length);
        return set;
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

    /// <summary>
    /// Returns a span of the characters in the string builder.
    /// </summary>
    /// <param name="builder">The string builder.</param>
    /// <returns>A readonly span of characters.</returns>
    public static ReadOnlySpan<char> AsReadOnlySpan(this StringBuilder builder)
    {
        var set = new char[builder.Length];
        builder.CopyTo(
            0,
            set,
            0,
            set.Length);

        return new ReadOnlySpan<char>(set);
    }
}