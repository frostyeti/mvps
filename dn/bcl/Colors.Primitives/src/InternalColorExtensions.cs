using System.Runtime.CompilerServices;

namespace FrostYeti.Colors;

internal static class InternalColorExtensions
{
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static string AsString(this ReadOnlySpan<char> value)
#if NETLEGACY
        => new(value.ToArray());
#else
        => new(value);
#endif
}