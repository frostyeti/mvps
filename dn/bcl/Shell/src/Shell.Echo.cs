using FrostYeti.Exec;

namespace FrostYeti;

public static partial class Shell
{
    public static void Echo(bool value)
         => Console.WriteLine(value);

    public static void Echo(char[] value, int index = 0, int count = -1)
    {
        if (count < 0)
        {
            count = value.Length - index;
        }

        if (index < 0 || index + count > value.Length)
        {
            throw new ArgumentOutOfRangeException(nameof(index), "Index and count must refer to a location within the array.");
        }

        Console.WriteLine(value, index, count);
    }

    public static void Echo(decimal value)
        => Console.WriteLine(value);

    public static void Echo(double value)
        => Console.WriteLine(value);

    public static void Echo(float value)
        => Console.WriteLine(value);

    public static void Echo(string value)
        => Console.WriteLine(value);

    public static void Echo(object? value)
        => Console.WriteLine(value);

    public static void Echo(short value)
        => Console.WriteLine(value);

    public static void Echo(int value)
        => Console.WriteLine(value);

    public static void Echo(long value)
        => Console.WriteLine(value);

    public static void Echo(string format, params object?[] args)
        => Console.WriteLine(format, args);

    public static void Echo(string template, object? arg0)
        => Console.WriteLine(template, arg0);

    public static void Echo(string template, object? arg0, object? arg1)
        => Console.WriteLine(template, arg0, arg1);

    public static void Echo(string template, object? arg0, object? arg1, object? arg2)
        => Console.WriteLine(template, arg0, arg1, arg2);

    public static void Print(string? value)
        => Console.Write(value);

    public static void Print(string format, params object?[] args)
        => Console.Write(format, args);

    public static void Print(string template, object? arg0)
        => Console.Write(template, arg0);

    public static void Print(string template, object? arg0, object? arg1)
        => Console.Write(template, arg0, arg1);

    public static void Print(string template, object? arg0, object? arg1, object? arg2)
        => Console.Write(template, arg0, arg1, arg2);

    public static void Print(bool value)
        => Console.Write(value);

    public static void Print(char value)
        => Console.Write(value);

    public static void Print(char[] value, int index = 0, int count = -1)
    {
        if (count < 0)
        {
            count = value.Length - index;
        }

        if (index < 0 || index + count > value.Length)
        {
            throw new ArgumentOutOfRangeException(nameof(index), "Index and count must refer to a location within the array.");
        }

        Console.Write(value, index, count);
    }

    public static void Print(decimal value)
        => Console.Write(value);

    public static void Print(double value)
        => Console.Write(value);

    public static void Print(float value)
        => Console.Write(value);

#if NET10_0_OR_GREATER
    public static void Print(ReadOnlySpan<char> value)
        => Console.Write(value);

#else
    public static void Print(ReadOnlySpan<char> value)
    {
        var rented = System.Buffers.ArrayPool<char>.Shared.Rent(value.Length);
        try
        {
            value.CopyTo(rented);
            Console.Write(rented, 0, value.Length);
        }
        finally
        {
            System.Buffers.ArrayPool<char>.Shared.Return(rented);
        }
    }
#endif

    public static void Print(short value)
         => Console.Write(value);

    public static void Print(int value)
        => Console.Write(value);

    public static void Print(long value)
        => Console.Write(value);

    public static void Print(object? value)
        => Console.Write(value);
}