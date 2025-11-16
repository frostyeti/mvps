using System.Buffers;
using System.Text;

using FrostYeti.Text;

namespace FrostYeti.Exec;

internal static class IOExtensions
{
    public static bool IsInputIOException(this Exception ex)
    {
        if (ex is AggregateException aggregateException)
            return aggregateException.InnerExceptions.All(IsInputIOException);

        if (ex is IOException ioException)
        {
            // this occurs when a head-like process stops reading from the input before we're done writing to it
            // see http://stackoverflow.com/questions/24876580/how-to-distinguish-programmatically-between-different-ioexceptions/24877149#24877149
            // see http://msdn.microsoft.com/en-us/library/cc231199.aspx
            return unchecked((uint)ioException.HResult) == 0x8007006D;
        }

        return ex.InnerException != null && IsInputIOException(ex.InnerException);
    }

    public static void PipeTo(
        this TextReader reader,
        TextWriter writer,
        int bufferSize = -1)
    {
        if (reader is null)
            throw new ArgumentNullException(nameof(reader));

        if (writer is null)
            throw new ArgumentNullException(nameof(writer));

        if (bufferSize < 0)
            bufferSize = 4096;

        var buffer = ArrayPool<char>.Shared.Rent(bufferSize);
        try
        {
            int read;
            var span = new Span<char>(buffer);

            while ((read = reader.Read(span)) > 0)
            {
                writer.Write(span.Slice(0, read));
            }
        }
        catch (Exception ex)
        {
            if (!ex.IsInputIOException())
                throw;
        }
        finally
        {
            ArrayPool<char>.Shared.Return(buffer, true);
        }
    }

    public static void PipeTo(
        this TextReader reader,
        Stream stream,
        Encoding? encoding = null,
        int bufferSize = -1,
        bool leaveOpen = false)
    {
        if (reader is null)
            throw new ArgumentNullException(nameof(reader));

        if (stream is null)
            throw new ArgumentNullException(nameof(stream));

        if (bufferSize < 0)
            bufferSize = 4096;

        encoding ??= Encoding.UTF8NoBom;

        using var sw = new StreamWriter(stream, encoding, bufferSize, leaveOpen);
        reader.PipeTo(sw, bufferSize);
    }

    public static void PipeTo(
        this TextReader reader,
        FileInfo file,
        Encoding? encoding = null,
        int bufferSize = -1)
    {
        if (reader is null)
            throw new ArgumentNullException(nameof(reader));

        if (file is null)
            throw new ArgumentNullException(nameof(file));

        if (bufferSize < 0)
            bufferSize = 4096;

        encoding ??= Encoding.UTF8NoBom;
        using var stream = file.Open(FileMode.Create, FileAccess.Write, FileShare.Read);
        reader.PipeTo(stream, encoding, bufferSize, false);
    }

    public static void PipeTo(
        this TextReader reader,
        ICollection<string> lines)
    {
        if (reader is null)
        {
            throw new ArgumentNullException(nameof(reader));
        }

        if (lines is null)
        {
            throw new ArgumentNullException(nameof(lines));
        }

        try
        {
            while (reader.ReadLine() is { } line)
            {
                lines.Add(line);
            }
        }
        catch (Exception ex)
        {
            if (!ex.IsInputIOException())
                throw;
        }
    }

    public static Task PipeToAsync(
        this TextReader reader,
        FileInfo file,
        Encoding? encoding = null,
        int bufferSize = -1,
        CancellationToken cancellationToken = default)
    {
        if (reader is null)
            throw new ArgumentNullException(nameof(reader));

        if (file is null)
            throw new ArgumentNullException(nameof(file));

        if (bufferSize < 0)
            bufferSize = 4096;

        encoding ??= Encoding.UTF8NoBom;

        return InnerPipeToAsync(reader, file, encoding, bufferSize, cancellationToken);
    }

    public static Task PipeToAsync(
        this TextReader reader,
        ICollection<string> lines,
        CancellationToken cancellationToken = default)
    {
        if (reader is null)
        {
            throw new ArgumentNullException(nameof(reader));
        }

        if (lines is null)
        {
            throw new ArgumentNullException(nameof(lines));
        }

        return InnerPipeToAsync(reader, lines, cancellationToken);
    }

    public static Task PipeToAsync(
        this TextReader reader,
        TextWriter writer,
        int bufferSize = -1,
        CancellationToken cancellationToken = default)
    {
        if (reader is null)
            throw new ArgumentNullException(nameof(reader));

        if (writer is null)
            throw new ArgumentNullException(nameof(writer));

        if (bufferSize < 0)
            bufferSize = 4096;

        return InnerPipeToAsync(reader, writer, bufferSize, cancellationToken);
    }

    public static Task PipeToAsync(
        this TextReader reader,
        Stream stream,
        Encoding? encoding = null,
        int bufferSize = -1,
        bool leaveOpen = false,
        CancellationToken cancellationToken = default)
    {
        if (reader is null)
            throw new ArgumentNullException(nameof(reader));

        if (stream is null)
            throw new ArgumentNullException(nameof(stream));

        if (bufferSize < 0)
            bufferSize = 4096;

        encoding ??= Encoding.UTF8NoBom;

        return InnerPipeToAsync(reader, stream, encoding, bufferSize, leaveOpen, cancellationToken);
    }

    public static int Read(this TextReader reader, Span<char> chars)
    {
        var buffer = ArrayPool<char>.Shared.Rent(chars.Length);
        try
        {
            var read = reader.Read(buffer, 0, buffer.Length);
            if (read > 0)
                buffer.AsSpan(0, read).CopyTo(chars);

            return read;
        }
        finally
        {
            ArrayPool<char>.Shared.Return(buffer, true);
        }
    }

    public static Task<int> ReadAsync(this TextReader reader, Memory<char> chars, CancellationToken cancellationToken = default)
    {
        var buffer = ArrayPool<char>.Shared.Rent(chars.Length);
        try
        {
            var read = reader.Read(buffer, 0, chars.Length);
            if (read > 0)
                buffer.AsSpan(0, read).CopyTo(chars.Span);

            return Task.FromResult(read);
        }
        finally
        {
            ArrayPool<char>.Shared.Return(buffer, true);
        }
    }

    public static Task WriteAsync(this TextWriter writer, ReadOnlyMemory<char> chars, CancellationToken cancellationToken = default)
    {
        var buffer = ArrayPool<char>.Shared.Rent(chars.Length);
        try
        {
            chars.Span.CopyTo(buffer);
            return writer.WriteAsync(buffer, 0, chars.Length);
        }
        finally
        {
            ArrayPool<char>.Shared.Return(buffer, true);
        }
    }

    /// <summary>
    /// Writes the contents of the <paramref name="reader"/> to the <paramref name="writer"/>.
    /// </summary>
    /// <param name="writer">The text writer.</param>
    /// <param name="reader">The text reader to read from.</param>
    /// <param name="bufferSize">The size of the buffer to use. Defaults to 4096.</param>
    /// <exception cref="ArgumentNullException">Thrown when the writer or reader is null.</exception>
    public static void Write(this TextWriter writer, TextReader reader, int bufferSize = -1)
    {
        if (writer is null)
            throw new ArgumentNullException(nameof(writer));

        if (reader is null)
            throw new ArgumentNullException(nameof(reader));

        if (bufferSize < 0)
            bufferSize = 4096;

        var buffer = ArrayPool<char>.Shared.Rent(bufferSize);
        try
        {
            var span = new Span<char>(buffer);
            int read;
            while ((read = reader.Read(span)) > 0)
            {
                writer.Write(span.Slice(0, read));
            }
        }
        catch (Exception ex)
        {
            if (!ex.IsInputIOException())
                throw;
        }
        finally
        {
            ArrayPool<char>.Shared.Return(buffer, true);
        }
    }

    /// <summary>
    ///  Writes the contents of the <paramref name="stream"/> to the <paramref name="writer"/>. The the method will close
    /// the stream unless <paramref name="leaveOpen"/> is true.
    /// </summary>
    /// <param name="writer">The text writer.</param>
    /// <param name="stream">The stream to read from.</param>
    /// <param name="encoding">The encoding to use. Defaults to UTF8.</param>
    /// <param name="bufferSize">The size of the buffer to use. Defaults to 4096.</param>
    /// <param name="leaveOpen">Instructs to leave the stream open.</param>
    /// <exception cref="ArgumentNullException">Thrown when writer or stream is null.</exception>
    public static void Write(this TextWriter writer, Stream stream, Encoding? encoding = null, int bufferSize = -1, bool leaveOpen = false)
    {
        if (writer is null)
            throw new ArgumentNullException(nameof(writer));

        if (stream is null)
            throw new ArgumentNullException(nameof(stream));

        if (bufferSize < 0)
            bufferSize = 4096;

        encoding ??= Encoding.UTF8NoBom;

        using var reader = new StreamReader(stream, encoding, true, bufferSize, leaveOpen);
        writer.Write(reader, bufferSize);
    }

    /// <summary>
    /// Writes the contents of the file to the <paramref name="writer"/>.
    /// </summary>
    /// <param name="writer">The text writer.</param>
    /// <param name="file">The file to read from.</param>
    /// <param name="encoding">The encoding to use. Defaults to UTF8.</param>
    /// <param name="bufferSize">The size of the buffer to use. Defaults to 4096.</param>
    /// <exception cref="ArgumentNullException">Thrown when writer or file is null.</exception>
    public static void Write(this TextWriter writer, FileInfo file, Encoding? encoding = null, int bufferSize = -1)
    {
        if (writer is null)
            throw new ArgumentNullException(nameof(writer));

        if (file is null)
            throw new ArgumentNullException(nameof(file));

        if (bufferSize < 0)
            bufferSize = 4096;

        encoding ??= Encoding.UTF8NoBom;

        using var stream = file.OpenRead();
        using var reader = new StreamReader(stream, encoding, true, bufferSize, false);
        writer.Write(reader, bufferSize);
    }

    public static string ScreamingSnakeCase(this string value)
    {
        var builder = StringBuilderCache.Acquire();
        var previous = char.MinValue;
        foreach (var c in value)
        {
            if (char.IsUpper(c) && builder.Length > 0 && previous != '_')
            {
                builder.Append('_');
            }

            if (c is '-' or ' ' or '_')
            {
                builder.Append('_');
                previous = '_';
                continue;
            }

            if (!char.IsLetterOrDigit(c))
                continue;

            builder.Append(char.ToUpperInvariant(c));
            previous = c;
        }

        return StringBuilderCache.GetStringAndRelease(builder);
    }

    private static async Task InnerPipeToAsync(
        TextReader reader,
        TextWriter writer,
        int bufferSize,
        CancellationToken cancellationToken)
    {
        if (bufferSize < 0)
            bufferSize = 4096;

        char[] buffer = ArrayPool<char>.Shared.Rent(bufferSize);
        try
        {
            int read;
            var memory = new Memory<char>(buffer);

            if (cancellationToken.IsCancellationRequested)
                cancellationToken.ThrowIfCancellationRequested();

            while ((read = await reader.ReadAsync(memory, cancellationToken)) > 0)
            {
                await writer.WriteAsync(memory.Slice(0, read), cancellationToken);
            }
        }
        catch (Exception ex)
        {
            if (!ex.IsInputIOException())
                throw;
        }
        finally
        {
            ArrayPool<char>.Shared.Return(buffer, true);
        }
    }

    private static async Task InnerPipeToAsync(
        TextReader reader,
        Stream stream,
        Encoding? encoding = null,
        int bufferSize = -1,
        bool leaveOpen = false,
        CancellationToken cancellationToken = default)
    {
        if (bufferSize < 0)
            bufferSize = 4096;

        encoding ??= Encoding.UTF8NoBom;

#if NETLEGACY
        using var sw = new StreamWriter(stream, encoding, bufferSize, leaveOpen);
#else
        await using var sw = new StreamWriter(stream, encoding, bufferSize, leaveOpen);
#endif
        await reader.PipeToAsync(sw, bufferSize, cancellationToken);
    }

    private static async Task InnerPipeToAsync(
        TextReader reader,
        FileInfo file,
        Encoding? encoding,
        int bufferSize,
        CancellationToken cancellationToken)
    {
        if (bufferSize < 0)
            bufferSize = 4096;

        encoding ??= Encoding.UTF8NoBom;

#if NETLEGACY
        using var stream = file.Open(FileMode.Create, FileAccess.Write, FileShare.Read);
#else
        await using var stream = file.Open(FileMode.Create, FileAccess.Write, FileShare.Read);
#endif
        await reader.PipeToAsync(stream, encoding, bufferSize, false, cancellationToken);
    }

    private static async Task InnerPipeToAsync(
        TextReader reader,
        ICollection<string> lines,
        CancellationToken cancellationToken)
    {
        try
        {
#if !NET7_0_OR_GREATER
            while (await reader.ReadLineAsync().ConfigureAwait(false) is { } line)
            {
                lines.Add(line);
            }
#else
            while (await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false) is { } line)
            {
                lines.Add(line);
            }
#endif
        }
        catch (Exception ex)
        {
            if (!ex.IsInputIOException())
                throw;
        }
    }
}