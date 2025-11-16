using System.Buffers;

namespace FrostYeti;

public static partial class Shell
{
    public static partial class Fs
    {
        public static void Tee(string content, string file)
            => Tee(content, Console.Out, [file], append: false);

        public static void Tee(ReadOnlySpan<char> content, string file)
            => Tee(content, Console.Out, [file], append: false);

        public static void Tee(ReadOnlySpan<byte> bytes, string file)
            => Tee(bytes, [file], append: false);

        public static void Tee(TextReader reader, string file)
            => Tee(reader, Console.Out, [file], append: false);

        public static void Tee(string content, string file, bool append)
            => Tee(new StringReader(content), Console.Out, file, append);

        public static void Tee(string content, IEnumerable<string> files, bool append)
            => Tee(new StringReader(content), Console.Out, files, append);

        public static void Tee(ReadOnlySpan<char> content, string file, bool append)
            => Tee(content, Console.Out, [file], append);

        public static void Tee(ReadOnlySpan<char> content, IEnumerable<string> files, bool append)
            => Tee(content, Console.Out, files, append);

        public static void Tee(ReadOnlySpan<byte> bytes, string file, bool append)
        => Tee(bytes, [file], append);

        public static void Tee(ReadOnlySpan<byte> bytes, IEnumerable<string> files, bool append)
        {
            try
            {
                var stream = Console.OpenStandardOutput();
                using var writer = new StreamWriter(stream, null, 1024, true);
                Tee(bytes, writer, files, append);
                stream.Flush();
            }
            finally
            {
                var standardOutput = new StreamWriter(Console.OpenStandardOutput(), null, 1024, true);
                standardOutput.AutoFlush = true;
                Console.SetOut(standardOutput);
            }
        }

        public static void Tee(TextReader reader, string file, bool append)
            => Tee(reader, Console.Out, [file], append);

        public static void Tee(TextReader reader, IEnumerable<string> files, bool append)
            => Tee(reader, Console.Out, files, append);

        public static void Tee(string content, TextWriter writer, string file, bool append)
            => Tee(new StringReader(content), writer, file, append);

        public static void Tee(string content, TextWriter writer, IEnumerable<string> file, bool append)
            => Tee(new StringReader(content), writer, file, append);

        public static void Tee(ReadOnlySpan<char> content, TextWriter writer, string file, bool append)
            => Tee(content, writer, [file], append);

        public static void Tee(ReadOnlySpan<char> content, TextWriter writer, IEnumerable<string> file, bool append)
        {
            if (writer is null)
                throw new ArgumentNullException(nameof(writer), "Writer cannot be null.");
            if (file is null)
                throw new ArgumentNullException(nameof(file), "Files cannot be null.");

            foreach (var f in file)
            {
                if (f.IsNullOrWhiteSpace())
                    throw new ArgumentException("File path cannot be null or empty.", nameof(file));

                var expandedPath = Env.Expand(f);
                if (expandedPath.IsNullOrWhiteSpace())
                    throw new ArgumentException("Expanded file path cannot be null or empty.", nameof(file));
                try
                {
                    using var fileWriter = new StreamWriter(expandedPath, append);
                    writer.Write(content);
                    writer.Flush();
                    fileWriter.Write(content);
                    fileWriter.Flush();
                }
                catch (Exception ex)
                {
                    throw new IOException($"Failed to write to file '{expandedPath}'.", ex);
                }
            }
        }

        public static void Tee(ReadOnlySpan<byte> content, StreamWriter writer, string file, bool append)
            => Tee(content, writer, [file], append);

        public static void Tee(ReadOnlySpan<byte> content, StreamWriter writer, IEnumerable<string> file, bool append)
        {
            if (writer is null)
                throw new ArgumentNullException(nameof(writer), "Writer cannot be null.");
            if (file is null)
                throw new ArgumentNullException(nameof(file), "Files cannot be null.");

            var rented = ArrayPool<byte>.Shared.Rent(content.Length);
            content.CopyTo(rented);

            try
            {
                foreach (var f in file)
                {
                    if (f.IsNullOrWhiteSpace())
                        throw new ArgumentException("File path cannot be null or empty.", nameof(file));

                    var expandedPath = Env.Expand(f);
                    if (expandedPath.IsNullOrWhiteSpace())
                        throw new ArgumentException("Expanded file path cannot be null or empty.", nameof(file));
                    try
                    {
                        using var fileWriter = new StreamWriter(expandedPath, append);
                        writer.BaseStream.Write(rented, 0, rented.Length);
                        writer.Flush();
                        fileWriter.BaseStream.Write(rented, 0, rented.Length);
                        fileWriter.Flush();
                    }
                    catch (Exception ex)
                    {
                        throw new IOException($"Failed to write to file '{expandedPath}'.", ex);
                    }
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(rented);
            }
        }

        public static void Tee(TextReader reader, TextWriter writer, string file, bool append)
        {
            if (reader is null)
                throw new ArgumentNullException(nameof(reader), "Reader cannot be null.");
            if (writer is null)
                throw new ArgumentNullException(nameof(writer), "Writer cannot be null.");
            if (file.IsNullOrWhiteSpace())
                throw new ArgumentException("File path cannot be null or empty.", nameof(file));

            var expandedPath = Env.Expand(file);
            using var fileWriter = new StreamWriter(expandedPath, append);
            string? line;
            while ((line = reader.ReadLine()) is not null)
            {
                writer.WriteLine(line);
                fileWriter.WriteLine(line);
            }
        }

        public static void Tee(TextReader reader, TextWriter writer, IEnumerable<string> files, bool append)
        {
            if (reader is null)
                throw new ArgumentNullException(nameof(reader), "Reader cannot be null.");
            if (writer is null)
                throw new ArgumentNullException(nameof(writer), "Writer cannot be null.");
            if (files is null)
                throw new ArgumentNullException(nameof(files), "Files cannot be null.");

            foreach (var file in files)
            {
                if (file.IsNullOrWhiteSpace())
                    throw new ArgumentException("File path cannot be null or empty.", nameof(files));

                var expandedPath = Env.Expand(file);
                using var fileWriter = new StreamWriter(expandedPath, append);
                string? line;
                while ((line = reader.ReadLine()) is not null)
                {
                    writer.WriteLine(line);
                    fileWriter.WriteLine(line);
                }
            }
        }
    }
}