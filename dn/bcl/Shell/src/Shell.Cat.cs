namespace FrostYeti;

public static partial class Shell
{
    public static partial class Fs
    {
        public static void Cat(string path)
            => Cat(path, Console.Out);

        public static void Cat(IEnumerable<string> files)
            => Cat(files, Console.Out);

        public static void Cat(string path, TextWriter writer)
        {
            if (path.IsNullOrWhiteSpace())
                throw new ArgumentException("Path cannot be null or whitespace.", nameof(path));

            path = ResolvePath(path);

            if (!File.Exists(path))
            {
                throw new FileNotFoundException($"The file '{path}' does not exist.", path);
            }

            using var reader = new StreamReader(path);
            string? line;
            while ((line = reader.ReadLine()) != null)
            {
                writer.WriteLine(line);
            }
        }

        public static void Cat(IEnumerable<string> paths, TextWriter writer)
        {
            foreach (var target in paths)
            {
                if (target.IsNullOrWhiteSpace())
                    throw new ArgumentException("Path cannot be null or whitespace.", nameof(paths));

                var path = ResolvePath(target);

                if (!File.Exists(path))
                {
                    throw new FileNotFoundException($"The file '{path}' does not exist.", path);
                }

                using var reader = new StreamReader(path);
                string? line;
                while ((line = reader.ReadLine()) != null)
                {
                    writer.WriteLine(line);
                }
            }
        }
    }
}