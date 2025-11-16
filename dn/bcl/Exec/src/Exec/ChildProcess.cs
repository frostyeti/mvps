using System.Diagnostics;
using System.Text;

namespace FrostYeti.Exec;

public sealed class ChildProcess : IDisposable
{
    private readonly Process process;

    private readonly int processId;

    private readonly List<IDisposable> disposables = new();

    private bool disposed;

    private DateTime exitTime;

    private byte[] stdout = Array.Empty<byte>();

    private byte[] stderr = Array.Empty<byte>();

    public ChildProcess(ProcessStartInfo startInfo)
    {
        if (startInfo == null)
            throw new ArgumentNullException(nameof(startInfo));

        this.process = new Process { StartInfo = startInfo };
        Command.GlobalWriteCommand?.Invoke(this.process.StartInfo);
        this.process.Start();
        this.processId = this.process.Id;
        this.exitTime = DateTime.MinValue;

        try
        {
            this.StartTime = this.process.StartTime;
        }
        catch (Exception e)
        {
            this.StartTime = DateTime.Now;
            Debug.WriteLine(e);
        }

        this.processId = this.process.Id;
    }

    public ChildProcess(Process process)
    {
        this.process = process ?? throw new ArgumentNullException(nameof(process));
        if (this.process.HasExited)
            throw new InvalidOperationException("Cannot create a ChildProcess from an already exited process.");

        this.processId = this.process.Id;
        this.exitTime = DateTime.MinValue;
        Command.GlobalWriteCommand?.Invoke(this.process.StartInfo);
        if (this.process.Threads.Count == 0)
            this.process.Start();

        try
        {
            this.StartTime = this.process.StartTime;
        }
        catch (Exception e)
        {
            this.StartTime = DateTime.Now;
            Debug.WriteLine(e);
        }

        this.processId = this.process.Id;
    }

    internal ChildProcess(CommandOptions options)
    {
        this.process = new Process();
        options.ToStartInfo(this.process.StartInfo);

        var cmd = options.WriteCommand ?? Command.GlobalWriteCommand;
        cmd?.Invoke(this.process.StartInfo);

        this.exitTime = DateTime.MinValue;
        this.process.Start();
        this.processId = this.process.Id;
        var now = DateTime.Now;
        try
        {
            this.StartTime = this.process.StartTime;
        }
        catch (Exception e)
        {
            this.StartTime = now;
            Debug.WriteLine(e);
        }

        this.processId = this.process.Id;
    }

    internal ChildProcess(ShellCommandOptions options)
    {
        this.process = new Process();
        options.ToStartInfo(this.process.StartInfo);

        var cmd = options.WriteCommand ?? Command.GlobalWriteCommand;
        cmd?.Invoke(this.process.StartInfo);

        this.exitTime = DateTime.MinValue;
        this.process.Start();
        this.processId = this.process.Id;
        var now = DateTime.Now;
        try
        {
            this.StartTime = this.process.StartTime;
        }
        catch (Exception e)
        {
            this.StartTime = now;
            Debug.WriteLine(e);
        }

        this.processId = this.process.Id;
    }

    ~ChildProcess()
    {
        this.Dispose();
    }

    public int Id => this.processId;

    public DateTime StartTime { get; }

    public DateTime ExitTime => this.exitTime;

    public Stream Stderr => this.process.StandardError.BaseStream;

    public StreamReader StderrReader => this.process.StandardError;

    public Stream Stdin => this.process.StandardInput.BaseStream;

    public StreamWriter StdinWriter => this.process.StandardInput;

    public Stream Stdout => this.process.StandardOutput.BaseStream;

    public StreamReader StdoutReader => this.process.StandardOutput;

    public bool IsStdoutRedirected => this.process.StartInfo.RedirectStandardOutput;

    public bool IsStdoutPiped { get; private set; }

    public bool IsStderrRedirected => this.process.StartInfo.RedirectStandardError;

    public bool IsStderrPiped { get; private set; }

    public bool IsStdinRedirected => this.process.StartInfo.RedirectStandardInput;

    public static implicit operator Process(ChildProcess child)
    {
        return child.process;
    }

    public ChildProcess AddDisposable(IDisposable disposable)
    {
        this.disposables.Add(disposable);
        return this;
    }

    public ChildProcess AddDisposables(IEnumerable<IDisposable> disposables)
    {
        this.disposables.AddRange(disposables);
        return this;
    }

    public void Dispose()
    {
        if (this.disposed)
            return;

        this.disposed = true;
        GC.SuppressFinalize(this);
        this.process.Dispose();
        if (this.disposables.Count == 0)
            return;

        foreach (var disposable in this.disposables)
        {
            disposable.Dispose();
        }
    }

    public void Kill()
    {
        this.process.Kill();
    }

    public void PipeTo(Stream stream)
    {
        this.GuardPiped();
        this.process.StandardOutput.BaseStream.CopyTo(stream);
    }

    public void PipeTo(TextWriter writer)
    {
        this.GuardPiped();
        this.process.StandardOutput.PipeTo(writer);
    }

    public void PipeTo(ICollection<string> lines)
    {
        this.GuardPiped();
        this.process.StandardOutput.PipeTo(lines);
    }

    public void PipeTo(FileInfo file)
    {
        this.GuardPiped();
        this.process.StandardOutput.PipeTo(file);
    }

    public void PipeTo(ChildProcess child)
    {
        this.GuardPiped();

        if (!child.IsStdinRedirected)
            throw new InvalidOperationException("Cannot pipe to child proccess' input when child process input is not redirected.");

        this.process.StandardOutput.BaseStream.CopyTo(child.process.StandardInput.BaseStream);
        child.process.StandardInput.BaseStream.Close();
    }

    public Task PipeToAsync(Stream stream, int bufferSize = -1, CancellationToken cancellationToken = default)
    {
        this.GuardPiped();

        if (bufferSize < 1)
            bufferSize = 4096;

        return this.process.StandardOutput.BaseStream.CopyToAsync(stream, bufferSize, cancellationToken);
    }

    public Task PipeToAsync(TextWriter writer, int bufferSize = -1, CancellationToken cancellationToken = default)
    {
        this.GuardPiped();
        return this.process.StandardOutput.PipeToAsync(writer, bufferSize, cancellationToken);
    }

    public Task PipeToAsync(ICollection<string> lines, CancellationToken cancellationToken = default)
    {
        this.GuardPiped();
        return this.process.StandardOutput.PipeToAsync(lines, cancellationToken: cancellationToken);
    }

    public Task PipeToAsync(FileInfo file, Encoding? encoding, int bufferSize = -1, CancellationToken cancellationToken = default)
    {
        this.GuardPiped();
        return this.process.StandardOutput.PipeToAsync(file, encoding, bufferSize, cancellationToken);
    }

    public async Task PipeToAsync(ChildProcess child, CancellationToken cancellationToken = default)
    {
        this.GuardPiped();

        if (!child.IsStdinRedirected)
            throw new InvalidOperationException("Cannot pipe to child's input when child input is not redirected.");

#if NETLEGACY
        await this.process.StandardOutput.BaseStream.CopyToAsync(child.process.StandardInput.BaseStream)
            .ConfigureAwait(false);
        child.process.StandardInput.BaseStream.Close();
#else
        await this.process.StandardOutput.BaseStream.CopyToAsync(child.process.StandardInput.BaseStream, cancellationToken)
            .ConfigureAwait(false);
        child.process.StandardInput.BaseStream.Close();
#endif
    }

    public void PipeErrorTo(Stream stream)
    {
        this.GuardErrorPiped();
        this.process.StandardError.BaseStream.CopyTo(stream);
    }

    public void PipeErrorTo(TextWriter writer)
    {
        this.GuardErrorPiped();
        this.process.StandardError.PipeTo(writer);
    }

    public void PipeErrorTo(ICollection<string> lines)
    {
        this.GuardErrorPiped();
        this.process.StandardError.PipeTo(lines);
    }

    public void PipeErrorTo(FileInfo file)
    {
        this.GuardErrorPiped();
        this.process.StandardError.PipeTo(file);
    }

    public void PipeFrom(ICollection<string> lines)
    {
        if (!this.IsStdinRedirected)
            throw new InvalidOperationException("Cannot pipe stdin from stream when input is not redirected.");

        this.process.StandardInput.Write(lines);
    }

    public void PipeFrom(FileInfo file)
    {
        if (!this.IsStdinRedirected)
            throw new InvalidOperationException("Cannot pipe stdin from stream when input is not redirected.");

        this.process.StandardInput.Write(file);
    }

    public void PipeFrom(Stream stream)
    {
        if (!this.IsStdinRedirected)
            throw new InvalidOperationException("Cannot pipe stdin from stream when input is not redirected.");

        this.process.StandardInput.Write(stream);
    }

    public void PipeFrom(TextReader reader)
    {
        if (!this.IsStdinRedirected)
            throw new InvalidOperationException("Cannot pipe stdin from stream when input is not redirected.");

        this.process.StandardInput.Write(reader);
    }

    public int Wait()
    {
        if (this.process.HasExited)
        {
            this.exitTime = this.process.ExitTime;
            return this.process.ExitCode;
        }

        this.process.WaitForExit();
        this.exitTime = this.process.ExitTime;
        return this.process.ExitCode;
    }

    public Output WaitForOutput()
    {
        try
        {
            if (this.IsStdoutRedirected && !this.IsStdoutPiped)
            {
                using var ms = new MemoryStream();
                this.process.StandardOutput.PipeTo(ms);
                ms.Flush();
                this.stdout = ms.ToArray();
            }

            if (this.IsStderrRedirected && !this.IsStderrPiped)
            {
                using var ms = new MemoryStream();
                this.process.StandardError.PipeTo(ms);
                ms.Flush();
                this.stderr = ms.ToArray();
            }

            if (this.process.HasExited)
            {
                this.exitTime = this.process.ExitTime;
            }
            else
            {
                this.process.WaitForExit();
                this.exitTime = this.process.ExitTime;
            }

            return new Output(
                this.process.StartInfo.FileName,
                this.process.ExitCode,
                this.stdout,
                this.stderr,
                this.StartTime,
                this.exitTime);
        }
        catch (Exception e)
        {
            this.exitTime = DateTime.Now;
            return new Output(
                this.process.StartInfo.FileName,
                -1,
                e,
                this.stdout,
                this.stderr,
                this.StartTime,
                this.exitTime);
        }
    }

    public async Task<int> WaitAsync(CancellationToken cancellationToken)
    {
        if (this.process.HasExited)
        {
            this.exitTime = this.process.ExitTime;
            return this.process.ExitCode;
        }

        await this.process.WaitForExitAsync(cancellationToken)
            .ConfigureAwait(false);
        return this.process.ExitCode;
    }

    public async ValueTask<Output> WaitForOutputAsync(CancellationToken cancellationToken)
    {
        try
        {
            if (this.IsStdoutRedirected && !this.IsStdoutPiped)
            {
                using var ms = new MemoryStream();
                await this.process.StandardOutput.PipeToAsync(ms, cancellationToken: cancellationToken)
                    .ConfigureAwait(false);
                await ms.FlushAsync(cancellationToken)
                    .ConfigureAwait(false);
                this.stdout = ms.ToArray();
            }

            if (this.IsStderrRedirected && !this.IsStderrPiped)
            {
                using var ms = new MemoryStream();
                await this.process.StandardError
                    .PipeToAsync(ms, cancellationToken: cancellationToken)
                    .ConfigureAwait(false);

                await ms.FlushAsync(cancellationToken)
                    .ConfigureAwait(false);
                this.stderr = ms.ToArray();
            }

            if (this.process.HasExited)
            {
                this.exitTime = this.process.ExitTime;
            }
            else
            {
                await this.process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
                this.exitTime = this.process.ExitTime;
            }

            return new Output(
                this.process.StartInfo.FileName,
                this.process.ExitCode,
                this.stdout,
                this.stderr,
                this.StartTime,
                this.exitTime);
        }
        catch (Exception e)
        {
            this.exitTime = DateTime.Now;
            return new Output(
                this.process.StartInfo.FileName,
                -1,
                e,
                this.stdout,
                this.stderr,
                this.StartTime,
                this.exitTime);
        }
    }

    private void GuardPiped()
    {
        if (this.IsStdoutPiped)
            throw new InvalidOperationException("Cannot pipe stdout. Stdout stream can only be read once.");

        if (!this.IsStdoutRedirected)
            throw new InvalidOperationException("Cannot pipe to stdout when stream is not redirected.");

        this.IsStdoutPiped = true;
    }

    private void GuardErrorPiped()
    {
        if (this.IsStderrPiped)
            throw new InvalidOperationException("Cannot pipe stderr. Stderr stream can only be read once.");

        if (!this.IsStderrRedirected)
            throw new InvalidOperationException("Cannot pipe to stderr when stream is not redirected.");

        this.IsStderrPiped = true;
    }
}