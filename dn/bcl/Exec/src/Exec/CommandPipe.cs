namespace FrostYeti.Exec;

public class CommandPipe
{
    public List<CommandOptions> Commands { get; set; } = [];

    public bool CanRun => this.Commands.Count > 1;

    public CommandPipe Pipe(CommandOptions command)
    {
        this.Commands.Add(command);
        return this;
    }

    public CommandPipe Pipe(CommandArgs args)
    {
        ArgumentOutOfRangeException.ThrowIfNullOrEmpty(args);
        var exe = args[0];
        args.RemoveAt(0);

        this.Commands.Add(new CommandOptions { Args = args, File = exe });
        return this;
    }

    public CommandPipe Pipe(ICommandOptionsOwner owner)
    {
        this.Commands.Add(owner.Options);
        return this;
    }

    public Output Run()
    {
        if (this.Commands.Count < 2)
        {
            throw new ProcessException("Pipe must have at least two commands");
        }

        var last = this.Commands.Count - 1;

        ChildProcess? lastProcess = null;
        for (var i = 0; i < this.Commands.Count; i++)
        {
            var command = this.Commands[i];
            if (i == 0)
            {
                command.Stdout = Stdio.Piped;
                command.Stderr = Stdio.Piped;
                lastProcess = new ChildProcess(command);
            }
            else if (i < last)
            {
                command.Stdout = Stdio.Piped;
                command.Stderr = Stdio.Piped;
                command.Stdin = Stdio.Piped;
                var currentProcess = new ChildProcess(command);
                lastProcess!.PipeTo(currentProcess);
                lastProcess.Wait();
                lastProcess.Dispose();
                lastProcess = currentProcess;
            }
            else
            {
                command.Stdin = Stdio.Piped;
                var currentProcess = new ChildProcess(command);
                lastProcess!.PipeTo(currentProcess);
                lastProcess.Wait();
                lastProcess.Dispose();
                lastProcess = currentProcess;
            }
        }

        return lastProcess!.WaitForOutput();
    }

    public async ValueTask<Output> RunAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (this.Commands.Count < 2)
        {
            throw new ProcessException("Pipe must have at least two commands");
        }

        var last = this.Commands.Count - 1;

        ChildProcess? lastProcess = null;
        for (var i = 0; i < this.Commands.Count; i++)
        {
            var command = this.Commands[i];
            cancellationToken.ThrowIfCancellationRequested();
            if (i == 0)
            {
                command.Stdout = Stdio.Piped;
                command.Stderr = Stdio.Piped;
                lastProcess = new ChildProcess(command);
            }
            else if (i < last)
            {
                command.Stdout = Stdio.Piped;
                command.Stderr = Stdio.Piped;
                command.Stdin = Stdio.Piped;
                var currentProcess = new ChildProcess(command);
                await lastProcess!.PipeToAsync(currentProcess, cancellationToken);
                await lastProcess.WaitAsync(cancellationToken);
                lastProcess.Dispose();
                lastProcess = currentProcess;
            }
            else
            {
                command.Stdin = Stdio.Piped;
                var currentProcess = new ChildProcess(command);
                await lastProcess!.PipeToAsync(currentProcess, cancellationToken);
                await lastProcess.WaitAsync(cancellationToken);
                lastProcess.Dispose();
                lastProcess = currentProcess;
            }
        }

        var output = await lastProcess!.WaitForOutputAsync(cancellationToken);
        lastProcess.Dispose();
        return output;
    }

    public Output Output()
    {
        if (this.CanRun)
        {
            var last = this.Commands[^1];
            last.Stdout = Stdio.Piped;
            last.Stderr = Stdio.Piped;
        }

        return this.Run();
    }

    public ValueTask<Output> OutputAsync(CancellationToken cancellationToken = default)
    {
        if (this.CanRun)
        {
            var last = this.Commands[^1];
            last.Stdout = Stdio.Piped;
            last.Stderr = Stdio.Piped;
        }

        return this.RunAsync(cancellationToken);
    }
}