namespace FrostYeti.Exec;

public abstract class CommandArgsBuilder : ICommandArgsBuilder
{
    public abstract string[] SubCommands { get; }

    public static implicit operator CommandArgs(CommandArgsBuilder builder)
    {
        return builder.Build();
    }

    public abstract CommandArgs Build();
}