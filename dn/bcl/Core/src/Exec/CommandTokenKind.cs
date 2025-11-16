namespace FrostYeti.Exec;

public enum CommandTokenKind
{
    Invalid = 0,
    Arg,
    SingleQuotedArg,
    DoubleQuotedArg,
    SubProcessStart,
    SubProcessEnd,
    And,
    Or,
    Pipe,
    StatementEnd,
    ClosureStart,
    ClosureEnd,
}