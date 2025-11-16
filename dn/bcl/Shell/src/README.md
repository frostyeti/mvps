# FrostYeti.Shell

## Overview

Shell makes it easier to use functionality in .NET single file apps similar to what
you would find in a shell script such as common posix file system utilities, echo,
print, running commands, and more.

## Usage

```csharp
using FrostYeti.Shell;

Echo("hello");

Run("git status");

Command("dotnet --version")
    .WithCwd("/home/user/repos")
    .Run();

if (IsProcessElevated)
    Fs.Chown("/home/user/file", "root", "root");

MakeDir("/opt/test");

Bash("echo 'Hello from Bash'");

Pushd("/opt/test");

Console.WriteLine(Cwd());

Popd()

Console.WriteLine(Cwd());

Console.WriteLine(ResolvePath("~/.config"));

Console.WriteLine(Which("dotnet"));
```
