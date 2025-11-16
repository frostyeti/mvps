# FrostYeti.DotEnv Changelog

## 0.0.0-alpha.2

Moved variable expansion to new library and remove dependency
on FrostYeti.Core.

Change deserialize dictionary to return an `OrderedDictionary<string, string>`
instead of `Dictionary<string, string>`.

Enable better escaping for double quoted values including unicode
characters, new lines, vertical tabs, and carriage returns.

Improve value termination for unquoted single line values. Instead of
terminating the value when the first space is found, all characters
on a single line is captures until a line break or comment is found. Then
the variable value removes any trailing whitespace characters starting
from the end.

The value already trims leading whitespace characters, so this
change only affects the end of the value.

## 0.0.0-alpha.0

An implementation of dotenv for parsing and writing .env files.

This library can:

- expand environment variables such as `MYVAR=${HOME}/.config`
- perserves the order of the environment variables defined in the file.
- can parse and write comments.
- can load multiple files and expand the environment variables.
- can handle extra parsing features such as json, yaml, and bacticks.  
- avoids reflection to help with AOT scenarios.
