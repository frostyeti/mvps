# FrostYeti.DotEnv

## Overview

Parse, read, and write dotenv (.env) files.

This library can:

- Perserve the order of the environment variables defined in the file.
- Parse and write comments.
- Load multiple files.
- Enables other multiline delimiters using {}, ---, or \`.
- Avoids reflection to help with AOT scenarios.

For variable expansion and command substitution use the
"FrostYeti.DotEnv.Expansion" library.

The Serializer converts to and from a new type called `DotEnvDocument` and
`OrderedDictionary<string,string>`.

## Usage

```csharp
using FrostYeti.DotEnv;


// load directly to environment variables
DotEnvLoader.Load(new DotEnvLoadOptions() {
    Files = ["./path/.env", "./path/prod.env"]
});

// parse multiple files and then load.
var doc3 = DotEnvLoader.Parse(new DotEnvLoadOptions() {
    Files = ["./path/.env", "./path/prod.env"]
});

// do something with values.
doc3["SOME_VAR"] = "test";

// then load to environment variables and 
// overwrite the existing ones.
DotEnvLoader.Load(doc3, true);

// use the serializer directly.
var doc = DotEnvSerializer.DeserializeDocument(
"""
# COMMENT
KEY=VALUE

MULTILINE=" my 
value
spans
multiple
lines"
single='single value'
""");

foreach(var node in doc) 
{
    if (node is DotEnvEmptyLine)
        Console.WriteLine("");

    if (node is DotEnvComment comment)
        Console.WriteLine($"#{comment.Value}");

    if (node is DotEnvEntry entry)
        Console.WriteLine($"{entry.Key}=\"{entry.Value}\"");
}

var content = DotEnvSerializer.SerializeDocument(doc);
Console.WriteLine(content);

// use the DotEnvDocument to create a new file.

// 
// # NODE VARS
// NODE_ENV=production
// OTHER_VAR=test
var doc2 = new DotEnvDocument();
doc2.AddEmptyLine();
doc2.AddComment("NODE VARS");
doc2.Add("NODE_ENV", "production");
doc2["OTHER_VAR"] = "test";

var content2 = DotEnvSerializer.SerializeDocument(doc);
Console.WriteLine(content2);
File.WriteAllText(".env", content2);
```

## Escaping

Escaping only works when using double quotes or backticks (\`).

- `\b` backspace
- `\n` newline
- `\r` carriage return
- `\f` form feed
- `\v` vertical tab
- `\t` tab
- `\"` escape double quote
- `\\'` escape single quote
- `\uFFFF` escape unicode characters.

## Defaults

By default, only basic dotenv parsing is performed. There are options to enable using
bacticks, json, and yaml delimiters for multiline value parsing to make things easier.

### AllowJson

The `AllowJson` option will allow using `{}` to notate the start and end of json in an
env file.

```dotenv
MY_JSON={
    "one": 1,
    "person": "bob"
    "nested": {
        "person": "alice"
    }
}
```

The above value will be capture as a multiline string.

### AllowYaml

The `AllowYaml` option will allow using `---` to notate the start and end of yaml
in an env file.

```dotenv
MY_YAML=---
one: 1
person: bob
nested:
  person: alice
---
NEXT_SECRET="test"
```

### AllowBackticks

The `AllowBackticks` options will allow using `\`` to notate the start and end
of a multiline value without using quotes so that single quotes and doubles
may be used without the need to escape them.  Backticks functions similarly
to using double quotes.

```dotenv
MYVALUE=`this
will be "captured"`
```
