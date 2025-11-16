# FrostYeti.Colors.Primitives

## Overview

Primitive structs that present color formats such as Rgb, Hex, Argb. Some basic parsing and conversion logic is included.

## Usage

```csharp
using FrostYeti.Colors;

var hex = Hex.Parse("#FF0000");
Console.WriteLine($"{hex.R} {hex.G} {hex.B}");
```
