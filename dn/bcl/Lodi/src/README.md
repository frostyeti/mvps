# FrostYeti.Lodi

## Overview

A very simple implementation for DI that mainly uses delegates
to create objects to avoid reflection to enable AOT scenarios.

## Usage

```csharp
using FrostYeti.Lodi

var sp = new LodiServiceProvider();

sp.RegisterSingleton(typeof(IContract), _ => new Contract());

var value = sp.GetService<IContract>();
```
