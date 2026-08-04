# Everyday API

The verbs in `XRootD` itself: [`StoragePath`](@ref), the `Base` functions it
answers to, and the `XRootD.`-qualified forms that take a URL as a string.
Failures here raise [`StorageError`](@ref XRootD.Storage.StorageError) rather
than returning a status. [Getting started](@ref) walks through them in the
order a job uses them.

```@autodocs
Modules = [XRootD]
```
