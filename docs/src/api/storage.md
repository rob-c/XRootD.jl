# Storage — `XRootD.Storage`

Backend-agnostic storage dispatching on URL scheme, and the `IO` streams over
it. Backend calls answer with a `Symbol`; the stream layer raises
[`StorageError`](@ref XRootD.Storage.StorageError).

```@autodocs
Modules = [XRootD.Storage]
```
