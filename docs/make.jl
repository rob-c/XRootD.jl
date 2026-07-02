using Documenter
using XRootD

makedocs(;
    sitename="XRootD.jl",
    modules=[XRootD, XRootD.XrdCl, XRootD.Storage, XRootD.Tools],
    format=Documenter.HTML(;
        prettyurls=Base.get(ENV, "CI", nothing) == "true",
        repolink="https://github.com/JuliaHEP/XRootD.jl",
    ),
    pages=["Home" => "index.md", "API" => "api.md", "Release Notes" => "release_notes.md"],
    authors="Pere Mato",
    warnonly=true,
)

deploydocs(; repo="github.com/JuliaHEP/XRootD.jl", push_preview=true)
