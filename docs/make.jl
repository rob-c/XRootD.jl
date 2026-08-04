using Documenter
using XRootD

makedocs(;
    sitename="XRootD.jl",
    modules=[XRootD, XRootD.XrdCl, XRootD.Storage, XRootD.Tools],
    format=Documenter.HTML(;
        prettyurls=Base.get(ENV, "CI", nothing) == "true",
        repolink="https://github.com/JuliaHEP/XRootD.jl",
    ),
    pages=[
        "Home" => "index.md",
        "Getting started" => "getting_started.md",
        "Recipes" => "recipes.md",
        # One page per module: the four together render past Documenter's
        # HTML size threshold, and a reader after `storage_open` should not have
        # to load the whole client API to reach it.
        "API" => [
            "Everyday" => "api/everyday.md",
            "Client" => "api/client.md",
            "Storage" => "api/storage.md",
            "Tools" => "api/tools.md",
        ],
        "Release Notes" => "release_notes.md",
    ],
    authors="Pere Mato",
    warnonly=true,
)

deploydocs(; repo="github.com/JuliaHEP/XRootD.jl", push_preview=true)
