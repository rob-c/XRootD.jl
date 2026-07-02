using Documenter
using XRootD

makedocs(;
    sitename="XRootD.jl",
    modules=[XRootD],
    format=Documenter.HTML(;
        prettyurls=Base.get(ENV, "CI", nothing) == "true",
        repolink="https://github.com/JuliaHEP/XRootD.jl",
    ),
    pages=["Home" => "index.md", "Release Notes" => "release_notes.md"],
    authors="Pere Mato",
    # Transitional while the 0.3 pure-Julia rewrite is in progress; the docs
    # get their full treatment in plan 08 (parity & release).
    warnonly=true,
)

deploydocs(; repo="github.com/JuliaHEP/XRootD.jl", push_preview=true)
