# Contributing

## Commits

Use [Conventional Commits](https://www.conventionalcommits.org/) for commit messages. The required format is:

```text
type(scope): description
```

Common types include `feat`, `fix`, `docs`, `build`, `ci`, `refactor`, `test`, and `chore`. Add `!` after the type or scope for a breaking change, or include a `BREAKING CHANGE:` footer.

Pull requests check every commit with commitlint. Merging conventional commits into `main` lets release-please prepare the next release and changelog.

## Local checks

```text
dotnet test IsaTool.slnx -c Release
```

The release workflow publishes self-contained single-file binaries for Windows x64 and Linux x64 when a `vX.Y.Z` tag is pushed.