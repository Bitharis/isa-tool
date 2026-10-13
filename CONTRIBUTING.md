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

## Manual releases

To release the current `main` branch, open **Actions**, select **release-please**, choose **Run workflow**, enter the desired version such as `1.2.0`, and run it. Release Please will open a release pull request; merge that pull request to create the tag and publish the binaries.

Automatic releases are normally based on `feat`, `fix`, `perf`, and breaking-change commits. `build`, `ci`, `chore`, `docs`, and `test` commits are included in release notes, and a manual release can force a version when those are the only changes.