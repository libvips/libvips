# Contributing to libvips

Thank you for your interest in contributing to libvips! There are many ways to
contribute, and we appreciate all contributions.

## New development

All new development should target the `master` branch. Stable release branches
are created from `master` roughly every six months.

If your pull request introduces a new API, add an entry to the [ChangeLog](
ChangeLog) file crediting yourself and any co-authors. This file is used when
preparing release notes.

<!-- TODO: Uncomment this for the 8.19 cycle.

## Bug fixes

Bug fixes should also target the `master` branch. Fixes that do not introduce
API changes generally should not update the [ChangeLog](ChangeLog) file.

-->

## Code style

This project uses `clang-format` to maintain a consistent code style throughout
the codebase. We recommend using version 19 (as available in Ubuntu 24.04), to
avoid any formatting mismatch with our [GitHub Actions lint check](
.github/workflows/lint.yml).

`clang-format` can be used via the `git-clang-format` script. On some systems,
it may already be installed (or be installable via your package manager). If
so, you can simply run it – the following commands will format only the code
on the staged changes:
```shell
# Stage original changes
$ git add .

# Run clang-format on staged changes
$ git clang-format

# Stage formatting changes and commit
$ git add .
$ git commit -m "My commit message"
```

Alternatively, you can format only the code changed in the most recent commit:
```shell
$ git clang-format HEAD~1
```

Note that this modifies the files, but doesn't commit them – you'll likely want
to run:
```shell
$ git commit --amend -a
```

in order to update the last commit with all pending changes.

In an emergency, reformat the entire project with something like:

```shell
find . \
  \( -name "*.[hc]" -o -name "*.cc" -o -name "*.cpp" \) \
  -not \( -path "./libvips/foreign/libnsgif/*" -o \
    -name vips-operators.cpp -o \
    -name StandaloneFuzzTargetMain.c -o \
    -name profiles.c \) | \
  xargs clang-format -i
```

## Maintainers guide

### Backports

You can request backports to a stable branch by adding special comments to an
issue or pull request. After your pull request has been merged:

1. Set the issue or pull request milestone to the target stable branch (`X.Y`).
2. Add a comment in the following format:
   ```
   /cherry-pick <commit1> <commit2> <...>
   ```

A GitHub Actions workflow will then automatically create a pull request against
the stable branch containing the specified commits.

### Merge strategy

Different types of pull requests should be merged using specific GitHub merge
options:

- Regular development pull requests: use "Squash and merge" to keep a clean,
  linear history.
- Backport pull requests: use "Rebase and merge" to avoid duplicate references
  and unnecessary `Co-authored-by:` lines in commit messages.
