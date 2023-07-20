# Contributing to libvips

Thank you for your interest in contributing to libvips! There are many ways to
contribute, and we appreciate all contributions.

## Code style

This project uses `clang-format` to maintain a consistent code style throughout
the codebase. We recommend using version 14 (as available in Ubuntu 22.04), to
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
