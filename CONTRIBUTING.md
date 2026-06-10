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

## AI Contribution Policy

We are a project by humans for humans. We prefer contributions that
are produced by human creativity, we expect a human to take full
responsibility for each contribution, and we will take more joy in
reviewing contributions when there are people at the other end of the
line to stand by their changes.

If you use LLM/GenAI tools for your contributions, here are the rules
you must follow:

### Requirements

1. Use AI as a tool. Verify behavior, correctness, and compatibility
   yourself prior to submitting your contribution. Do not ask the
   maintainers to do this for you.
1. Keep changes narrow and limited. Do **NOT** use LLM/GenAI tools to
   generate broad rewrites, large refactorings, or style changes.
1. Do **NOT** submit generated code, documentation, or tests that you
   don't understand.
1. Do **NOT** fabricate benchmarks, bug reports, test results, code
   samples, or reproducers.
1. Do **NOT** include private code, credentials, tokens, or any other
   confidential material.
1. Respect the licensing and attribution requirements.

### Disclosure

Always disclose the use of LLM/GenAI tools when creating an issue or
a merge request. Do not include trailers like “Co-authored-by:” or
“Assisted-by:” in commit messages, since they serve as free advertising
for AI companies.

### Reviews

1. Describe your changes, and the verification steps.
1. Be prepared to explain all the changes yourself.
1. Do **NOT** feed the review feedback to an LLM/GenAI tool.

### Maintainers expectations

1. Review LLM/GenAI-assisted contributions more strictly than any other contribution.
1. Require reproducibility in fixes and tests.
1. Reject changes that appear to be unverified LLM/GenAI output.
1. Reject comments and feedback that appear to be LLM/GenAI output.

> A COMPUTER CAN NEVER BE HELD ACCOUNTABLE.
> THEREFORE A COMPUTER MUST NEVER MAKE A MAINTENANCE DECISION.

