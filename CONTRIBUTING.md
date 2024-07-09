# Contributing Guidelines

The following is a set of guidelines for contributing to NGINX Unit.  We do
appreciate that you are considering contributing!

## Table Of Contents

- [Getting Started](#getting-started)
- [Ask a Question](#ask-a-question)
- [Contributing](#contributing)
- [Git Style Guide](#git-style-guide)


## Getting Started

Check out the [Quick Installation](README.md#quick-installation) and
[Howto](https://unit.nginx.org/howto/) guides to get NGINX Unit up and
running.


## Ask a Question

Please open an [issue](https://github.com/nginx/unit/issues/new) on GitHub
with the label `question`.  You can also ask a question on
[GitHub Discussions](https://github.com/nginx/unit/discussions) or the NGINX
Unit mailing list, unit@nginx.org (subscribe
[here](https://mailman.nginx.org/mailman3/lists/unit.nginx.org/)).


## Contributing

### Report a Bug

Ensure the bug was not already reported by searching on GitHub under
[Issues](https://github.com/nginx/unit/issues).

If the bug is a potential security vulnerability, please report using our
[security policy](https://unit.nginx.org/troubleshooting/#getting-support).

To report a non-security bug, open an
[issue](https://github.com/nginx/unit/issues/new) on GitHub with the label
`bug`.  Be sure to include a title and clear description, as much relevant
information as possible, and a code sample or an executable test case showing
the expected behavior that doesn't occur.


### Suggest an Enhancement

To suggest an enhancement, open an
[issue](https://github.com/nginx/unit/issues/new) on GitHub with the label
`enhancement`.  Please do this before implementing a new feature to discuss
the feature first.


### Open a Pull Request

Before submitting a PR, please read the NGINX Unit code guidelines to know
more about coding conventions and benchmarks.  Fork the repo, create a branch,
and submit a PR when your changes are tested and ready for review.  Again, if
you'd like to implement a new feature, please consider creating a feature
request issue first to start a discussion about the feature.


## Git Style Guide

- Create atomic commits.  A commit should do just one thing, i.e. you
  shouldn't mix refactoring with functional code changes.  Do the
  refactoring in one or more commits first.

  Ideally you should rebase locally and force push new commits up.

- In the subject line, use the imperative mood.  I.e. write the subject like
  you're giving git a command, e.g. "Free memory before exiting". Do not
  terminate the subject with a `.`

- Try to limit the subject line to around 50 characters, but try not to
  exceed 72.

- Wrap the body of the commit message after 72 characters.

- Use lowercase subject line prefixes for commits that affect a specific
  portion of the code; examples include "tests:", "ci:", or "http:", and
  also individual languages such as "python:" or "php:".  If multiple areas
  are affected you can specify multiple prefixes, e.g. "auto, perl:"

- If the commit fixes an open issue then you can use the "Closes:"
  tag/trailer to reference it and have GitHub automatically close it once
  it's been merged.  E.g.:

  `Closes: https://github.com/nginx/unit/issues/9999`

  That should go at the end of the commit message, separated by a blank line,
  along with any other tags.

