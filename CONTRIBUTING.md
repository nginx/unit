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
[Howto](https://unit.nginx.org/howto/) guides to get NGINX Unit up and running.


## Ask a Question

Please open an [issue](https://github.com/nginx/unit/issues/new) on GitHub with
the label `question`.  You can also ask a question on
[GitHub Discussions](https://github.com/nginx/unit/discussions) or the NGINX Unit mailing list,
unit@nginx.org (subscribe
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
`enhancement`.  Please do this before implementing a new feature to discuss the
feature first.


### Open a Pull Request

Before submitting a PR, please read the NGINX Unit code guidelines to know more
about coding conventions and benchmarks.  Fork the repo, create a branch, and
submit a PR when your changes are tested and ready for review.  Again, if you'd
like to implement a new feature, please consider creating a feature request
issue first to start a discussion about the feature.


## Git Style Guide

- Keep a clean, concise and meaningful `git commit` history on your branch,
  rebasing locally and squashing before submitting a PR

- For any user-visible changes, updates, and bugfixes, add a note to
  `docs/changes.xml` under the section for the upcoming release, using `<change
  type="feature">` for new functionality, `<change type="change">` for changed
  behavior, and `<change type="bugfix">` for bug fixes.

- In the subject line, use the past tense ("Added feature", not "Add feature");
  also, use past tense to describe past scenarios, and present tense for
  current behavior

- Limit the subject line to 67 characters, and the rest of the commit message
  to 80 characters

- Use subject line prefixes for commits that affect a specific portion of the
  code; examples include "Tests:", "Packages:", or "Docker:", and also
  individual languages such as "Java:" or "Ruby:"

- Reference issues and PRs liberally after the subject line; if the commit
  remedies a GitHub issue, [name
  it](https://docs.github.com/en/issues/tracking-your-work-with-issues/linking-a-pull-request-to-an-issue)
  accordingly

- Don't rely on command-line commit messages with `-m`; use the editor instead

