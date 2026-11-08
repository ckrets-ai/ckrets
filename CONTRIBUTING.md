# Contributing

Thank you for helping with the ckrets clients: `@ckrets/helper`, `@ckrets/mcp` and the `ckrets` Python package.

## Before you start

- **Security issues are never filed in public.** Report them privately through this repository's **Security** tab
  ("Report a vulnerability"), as [SECURITY.md](SECURITY.md) explains.
- For anything larger than a small fix, open an issue first so we can agree on the approach before you write the code.
- Everyone taking part follows the [Code of Conduct](CODE_OF_CONDUCT.md).

## Develop

Node 22 or later (the `engines` of every package), and Python 3.9 or later with `cryptography>=42`.

```bash
npm ci --ignore-scripts
npm test                      # the self-contained tests, in JS and Python: no API needed
```

`npm run test:api` runs every test against a ckrets API (`CKRETS_TEST_BASE_URL`, an API you may test against); it
never skips. The CI workflow runs `npm test` on every pull request: on Node 22 with every Python version from 3.9 to
3.14, and on Node 24.

## The rules a change keeps

These are what the clients promise, and the tests hold them; a pull request that weakens one is not merged:

- A value goes only where the user says: a child process's environment, a file created at an explicit mode, or stdout
  with `--print`. Everything else (digests, receipts, notes) goes to stderr. Nothing logs or prints a value by accident.
- A refusal comes before a reveal is spent whenever it can, so a mistake does not burn a one-time value.
- Checks fail closed: malformed input is a refusal, never an exception or an accept.
- `create` encrypts on the user's machine by default; `plaintext` is an explicit opt-out.
- The helper has no runtime dependencies, and the Python package exactly one (`cryptography`).
- The helper (JS) and the Python client behave the same: the same command, exit codes and refusals.

## Pull requests

Every change, from maintainers too, lands through a pull request from a branch; nothing is pushed straight to `main`.
Each pull request is reviewed (independent review plus a maintainer's approval) and must pass the required checks: CI,
CodeQL and dependency review. Outside contributions follow exactly the same review.

- Keep each pull request to one change, with a test that fails without it.
- Update the README (and `python/README.md`) when behaviour changes, and add a line under **Unreleased** in
  [CHANGELOG.md](CHANGELOG.md).
- Never put a real secret, key or token in code, tests, issues or logs. Tests make their own fake values.
- Workflows pin every action by its full commit SHA, keep `permissions` to read-only unless a job needs more, check out
  with `persist-credentials: false`, never use `pull_request_target`, and never put `github.event` text in a `run:`
  step.
- CI and tool dependencies are exact pins (the npm lockfile, the workflow actions and tools, the Python build backend),
  installed with `npm ci --ignore-scripts`; a new version waits 7 days unless a security advisory needs it sooner. The
  published packages' runtime requirements stay ranges (the helper has none; Python needs `cryptography>=42`).

## Licence

By contributing, you agree that your contribution is licensed under the Apache License 2.0, the same as this
repository (see `LICENSE` and `NOTICE`).
