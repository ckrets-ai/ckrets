# Changelog

Notable changes to `@ckrets/helper`, `@ckrets/mcp` and `ckrets` (Python), which share one version. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).
Releases are made from tags: see [docs/RELEASING.md](docs/RELEASING.md).

Nothing is published yet. The first release to npm and PyPI is planned as **0.10.0**, matching the ckrets API's minor
version; until then the package files say 0.9.0, the unpublished beta. Everything below ships in that first release.

## Unreleased (planned as 0.10.0, the first published release)

### Added
- `@ckrets/helper`: `create` (encrypted on your machine by default), `reveal` into a child process's environment, a
  file at an explicit mode, or stdout with `--print`; `request` and `wait`.
- `@ckrets/mcp`: the ckrets MCP server over stdio, with `deliver_secret` into sinks the operator configures.
- `ckrets` (Python): the same client and command in Python.
- Webhooks (preview): `verifyWebhook` in the helper and `verify_webhook` in Python check a ckrets webhook delivery
  (RFC 9421 signature by the issuer's EC P-256 `ckrets-event` key, body digest, a 300 s window, webhook-id). They fail
  closed: anything malformed is `{ ok: false, why }`.
- `npm test` runs the self-contained tests with no API; `npm run test:api` runs every test against a ckrets API.
- Contributor guide, code of conduct, issue and pull request templates, and CI, CodeQL, dependency review and OpenSSF
  Scorecard workflows.
- The publish workflow runs only from an annotated release tag `v<version>` that points at a commit on `main` and
  matches every package's version, each an exact pin; a signature on the tag, if any, must verify (when GitHub cannot
  check it just then, the run goes on with a note).

### Changed
- The helper and the MCP server need Node 22 or later, not 20 (Node 20 is past its end of life), the same as the
  repository.
