# Releasing

A release publishes `@ckrets/helper` and `@ckrets/mcp` to npm and `ckrets` to PyPI, all at one version, from a git tag
`v<version>`. Nothing is published yet: the first release is planned as 0.10.0 (see [CHANGELOG.md](../CHANGELOG.md)).
It runs only in `.github/workflows/publish.yml`, by **trusted publishing**: GitHub's OIDC token is the only credential.
No npm or PyPI token exists anywhere, and none is ever added to this repository.

## How it is set up

- **npm:** each package has a trusted publisher that names this repository, the workflow `publish.yml` and the
  environment `release`. `npm publish --provenance` (npm 11.5.1 or later) attaches a signed provenance statement that
  links each tarball to the commit and the workflow run that built it.
- **PyPI:** the `ckrets` project has a trusted publisher that names this repository, `publish.yml` and the environment
  `pypi`. `pypa/gh-action-pypi-publish` uploads with PyPI's attestations.
- **GitHub environments:** `release` (npm) and `pypi` each require a maintainer's review before their job runs, and
  each allows deployments only from tags matching `v*`. The repository variable `CKRETS_RELEASE_REVIEWER` names that
  reviewer, and each job checks first that its environment really requires that review; it refuses otherwise.
- **A tag ruleset:** only maintainers may create, move or delete `v*` tags, so a release tag cannot come from anyone
  else.
- **Repository variables:** `CKRETS_PUBLISH` must be `on` for anything to run; `CKRETS_STAGING_URL` is the staging API
  the tests run against before an upload.

## The workflow refuses unless

- it was started from a tag `v<version>`, and the tag's commit is on `main`;
- that version is the same, as an exact pin (`0.10.0`, never a `^` or `~` range), in `helper/package.json`,
  `mcp/package.json` (and its dependency on `@ckrets/helper`), `registry/server.json` (both fields),
  `python/pyproject.toml` and `python/ckrets/__init__.py`;
- no package is marked private (`"private": true`, `Private :: Do Not Upload`);
- the full test suite passes against staging, and the quickstart passes from a fresh install against production.

## Steps

1. **Prepare the release in a pull request:** set the new version, as an exact pin, in every file listed above, and
   move the **Unreleased** lines of `CHANGELOG.md` under a heading for the version and today's date. CI must be green.
2. **Merge it, then tag that commit on `main`:**
   ```bash
   git switch main && git pull --ff-only
   git tag -s v0.10.0 -m "v0.10.0"        # a signed, annotated tag
   git push origin v0.10.0
   ```
3. **Run the workflow from the tag:** Actions, **Publish**, **Run workflow**, "Use workflow from" **Tags: v0.10.0**.
   The tests run first; then the `release` job waits for the maintainer's approval and publishes to npm; then the
   `pypi` job waits for approval and publishes to PyPI. Before approving, the reviewer checks that the run is for the
   tag `v<version>` and that the tag's commit is on `main` (the workflow refuses otherwise, and the reviewer checks
   anyway).
4. **Check what was published:**
   ```bash
   npm view @ckrets/helper@0.10.0 dist.attestations      # provenance is attached
   mkdir /tmp/check && cd /tmp/check && npm init -y >/dev/null && npm i @ckrets/helper@0.10.0 && npm audit signatures
   ```
   On PyPI, the release's files show their attestations ("Verified details" on https://pypi.org/project/ckrets/).
5. **Publish the GitHub release** from the tag, with the version's `CHANGELOG.md` section as its notes.
6. **The MCP registry entry** (`registry/server.json`) is published after npm, with `mcp-publisher`, under the
   `ai.ckrets` namespace.

A published version is never replaced. If a release is wrong, deprecate it (`npm deprecate`, or yank it on PyPI) and
release a new patch version.
