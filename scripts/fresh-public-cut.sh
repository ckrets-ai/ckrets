#!/usr/bin/env bash
# Publishes this checkout's tracked files to a new repository as one commit with no history:
#
#   bash scripts/fresh-public-cut.sh <target remote URL> [--push]
#   bash scripts/fresh-public-cut.sh --bundle <file>          (the same commit as a git bundle, for a session that holds the target)
#
# It checks the tree first (no internal reference, no personal address, no account ID, no staging host), builds an
# orphan commit of the tracked files in a temporary clone (this repository and its history are never touched), shows
# what it made, and pushes it to the target's main only with --push. The target must be empty: it refuses a target that
# already has a main, and never force-pushes. Author and committer: ckrets <noreply@ckrets.ai>.
set -euo pipefail
cd "$(dirname "$0")/.."
TARGET=${1:-}; PUSH=${2:-}; BUNDLE=
if [ "$TARGET" = --bundle ]; then BUNDLE=${2:-}; TARGET=; PUSH=; [ -n "$BUNDLE" ] || { echo "usage: bash scripts/fresh-public-cut.sh --bundle <file>"; exit 64; }; BUNDLE=$(cd "$(dirname "$BUNDLE")" && pwd)/$(basename "$BUNDLE"); fi
[ -n "$TARGET$BUNDLE" ] || { echo "usage: bash scripts/fresh-public-cut.sh <target remote URL> [--push] | --bundle <file>"; exit 64; }
[ -z "$PUSH" ] || [ "$PUSH" = --push ] || { echo "unknown option $PUSH"; exit 64; }
[ -z "$(git status --porcelain)" ] || { echo "REFUSED: commit or discard local changes first (only committed, tracked files are published)"; exit 3; }

# 1. the tree must be clean of what must not be public: internal references, account IDs, staging hosts, personal
#    addresses, and the names in CUT_DENY (a regular expression the maintainers keep outside this repository, so the
#    names it guards are not published here either)
[ -n "${CUT_DENY:-}" ] || { echo "REFUSED: set CUT_DENY (the maintainers' list of names that must not be public)"; exit 3; }
PATTERN="claude\\.ai/code/session|\\b[TD][0-9]{2,3}\\b|\\b[0-9]{12}\\b|cloudfront\\.net|execute[-]api|@gmail\\.com|$CUT_DENY"
hits=$(git ls-files -z | grep -zv '^package-lock\.json$' | xargs -0 grep -I -n -P "$PATTERN" 2> /dev/null || true)
if [ -n "$hits" ]; then echo "REFUSED: the tree still holds references that must not be public (file:line only):"; printf '%s\n' "$hits" | cut -d: -f1,2; exit 3; fi
! grep -q -P "$CUT_DENY" package-lock.json || { echo "REFUSED: package-lock.json matches CUT_DENY"; exit 3; }

# 2. one orphan commit of the tracked files, in a throwaway clone
WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT
git archive --format=tar HEAD | tar -x -C "$WORK"
cd "$WORK"
git init -q -b main
git add -A
GIT_AUTHOR_NAME=ckrets GIT_AUTHOR_EMAIL=noreply@ckrets.ai GIT_COMMITTER_NAME=ckrets GIT_COMMITTER_EMAIL=noreply@ckrets.ai \
  git -c commit.gpgsign=false commit -q -m "ckrets clients 0.9.0"
echo "made $(git rev-parse --short HEAD): $(git ls-files | wc -l) files, one commit, no history"
git log --format='  author %an <%ae>, committer %cn <%ce>: %s' -1

# 3. a bundle (main only), or push only with --push, and only to an empty target
if [ -n "$BUNDLE" ]; then git bundle create -q "$BUNDLE" main && echo "bundle $BUNDLE: commit $(git rev-parse HEAD), sha256 $(sha256sum "$BUNDLE" | cut -c1-64)"; exit 0; fi
git remote add target "$TARGET"
if git ls-remote --exit-code --heads target main > /dev/null 2>&1; then echo "REFUSED: $TARGET already has a main; this script never overwrites one"; exit 3; fi
if [ "$PUSH" = --push ]; then git push -q target main && echo "pushed to $TARGET main"; else echo "dry run: pass --push to push it to $TARGET main"; fi
