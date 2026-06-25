# Homebrew packaging for the vjeantet/nono fork

This directory generates a **binary** Homebrew formula for the
[`vjeantet/homebrew-tap`](https://github.com/vjeantet/homebrew-tap) tap. The
formula installs pre-built macOS release binaries instead of compiling from
source, so installs and updates are fast.

This is specific to the `vjeantet/nono` fork. The upstream project publishes a
source-based formula to homebrew-core via a separate mechanism
(`update-homebrew-core` in `release.yml`); that path is left untouched and is
skipped on the fork.

## Install

```bash
brew tap vjeantet/tap
brew install nono
# or, in one shot:
brew install vjeantet/tap/nono
```

## Files

| File | Purpose |
|------|---------|
| `update.sh` | Regenerates the tap's `Formula/nono.rb` for a given release tag, reading the macOS sha256 values from the release's `SHA256SUMS.txt`. |

The formula itself lives in the tap repository (`Formula/nono.rb`), not here; it
is fully generated and overwritten on each release.

## How publishing works

The `.github/workflows/homebrew-tap-publish.yml` workflow publishes the formula:

- It runs automatically after each successful **Release** (or manually via
  `workflow_dispatch` with a tag input); prereleases and non-tag refs are
  skipped.
- It downloads `SHA256SUMS.txt` from the release, regenerates `Formula/nono.rb`,
  and pushes to the tap **only if it changed**, so re-runs are safe no-ops.
- It never builds nono itself: the formula only references release artifacts that
  are already published.

## Coverage

macOS only: `aarch64-apple-darwin` (Apple Silicon) and `x86_64-apple-darwin`
(Intel). To add Linux later, extend the template in `update.sh` with an
`on_linux` block referencing the `*-unknown-linux-gnu.tar.gz` artifacts (already
produced by the Release workflow).

## Credentials

| What | Where |
|------|-------|
| Tap write access | `HOMEBREW_TAP_TOKEN` repository secret (Actions): a token with `Contents: write` on `vjeantet/homebrew-tap`. |

## Testing locally

```bash
# With a SHA256SUMS.txt from a real release (or a synthetic one):
SHA256SUMS_FILE=./SHA256SUMS.txt FORMULA_PATH=/tmp/nono.rb \
  packaging/homebrew/update.sh v0.65.1
ruby -c /tmp/nono.rb               # check Ruby syntax
brew style --formula /tmp/nono.rb  # if brew is available
```
