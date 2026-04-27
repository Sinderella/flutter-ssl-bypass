# Release Runbook — flutter-ssl-bypass

Maintainer-only runbook for cutting the first non-RC release of `flutter-ssl-bypass`. This document captures the **exact sequence** of commands and observation checkpoints. Execute it in order; do not skip checkpoints.

This is maintainer documentation. End users do not need to read this — they get the agent from the GitHub Releases page (see `README.md` § Quick start).

## Prerequisites

Before starting, every one of the following must be true:

- Working tree on `main`, clean (`git status` shows nothing modified, no untracked files in tracked paths).
- Up-to-date with origin: `git fetch && git rev-parse HEAD` matches `git rev-parse origin/main`.
- Local toolchain installed: `bun` (1.3.x), and `frida-compile` resolved through `bun install` (not a global install).
- `.github/workflows/release.yml` exists and triggers on `v*` tag pushes.
- Maintainer has push access to the `Sinderella/flutter-ssl-bypass` repository on GitHub.
- The `gh` CLI is authenticated (`gh auth status` shows logged in) — used optionally for verification, not required for tagging.

If any precondition fails, stop and resolve it before continuing. A tag push against a dirty tree or a stale `main` will publish the wrong artifact.

## Release sequence

Execute the following six steps in order.

### Step 1 — Pre-flight checks

Every command must exit 0 before pushing any tag.

```bash
bun run typecheck
bun run lint
bun run build
bun run verify:smoke
git status         # working tree clean
git log -1 --oneline  # confirm what HEAD points at
```

Expected: every command exits 0; `git status` reports "nothing to commit, working tree clean"; `dist/flutter-ssl-bypass.js` exists and matches what `release.yml` will publish (the workflow runs `bun run build` itself, but a clean local build proves the source compiles).

### Step 2 — Push v0.1.0-rc.1 and observe

```bash
git tag v0.1.0-rc.1
git push origin v0.1.0-rc.1
```

Then in the GitHub UI (`https://github.com/Sinderella/flutter-ssl-bypass`):

- **Actions tab** — the `release.yml` workflow shows a run in progress for the `v0.1.0-rc.1` tag. Wait for it to finish (typically 2-4 minutes).
- **Releases tab** — a new release `v0.1.0-rc.1` appears with the **prerelease flag set** (orange "Pre-release" badge — `release.yml` auto-derives `prerelease: true` from the `-rc.` substring in the tag name). It must show two assets:
  - `flutter-ssl-bypass.js`
  - `flutter-ssl-bypass.js.sha256`
- The release notes (auto-generated) include the verification stanza — the same `sha256sum -c` command users see in `README.md` § Verify the artifact. Spot-check the wording.

If anything is wrong (workflow failed, asset missing, prerelease flag not set, notes incorrect), the RC iteration loop in Step 3 handles it.

### Step 3 — RC iteration loop on workflow bugs

If `RC.N` has a problem:

1. Investigate `release.yml` in the Actions tab. Identify the broken step and root cause.
2. Fix on `main` and push the fix:
   ```bash
   # ... edit .github/workflows/release.yml or related files ...
   git add .github/workflows/release.yml
   git commit -m "fix(release): <what was wrong>"
   git push origin main
   ```
3. Delete the broken RC tag locally and on origin:
   ```bash
   git tag -d v0.1.0-rc.1
   git push origin :refs/tags/v0.1.0-rc.1
   ```
4. **Manually delete the broken Release in the GitHub UI** — Releases tab → click the broken RC → Delete release. This keeps the Releases page clean.
5. Push the next RC:
   ```bash
   git tag v0.1.0-rc.2
   git push origin v0.1.0-rc.2
   ```
6. Re-run Step 2's GitHub UI checks against `v0.1.0-rc.2`. If still broken, repeat (incrementing the RC number each time).

**Circuit breaker: If after 3 RC iterations (rc.1, rc.2, rc.3) the workflow still produces a broken release — STOP.** Three RCs is the cap. A persistent failure means something fundamental about `release.yml` is wrong; further attempts will not converge without a different angle. Step back, debug `release.yml` from a different angle, then resume. Sinking 4-5 RCs into the same broken workflow just produces tag noise.

### Step 4 — Push v0.1.0 (the non-RC tag)

Once an RC is observed clean (workflow green, both artifacts attached, prerelease flag correct, release notes look right):

```bash
git tag v0.1.0
git push origin v0.1.0
```

GitHub UI checks (mirrors Step 2 but **without** the prerelease flag this time):

- Actions tab: `release.yml` runs to completion against `v0.1.0`.
- Releases tab: `v0.1.0` appears as a non-prerelease (no orange "Pre-release" badge — the `-rc.` substring isn't in the tag name, so the auto-derive flips correctly). It shows both assets:
  - `flutter-ssl-bypass.js`
  - `flutter-ssl-bypass.js.sha256`
- Auto-generated notes include the verification stanza.

### Step 5 — Local verify (belt-and-suspenders)

Even though the workflow already produced the artifacts, the maintainer downloads and verifies them once before announcing the release. This catches the failure mode where `release.yml` builds the JS in one step and computes the sha256 in a different checkout / different job — yielding a sha256 that doesn't match the published JS.

```bash
mkdir -p /tmp/release-verify && cd /tmp/release-verify
curl -L -O https://github.com/Sinderella/flutter-ssl-bypass/releases/download/v0.1.0/flutter-ssl-bypass.js
curl -L -O https://github.com/Sinderella/flutter-ssl-bypass/releases/download/v0.1.0/flutter-ssl-bypass.js.sha256
sha256sum -c flutter-ssl-bypass.js.sha256
# expected output: flutter-ssl-bypass.js: OK
```

If this fails, **do not announce the release**. The workflow is producing inconsistent artifacts; investigate `release.yml` (probably the build and sha256 steps run in different jobs / different working directories) and re-RC.

### Step 6 — Post-release symlink swap

After `v0.1.0` is published and locally verified, swap the root parity reference for a symlink to the build output:

```bash
# In the repo root (NOT in /tmp/release-verify).
cd path/to/your/flutter-ssl-bypass/checkout
rm flutter-ssl-bypass.js
ln -s dist/flutter-ssl-bypass.js flutter-ssl-bypass.js
git add flutter-ssl-bypass.js
git commit -m "chore: replace root JS with symlink to dist/ (post-v0.1.0)"
git push origin main
```

**Important note — broken-on-clone behavior:** `dist/` is `.gitignore`d, so on a fresh clone the symlink points at a nonexistent file. This is **intentional** — users are expected to download the agent from GitHub Releases, not clone the repo and run the working tree. Anyone who clones and tries `frida -l flutter-ssl-bypass.js` directly will see a clear "broken symlink" error and recover by running `bun run build` once. Document this in your release announcement so contributors are not confused.

### Optional safety: tag the pre-symlink-swap commit

If you want a permanent recovery point for the original parity-reference JS — recommended but **not required** — tag the commit immediately before the rm+symlink change:

```bash
# Run BEFORE the rm/ln/commit above. Get the commit hash with `git log -1`.
git tag legacy-js-pre-symlink-swap <commit-sha-before-the-rm>
git push origin legacy-js-pre-symlink-swap
```

Cost: one tag in the repo. Benefit: a future archaeologist can recover the original JS verbatim with `git checkout legacy-js-pre-symlink-swap -- flutter-ssl-bypass.js`. The parity baselines under `tests/parity/` also persist this content, so the tag is belt-and-suspenders rather than load-bearing.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `release.yml` workflow fails on tag push | Workflow file change broke it | Check the failing step in Actions tab; fix on `main`; delete the RC tag and re-push |
| Release page shows only one asset | `release.yml` artifact upload step is broken | Same — fix and re-RC |
| Prerelease flag missing on rc.X | `release.yml` prerelease auto-derive is broken | Same — fix and re-RC |
| `sha256sum -c` fails on downloaded artifact | The sha256 sibling and the JS were built from different sources | Fix `release.yml` (probably running `build` and `sha256sum` in different jobs / different checkouts); re-RC |
| 3 RCs in and still broken | Fundamental `release.yml` issue | **Stop.** Step back and debug `release.yml` from a different angle before retrying |
| Symlink in working tree shows as "broken" on a fresh clone | `dist/` is gitignored, so the symlink target doesn't exist | Expected behavior. Run `bun run build` once to populate `dist/flutter-ssl-bypass.js` |

## References

- `.github/workflows/release.yml` — the workflow whose runs Step 2 / Step 4 observe.
- `package.json` — owns the `typecheck`, `lint`, `build`, `verify:smoke` scripts referenced in Step 1.
- `tools/parity-capture.md` — the established pattern for maintainer-only runbooks under `tools/`.

This runbook is exhaustive on purpose. After the first execution, the steps will feel obvious; before the first execution, they prevent missed checkpoints (the prerelease flag is the most-skipped one).
