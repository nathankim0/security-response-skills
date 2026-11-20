# AGENTS.md

Instructions for any coding agent (Claude Code, Codex, others) working in this repository. `CLAUDE.md` is a symlink to this file; edit `AGENTS.md` only.

## What this repo is

A growing collection of security check and response skills. Every skill follows the same two-pass shape: a fast, read-only check script finds what is affected, then each finding is fixed by its own runbook and checked again. Distributed as a Claude Code plugin marketplace and as plain skill folders that `install.sh` links into Claude Code or Codex.

```text
.claude-plugin/plugin.json        plugin manifest (version)
.claude-plugin/marketplace.json   marketplace manifest (metadata.version)
skills/<name>/SKILL.md            one skill per security issue or theme
skills/<name>/scripts/check.sh    read-only check, prints the finding contract below
skills/<name>/references/         remediation.md (one section per ACTION_ID), advisory.md, compromise.md
tests/run.sh                      runs every check script against fake binaries
install.sh                        symlinks skills into ~/.claude/skills and ~/.codex/skills
```

## Rules for every change

1. **Commit and push after every change.** One logical change per commit. Push to `main` right after committing. Do not leave work uncommitted at the end of a task.
2. **Release only for distribution changes.** A change is a distribution change when it alters what users install or how a skill behaves: `skills/`, `.claude-plugin/`, `install.sh`. For these:
   - bump the version one step in `.claude-plugin/plugin.json` and `.claude-plugin/marketplace.json` (`metadata.version`): patch for fixes and small tweaks, minor for a new skill or feature, major for breaking changes
   - move the `Unreleased` notes in `CHANGELOG.md` under the new version
   - commit `Release vX.Y.Z`, push, then tag and release:
     ```bash
     git tag -a vX.Y.Z -m "vX.Y.Z"
     git push origin vX.Y.Z
     gh release create vX.Y.Z --title "vX.Y.Z" --notes-file <notes>
     ```
3. **Docs-only changes do not release.** README, AGENTS.md, images, comments, and typo fixes are committed and pushed with no version bump, tag, or release.
4. **Keep READMEs in sync.** Any change to `README.md` gets the same change in `README.ko.md`, and the reverse. Add every new skill to the skills table in both.
5. **Validate before committing** a distribution change: `shellcheck -S warning skills/*/scripts/*.sh install.sh tests/run.sh && tests/run.sh && claude plugin validate .` must pass.
6. **Never commit secrets or private information**: no tokens, employer or internal names, hostnames, IPs, personal emails, or home paths. Test fixtures use made-up values.

## Adding a skill

Each new skill is one folder under `skills/`, named after the issue (`nginx2root-java4shell`) or the theme (`ssh-hardening`).

- **`SKILL.md`**: frontmatter `name`, `description` with the CVE ids and the phrases users actually type (Korean and English), then the five steps: Scope, Check, Triage, Respond, Verify and report.
- **`scripts/check.sh`**: read-only. It never installs, edits, restarts, or sends anything except the probes the user asked for. Runs on Linux with bash 3.2+ (macOS too where it makes sense), works without root and says what it could not see, and works over `ssh host 'sudo bash -s' < check.sh`.
- **Finding contract**: one finding per line, tab separated, `STATUS  ACTION_ID  TARGET  DETAIL`, comments start with `#`, the last line is `# summary host=... ACTION=n MITIGATE=n REVIEW=n OK=n INFO=n`. Exit 0 when nothing is needed, 1 when any `ACTION` or `MITIGATE` row exists, 2 on a usage error.
  - `ACTION` fix needed, `MITIGATE` temporary measure while the fix waits, `REVIEW` undecided, `OK` not affected, `INFO` context.
  - `TARGET` starts with the hostname so results from many hosts can be merged.
- **`references/remediation.md`**: one `## <ACTION_ID>` section per id the script can print, each with how to resolve `REVIEW`, steps, verify, rollback.
- **`tests/run.sh`**: add cases with fake binaries on `PATH` for every status the script can print.
- Use `IR-*` ids for possible-compromise rows and keep the "preserve evidence before restarting" rule.

## Project rules

- Advisory data goes in `references/advisory.md` with the date it was current and links to the sources. Vendor bulletins win over our summary.
- Real fixes (patch, upgrade) come before temporary mitigations in every runbook.
- Runbooks show commands; agents confirm with the user before changing production systems.

## Commit messages

Imperative, short subject. Example: `Add ssh-hardening skill` or `Detect nginx in containerd pods`.
