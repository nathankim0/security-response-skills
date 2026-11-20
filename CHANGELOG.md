# Changelog

## Unreleased

## v1.0.0 (2026-11-20)

### Added

- `nginx2root-java4shell` skill: fast read-only check and response runbooks for NGINX2Root (CVE-2026-123007, CVE-2026-123633, CVE-2026-121810, CVE-2026-123634, CVE-2026-113425), Java4Shell (CVE-2026-114938) and the Linux SCTP privilege escalation.
  - `check.sh` covers host binaries, running processes, Docker containers, containers from other runtimes through `nsenter`, optional Kubernetes images and external TLS probes.
  - Detects distro backports from package changelogs, stale nginx binaries after an upgrade, the AVX-512 VBMI CPU gate, and JVM mitigation flags.
- Finding contract shared by all future skills, `install.sh` for Claude Code and Codex, Claude Code plugin marketplace, and `tests/run.sh`.
