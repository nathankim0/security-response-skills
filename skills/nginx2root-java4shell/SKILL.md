---
name: nginx2root-java4shell
description: Fast triage and response for NGINX2Root (CVE-2026-123007, CVE-2026-123633, CVE-2026-121810, CVE-2026-123634, CVE-2026-113425), Java4Shell (CVE-2026-114938) and the Linux SCTP privilege escalation disclosed with NGINX2Root. Runs a read-only check on hosts, Docker containers and optionally Kubernetes, keeps only the findings that need a response, then applies each fix by its runbook (patch first, temporary mitigation only when the patch has to wait) and re-checks. Use when the user says "NGINX2Root", "Java4Shell", "nginx 취약점 점검", "nginx http2 RCE", "자바 Base64 취약점", "CVE-2026-123007", "CVE-2026-114938", "보안 긴급 패치 점검", or asks whether their nginx or Java servers are affected by the November 2026 advisories.
argument-hint: "[local | ssh host1 host2 ... | --k8s] [--probe domain]"
---

# nginx2root-java4shell

Two passes. **Check fast, then respond only where it matters.**

1. **Check**: run `scripts/check.sh` on every target. It is read-only and finishes in seconds per host.
2. **Triage**: keep only `ACTION`, `MITIGATE` and `REVIEW` rows. Resolve each `REVIEW` into `ACTION` or `OK`.
3. **Respond**: for each remaining row, follow its runbook in `references/remediation.md#<ACTION_ID>`.
4. **Verify**: run the check again on the same targets. Done when no `ACTION` row is left.

Background on each CVE (conditions, affected and fixed versions, sources): `references/advisory.md`. Compromise checks: `references/compromise.md`.

Advisory data is as of 2026-11-20. If web access is available, check the NGINX security advisories page and the Java vendor's bulletin for newer fixed builds before declaring a version safe.

## Step 1. Scope

Infer the targets. Do not ask unless nothing points to any server.

| Situation | Targets |
|---|---|
| no argument, or "이 서버", "local" | this machine |
| hostnames, an inventory file, `~/.ssh/config` hosts the user names | each host over SSH |
| the user mentions Kubernetes, ingress, EKS/GKE | add `--k8s` |
| a public domain is named | add `--probe <domain>` (shows what the edge negotiates) |

Run as root where possible: `nginx -T`, other users' `/proc/<pid>/environ` and logs need it. Without root the script still runs and reports what it could not see as `REVIEW`.

## Step 2. Check

```bash
S=<this skill dir>/scripts/check.sh

# local
sudo bash "$S"                      # or: bash "$S" without sudo
# remote hosts, in parallel, one result file each
for h in web1 web2 api1; do ssh "$h" 'sudo -n bash -s' < "$S" > "/tmp/n2r-$h.tsv" 2>&1 & done; wait
# options
bash "$S" --k8s --probe example.com
```

Output is tab separated: `STATUS  ACTION_ID  TARGET  DETAIL`, plus `# summary ... ACTION=n MITIGATE=n REVIEW=n` per host. Exit code 1 means something needs a response.

| STATUS | Meaning |
|---|---|
| `ACTION` | fix needed |
| `MITIGATE` | temporary mitigation for a target whose `ACTION` cannot be done right now |
| `REVIEW` | the script could not decide; confirm by hand |
| `OK` / `INFO` | no response needed; keep out of the triage list |

## Step 3. Triage

Build one table from all hosts with only `ACTION`, `MITIGATE` and `REVIEW` rows, sorted by priority:

1. internet-facing nginx with `NGX-PATCH` and `NGX-H2-OFF` (widest unauthenticated RCE)
2. `JAVA-PATCH` on auth servers (Keycloak, PingFederate), CI/CD (Jenkins, Artifactory), Jira or Confluence
3. any `IR-NGINX` or `IR-JAVA` row: possible compromise, handle before patching hides evidence
4. other `NGX-*` and `JAVA-*` rows
5. `KRN-SCTP`

Resolve each `REVIEW` row with the matching section in `references/remediation.md` (each section has a "Resolve REVIEW" line). A `REVIEW` that stays unresolved goes in the final report as open.

Show the user the triage table before changing anything. Keep it short: target, finding, planned action.

## Step 4. Respond

Work through the table one row at a time, using `references/remediation.md#<ACTION_ID>`:

- **Patch first.** `NGX-PATCH`, `JAVA-PATCH` are the real fixes. `NGX-RESTART` makes a patch take effect.
- **Mitigate only when the patch waits** (change freeze, vendor build not out, image rebuild pending). Then apply the `MITIGATE` rows for that target and record that the patch is still owed.
- **Compromise rows stop the line.** On `IR-*`, preserve evidence (`references/compromise.md`) before restarting or replacing anything on that target.
- Follow how the target is managed: package manager on hosts, a rebuilt image for containers, the chart or manifest for Kubernetes, the config repo if nginx config lives in git. Do not hand-edit a box that config management will overwrite.
- Restarts, package upgrades and config reloads on production change live traffic. Confirm with the user before running them unless they already said to go ahead. Show the exact commands.
- Run `nginx -t` before every reload. Keep a backup of every file you edit.

## Step 5. Verify and report

Re-run `check.sh` on every target that had a row. Then report:

```text
Target                     Finding        Done                               Result
web1:/usr/sbin/nginx       NGX-PATCH      apt upgrade nginx, restart         OK (changelog lists CVE-2026-123007)
api1:pid 812 (jdk-21)      JAVA-PATCH     pending (vendor build Friday)      MITIGATE applied: -XX:-UseBASE64Intrinsics
web2:kernel 6.8.0-49       KRN-SCTP       modprobe block + rmmod             OK
```

List anything still open: patches owed behind a mitigation, unresolved `REVIEW` rows, and hosts that could not be reached.
