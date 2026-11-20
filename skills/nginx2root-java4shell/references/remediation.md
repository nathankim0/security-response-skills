# Remediation runbooks

One section per `ACTION_ID` printed by `scripts/check.sh`. Each section: when it applies, how to resolve a `REVIEW` row, steps, verification, rollback.

Production changes (package upgrades, restarts, reloads, image rollouts) need the user's go-ahead unless they already gave it. Always show the commands first.

---

## NGX-PATCH

**Fixes**: all five NGINX2Root CVEs. This is the real fix; every other `NGX-*` row is temporary.

**Fixed versions**: Open Source stable **1.30.7**, mainline **1.31.9**, NGINX Plus: the F5 fixed build for your branch (for example 37.0.8.1, 37.3.0.1). Distro packages may keep the old version number with a backported fix.

**Resolve REVIEW**:
- NGINX Plus or Tengine: compare the version with the vendor advisory.
- Distro package: the fix is in if the package changelog lists `CVE-2026-123007`:
  `zcat /usr/share/doc/nginx*/changelog.Debian.gz | grep CVE-2026-123007` or `rpm -q --changelog nginx | grep CVE-2026-123007`.
- Kubernetes images (`--k8s`): look up the nginx version bundled in each ingress controller or nginx image tag in its release notes.

**Steps**, by how nginx is installed:

| Install | Command |
|---|---|
| Debian, Ubuntu | `sudo apt-get update && sudo apt-get install --only-upgrade 'nginx*'` |
| RHEL, Rocky, Alma, Amazon Linux | `sudo dnf upgrade 'nginx*'` (or `yum`) |
| Alpine | `apk upgrade nginx` |
| nginx.org repo | same package commands; the repo carries 1.30.7 / 1.31.9 |
| built from source | rebuild from the fixed tarball with the same `nginx -V` configure arguments |
| Docker image | bump the base image (`nginx:1.30.7`, `nginx:1.31.9` or a patched distro tag), rebuild, redeploy. Do not patch a running container. |
| Kubernetes ingress | upgrade the controller chart or image to a release that bundles a fixed nginx, roll out |
| OpenResty | upgrade to an OpenResty release that includes the fix, or apply the upstream patches |

If the distro has not shipped a fix yet, apply the `MITIGATE` rows for this target now and recheck the distro daily.

After the binary changes, the running master must be replaced (see `NGX-RESTART`). `nginx -s reload` alone keeps the old binary.

**Verify**: re-run `check.sh`: the row is `OK`. Also `nginx -v`, and smoke-test main pages, APIs, gRPC and TLS.

**Rollback**: reinstall the previous package version or redeploy the previous image tag. Then apply the `MITIGATE` rows, because the old build is still vulnerable.

---

## NGX-RESTART

**When**: the nginx master runs a binary that was replaced on disk (`/proc/<pid>/exe ... (deleted)`). The patch is installed but not running.

**Steps** (pick one):
- Restart: `sudo nginx -t && sudo systemctl restart nginx`
- Zero-downtime binary upgrade:
  ```bash
  sudo kill -USR2 "$(cat /run/nginx.pid)"           # start new master with new binary
  sleep 2; sudo kill -WINCH "$(cat /run/nginx.pid.oldbin)"   # stop old workers
  sudo kill -QUIT "$(cat /run/nginx.pid.oldbin)"    # stop old master once traffic looks fine
  ```

**Verify**: `ps -ef | grep '[n]ginx'` shows only new processes; `check.sh` no longer prints `NGX-RESTART`.

---

## NGX-CONF

**When**: `nginx -T` could not be read, so protocol exposure is unknown.

**Resolve REVIEW**: re-run `check.sh` as root, or run `sudo nginx -T` and look for the directives in the `NGX-H2-OFF`, `NGX-H3-OFF`, `NGX-RESOLVER` and `NGX-MAIL` sections. If the patch is applied soon, this row needs no separate work.

---

## NGX-H2-OFF

**Temporary.** Blocks the known paths of CVE-2026-123007 and CVE-2026-123633 until `NGX-PATCH` is done. Does not fix the other three CVEs.

**Before**: check for HTTP/2-only traffic. Native gRPC (`grpc_pass`, clients that require h2) breaks without HTTP/2. If gRPC is served here, patch instead or move gRPC behind another proxy.

**Steps**:
1. Back up config: `sudo cp -a /etc/nginx /etc/nginx.bak.$(date +%Y%m%d%H%M)`
2. Find every place: `sudo nginx -T 2>/dev/null | grep -nE 'listen.*http2|http2 on'`
3. Edit the source files (the `# configuration file` lines in `nginx -T` name them):
   - nginx 1.25.1 and later: remove `http2` from `listen` lines and set `http2 off;` in each `server` (or once in `http`).
   - nginx 1.25.0 and earlier: remove `http2` from every `listen` line. With several servers on the same address, every one must drop it.
4. `sudo nginx -t && sudo nginx -s reload`. If long-lived h2 connections stay up, restart.

**Verify**:
```bash
openssl s_client -connect <origin-ip>:443 -servername <host> -alpn h2 </dev/null 2>&1 | grep 'ALPN protocol'
```
Expect no `h2`. Probe the origin, not the CDN.

**Rollback**: restore the backup directory, `nginx -t`, reload.

---

## NGX-H3-OFF

**Temporary.** For CVE-2026-121810 until `NGX-PATCH`.

**Steps**:
1. Back up config as above.
2. Remove `listen ... quic` lines, set `http3 off;` where supported.
3. Remove `Alt-Svc` headers that advertise `h3` (`add_header Alt-Svc ...`).
4. `sudo nginx -t && sudo nginx -s reload`

**Verify**: `sudo ss -lunp 'sport = :443'` shows no nginx UDP listener; `curl -sI https://<host> | grep -i alt-svc` has no `h3`.

**Rollback**: restore backup, reload.

---

## NGX-RESOLVER

**Temporary.** Narrows CVE-2026-123634 until `NGX-PATCH`.

**Steps**, as far as the service allows:
- Stop building the upstream host from request data (`proxy_pass http://$arg_x`, `$http_*`, `$host` in the host part). Use a fixed `upstream` block.
- Remove `resolver` where it is only there for those dynamic upstreams.
- Remove unneeded `mirror` and `ssi on`. Note: turning off `mirror` alone does not close every path.
- `nginx -t`, reload.

**Verify**: `sudo nginx -T | grep -nE 'resolver|mirror|ssi on|proxy_pass.*\$'` matches only what you decided to keep, and the row no longer appears.

---

## NGX-MAIL

**Temporary.** For CVE-2026-113425 until `NGX-PATCH`.

**Steps**:
- If the mail proxy is not needed, remove the `mail { }` block (and `load_module ... ngx_mail_module.so`).
- If it is needed, restrict who can connect: firewall the SMTP/IMAP/POP3 ports to trusted client ranges, or `allow`/`deny` in the mail `server` blocks.
- `nginx -t`, reload.

**Verify**: `sudo ss -ltnp | grep nginx` shows no unexpected mail ports open to the internet.

---

## JAVA-PATCH

**Fixes**: CVE-2026-114938 (Java4Shell). The check only raises `ACTION` when the CPU exposes AVX-512 VBMI; elsewhere it prints `INFO` and the update can follow the normal cycle.

**Fixed versions** (OpenJDK numbering; vendor build numbers can differ, check the vendor bulletin):

| Family | Fixed |
|---|---|
| 17 (17.0.6 and later affected) | 17.0.21.1 |
| 21 | 21.0.13.1 |
| 25 | 25.0.5.1 |
| 27 | 27.0.1.1 |
| Oracle Java 8 Enterprise Performance Pack | 8u513-perf |
| non-LTS 18–20, 22–24, 26 | no fix: move to a patched LTS |

Java 8 (standard) and 11 are not affected by this CVE.

**Resolve REVIEW**: a JVM whose binary is gone: `jcmd <pid> VM.version`. Java 8 perf pack: compare with the Oracle advisory.

**Steps**: update the runtime the **process actually uses** (the path in the TARGET column), not just the one on `PATH`.

| Runtime | How |
|---|---|
| OS package (Temurin, Corretto, Zulu, Red Hat, Microsoft, Liberica repos) | `apt-get install --only-upgrade <jdk pkg>` / `dnf upgrade <jdk pkg>` |
| tarball under `/opt` | install the fixed build beside it, repoint the symlink or `JAVA_HOME` |
| Docker image | bump the base image tag (for example `eclipse-temurin:21` after the vendor publishes 21.0.13.1), rebuild, redeploy |
| bundled JRE (Jenkins, Jira, Confluence, Artifactory, Keycloak, Elasticsearch, Solr, Kafka distributions) | upgrade the product to a release that ships the fixed JRE, or point it at a fixed system JDK if the product supports that |

Restart the service afterwards. The old JVM keeps running until then.

**Verify**: `check.sh` shows `OK` for the target, or `jcmd <pid> VM.version`.

---

## JAVA-MITIGATE

**Temporary.** Turns off the vulnerable Base64 intrinsic until `JAVA-PATCH`.

**Steps**:
1. Check the JVM accepts the flag: `<java> -XX:-UseBASE64Intrinsics -version`
2. Add it where the service starts:
   - systemd: `sudo systemctl edit <svc>` → `[Service]` `Environment="JAVA_TOOL_OPTIONS=-XX:-UseBASE64Intrinsics"` (append to an existing value, do not replace it)
   - Docker / Kubernetes: add `JAVA_TOOL_OPTIONS=-XX:-UseBASE64Intrinsics` to the container env, redeploy
   - products: their JVM options file (`setenv.sh`, `jvm.options`, `JAVA_OPTS`)
3. Restart the service.

Fallback when the flag is not available: `-XX:UseAVX=2` (x86-64 only, wider performance impact).

**Verify**: `jcmd <pid> VM.flags -all | grep UseBASE64Intrinsics` shows `false`, and the `MITIGATE` row disappears.

**Rollback**: remove the option and restart. Remove it anyway after `JAVA-PATCH` is done.

---

## KRN-SCTP

**When**: the SCTP kernel module can be loaded (or is loaded). Used as the root step after an nginx RCE. No vendor kernel fix existed at disclosure, so blocking the module is the response.

**Before**: confirm nothing uses SCTP: `ss -Sanp` (empty), and no telecom, Diameter, or WebRTC data channel stack that needs kernel SCTP. Run this on the **host**, not inside a container.

**Steps**:
```bash
echo 'install sctp /bin/false' | sudo tee /etc/modprobe.d/disable-sctp.conf
lsmod | grep '^sctp' && sudo modprobe -r sctp     # unload if loaded and unused
```
If SCTP is built into the kernel, the block does not apply: track the kernel vendor advisory and update the kernel when a fix ships.

**Verify**: `check.sh` shows `OK  KRN-SCTP ... blocked`.

**Rollback**: `sudo rm /etc/modprobe.d/disable-sctp.conf`.

---

## IR-NGINX, IR-JAVA

**When**: crash evidence (nginx worker signal 11/6, segfaults, `hs_err_pid*.log`). A crash alone does not prove compromise, but it must be looked at before the target is restarted or replaced.

**Steps**: `references/compromise.md`.

---

## CONTAINERS, K8S, PROBE

- `CONTAINERS` REVIEW: Docker exists but the daemon was not reachable. Re-run as root, or check images in the registry.
- `K8S` REVIEW: `kubectl` missing. Run from a machine with cluster access.
- `PROBE` rows are context. An edge that negotiates `h2` may be a CDN or load balancer; what matters is the protocol between that edge and the origin nginx.
