# Advisory summary (as of 2026-11-20)

Condensed from the researcher write-ups and vendor advisories listed at the end. Vendor bulletins win over this file when they disagree.

## NGINX2Root (disclosed 2026-11-18, Xint)

Five independent unauthenticated RCE paths in nginx, plus a separate Linux kernel SCTP bug used to go from the nginx worker to host root. Each nginx CVE works alone. CVSS 4.0: 9.2 each (F5 CVSS 3.1: 8.1).

| CVE | Bug | Reachable when | Affected |
|---|---|---|---|
| CVE-2026-123007 | HTTP/2 flow control `send_window` integer underflow, out-of-bounds read and write | HTTP/2 enabled. Works on static-file-only servers. | 1.9.5 – 1.31.8 |
| CVE-2026-123633 | HTTP/2 use-after-free while reclaiming upstream connection slots | HTTP/2 plus `proxy_pass` / `fastcgi_pass` / `grpc_pass` | 1.19.7 – 1.31.8 |
| CVE-2026-121810 | HTTP/3 / QUIC use-after-free when forwarding upstream | HTTP/3 or QUIC listener | 1.25.0 – 1.31.8 |
| CVE-2026-123634 | DNS resolver use-after-free with subrequests | `resolver`, request data in the `proxy_pass` host, `mirror` (with `mirror_request_body off`) or SSI | 0.6.18 – 1.31.8 |
| CVE-2026-113425 | mail proxy use-after-free during `auth_http` | `mail { }` with `proxy on` and `auth_http` | 0.5.33 – 1.31.8 |

Fixed: **1.30.7** (stable), **1.31.9** (mainline), NGINX Plus fixed builds per branch (37.0.8.1, 37.3.0.1, ...). Distros may backport without changing the version.

Kernel: SCTP association migration between sockets mishandles object lifetime (use-after-free / double free). Demonstrated on cloud VMs, bare Linux and from inside a Docker nginx container to host root. No kernel patch at disclosure.

Common mistakes:
- HTTP/2 off is not a fix: HTTP/3, resolver and mail paths remain.
- `nginx -s reload` after a package upgrade keeps the old binary.
- A CDN or ALB in front only helps if it terminates HTTP/2 and talks a different protocol to the origin.
- Docker does not isolate a kernel bug.

## Java4Shell (disclosed 2026-11-17, Calif)

CVE-2026-114938. HotSpot's AVX-512 VBMI Base64 decoder intrinsic miscomputes output length on malformed padding and writes up to 62 bytes past the output buffer, before the input is rejected. Results: JVM crash, memory disclosure, RCE depending on the application heap layout. CVSS 4.0 9.2 (3.1: 8.1). Exploitation attempts seen from 2026-11-19; no confirmed successful compromise in the sources as of 2026-11-20.

All of these must hold:
- x86-64 CPU exposing `avx512f`, `avx512bw`, `avx512vbmi`, `bmi2` (Ice Lake and later Xeon, AMD Zen 4 and later). ARM64 (Graviton, Apple Silicon) is not affected. In VMs, check the flags the guest sees.
- An affected JDK build with the Base64 intrinsic enabled.
- Attacker-controlled Base64 reaching `java.util.Base64.Decoder`: Basic auth, JWT, SAML, uploads, message payloads, or TLS data from a malicious server the JVM connects to.

| Family | Affected | Fixed |
|---|---|---|
| 17 | 17.0.6 and later, unpatched | 17.0.21.1 |
| 21 | up to 21.0.13.0.3 | 21.0.13.1 |
| 25 | up to 25.0.5.0.3 | 25.0.5.1 |
| 27 | up to 27.0.1.0.3 | 27.0.1.1 |
| Oracle Java 8 Perf Pack | 8u511b33-perf | 8u513-perf |

Standard Java 8 and 11 are not affected. Applies to Corretto, Temurin, Zulu, Microsoft, Liberica, Red Hat, Oracle Java SE and GraalVM builds of those families; vendor build numbers can differ.

Researchers showed pre-auth RCE on Keycloak, Jira, Confluence, Artifactory, Jenkins and PingFederate, and post-auth RCE on Kafka, Solr, Elasticsearch, Gerrit and Spinnaker. Every exploit is product specific; there is no universal payload.

Temporary mitigation: `-XX:-UseBASE64Intrinsics` (or `-XX:UseAVX=2` on x86-64, broader performance cost).

## Sources

- Xint, NGINX2Root: https://xint.io/blog/nginx2root-remote-code-execution
- Wiz, NGINX HTTP/2 RCE: https://www.wiz.io/blog/nginx-http2-rce-vulnerabilities
- Calif, Java4Shell: https://calif.io/java4shell
- nginx security advisories: https://nginx.org/en/security_advisories.html
- KISA / KrCERT nginx advisory (2026-11-19): https://www.krcert.or.kr/kr/bbs/view.do?bbsId=B0000133&menuNo=205020&nttId=72314&pageIndex=1
- Oracle Critical Patch Update, November 2026: https://www.oracle.com/security-alerts/cspunov2026.html
- Oracle Java fix releases, November 2026: https://docs.oracle.com/en-us/iaas/releasenotes/java-management/jdk-cspu-november-2026.htm
- CISA alert (2026-11-17): https://www.cisa.gov/news-events/alerts/2026/11/17/critical-java-vulnerability-requires-immediate-patching
- CERT-EU nginx: https://cert.europa.eu/publications/security-advisories/2026-022
- CERT-EU Java: https://www.cert.europa.eu/publications/security-advisories/2026-021/pdf
- SecurityWeek, exploitation attempts (2026-11-19): https://www.securityweek.com/java4shell-exploitation-attempts-begin-as-vendors-rush-out-advisories/
