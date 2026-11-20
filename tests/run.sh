#!/usr/bin/env bash
# Runs every skill's check script against fake binaries. No real servers needed.
#   tests/run.sh
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
CHECK="$ROOT/skills/nginx2root-java4shell/scripts/check.sh"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/bin"

cat > "$TMP/bin/nginx" <<'SH'
#!/bin/sh
case $1 in
  -v) echo "nginx version: ${FAKE_NGINX_V:-nginx/1.24.0}" >&2 ;;
  -V) echo "nginx version: ${FAKE_NGINX_V:-nginx/1.24.0}" >&2; echo "configure arguments: --with-http_v2_module" >&2 ;;
  -T) printf '%s\n' "${FAKE_NGINX_CONF:-}" ;;
esac
SH
cat > "$TMP/bin/java" <<'SH'
#!/bin/sh
echo "openjdk version \"${FAKE_JAVA_V:-21.0.5}\" 2026-10-20 LTS" >&2
echo "OpenJDK Runtime Environment Temurin-${FAKE_JAVA_V:-21.0.5}+11 (build x)" >&2
SH
chmod +x "$TMP/bin/nginx" "$TMP/bin/java"

PASS=0 FAIL=0
run() { PATH="$TMP/bin:$PATH" "$@" bash "$CHECK" --no-containers 2>&1; }
expect() { # name, pattern (grep -E), output
  if printf '%s\n' "$3" | grep -Eq "$2"; then PASS=$((PASS + 1)); else
    FAIL=$((FAIL + 1)); echo "FAIL: $1 (wanted /$2/)"; printf '%s\n' "$3" | sed 's/^/    /'; fi
}
reject() {
  if printf '%s\n' "$3" | grep -Eq "$2"; then FAIL=$((FAIL + 1)); echo "FAIL: $1 (unexpected /$2/)"; printf '%s\n' "$3" | sed 's/^/    /'; else PASS=$((PASS + 1)); fi
}
X86="x86_64:avx512f avx512bw avx512vbmi bmi2 sse2"

CONF='server {
  listen 443 ssl http2;
  listen 443 quic reuseport;
  resolver 1.1.1.1;
  location / { mirror /m; proxy_pass http://$arg_host; }
  # http3 on;
}
mail { auth_http http://127.0.0.1/auth; server { proxy on; } }'

out=$(run env FAKE_NGINX_V=nginx/1.24.0 FAKE_NGINX_CONF="$CONF" CHECK_TEST_CPU="$X86")
expect "old nginx needs patch" '^ACTION	NGX-PATCH	.*1\.24\.0' "$out"
expect "http2 mitigation" '^MITIGATE	NGX-H2-OFF' "$out"
expect "http3 mitigation" '^MITIGATE	NGX-H3-OFF' "$out"
expect "resolver mitigation" '^MITIGATE	NGX-RESOLVER' "$out"
expect "mail mitigation" '^MITIGATE	NGX-MAIL' "$out"
expect "java 21.0.5 on avx512 host" '^ACTION	JAVA-PATCH	.*21\.0\.5' "$out"
expect "java mitigation" '^MITIGATE	JAVA-MITIGATE' "$out"
expect "summary line" '^# summary .*ACTION=2' "$out"

out=$(run env FAKE_NGINX_V=nginx/1.30.7 FAKE_NGINX_CONF="$CONF" FAKE_JAVA_V=21.0.13.1 CHECK_TEST_CPU="$X86")
expect "stable fix ok" '^OK	NGX-PATCH	.*1\.30\.7' "$out"
reject "no mitigation when patched" '^MITIGATE	NGX' "$out"
expect "java fixed ok" '^OK	JAVA-PATCH	.*21\.0\.13\.1' "$out"

out=$(run env FAKE_NGINX_V=nginx/1.31.8 FAKE_NGINX_CONF='server { listen 443 ssl; http2 on; }' CHECK_TEST_CPU="$X86")
expect "mainline 1.31.8 vulnerable" '^ACTION	NGX-PATCH	.*1\.31\.8' "$out"
expect "http2 on directive" '^MITIGATE	NGX-H2-OFF' "$out"

out=$(run env FAKE_NGINX_V=nginx/1.30.6 FAKE_NGINX_CONF='server { listen 443 ssl; # http2 on;
}' CHECK_TEST_CPU="$X86")
expect "1.30.6 vulnerable" '^ACTION	NGX-PATCH	.*1\.30\.6' "$out"
reject "commented http2 ignored" 'NGX-H2-OFF' "$out"

out=$(run env FAKE_NGINX_V=nginx/1.31.9 CHECK_TEST_CPU="$X86")
expect "mainline fix ok" '^OK	NGX-PATCH	.*1\.31\.9' "$out"

out=$(run env FAKE_NGINX_V=openresty/1.25.3.1 FAKE_NGINX_CONF='' CHECK_TEST_CPU="$X86")
expect "openresty vulnerable" '^ACTION	NGX-PATCH	.*OpenResty' "$out"
expect "unreadable config" '^REVIEW	NGX-CONF' "$out"

out=$(run env FAKE_JAVA_V=21.0.5 CHECK_TEST_CPU="arm64:")
expect "arm java is info only" '^INFO	JAVA-PATCH	.*21\.0\.5.*ARM' "$out"
reject "arm java no action" '^ACTION	JAVA' "$out"

out=$(run env FAKE_JAVA_V=21.0.5 CHECK_TEST_CPU="x86_64:avx2 bmi2")
expect "x86 without vbmi is info" '^INFO	JAVA-PATCH	.*missing: avx512f avx512bw avx512vbmi' "$out"

out=$(run env FAKE_JAVA_V=17.0.21.1 CHECK_TEST_CPU="$X86")
expect "java 17 fixed" '^OK	JAVA-PATCH	.*17\.0\.21\.1' "$out"
out=$(run env FAKE_JAVA_V=17.0.5 CHECK_TEST_CPU="$X86")
expect "java 17.0.5 predates" '^OK	JAVA-PATCH	.*predates' "$out"
out=$(run env FAKE_JAVA_V=1.8.0_402 CHECK_TEST_CPU="$X86")
expect "java 8 not affected" '^OK	JAVA-PATCH	.*Java 8 is not affected' "$out"
out=$(run env FAKE_JAVA_V=11.0.25 CHECK_TEST_CPU="$X86")
expect "java 11 not affected" '^OK	JAVA-PATCH	.*11\.0\.25' "$out"
out=$(run env FAKE_JAVA_V=24.0.2 CHECK_TEST_CPU="$X86")
expect "java 24 non-LTS" '^ACTION	JAVA-PATCH	.*non-LTS' "$out"
out=$(run env FAKE_JAVA_V=25.0.5 JAVA_TOOL_OPTIONS=-XX:-UseBASE64Intrinsics CHECK_TEST_CPU="$X86")
expect "java 25.0.5 needs patch" '^ACTION	JAVA-PATCH	.*25\.0\.5.*mitigation flag present' "$out"
reject "mitigated jvm no MITIGATE row" '^MITIGATE	JAVA' "$out"
out=$(run env FAKE_JAVA_V=27.0.1.0.3 CHECK_TEST_CPU="$X86")
expect "java 27.0.1.0.3 vulnerable" '^ACTION	JAVA-PATCH	.*27\.0\.1\.0\.3' "$out"

PATH="$TMP/bin:$PATH" bash "$CHECK" --bogus >/dev/null 2>&1; rc=$?
expect "usage error exit 2" '^2$' "$rc"

echo "passed=$PASS failed=$FAIL"
[ $FAIL = 0 ]
