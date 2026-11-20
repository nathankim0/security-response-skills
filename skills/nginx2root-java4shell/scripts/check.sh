#!/usr/bin/env bash
# Quick, read-only exposure check for NGINX2Root (CVE-2026-123007, -123633,
# -121810, -123634, -113425), Java4Shell (CVE-2026-114938) and the Linux SCTP
# privilege escalation published with NGINX2Root.
#
# It changes nothing. It only runs version commands, `nginx -T`, reads /proc,
# package changelogs and logs.
#
# Output: one finding per line, tab separated:
#   STATUS  ACTION_ID  TARGET  DETAIL
# STATUS is one of:
#   ACTION    a fix is needed (see references/remediation.md#<ACTION_ID>)
#   MITIGATE  a temporary mitigation applies while ACTION is not done yet
#   REVIEW    the script could not decide; a human or agent must confirm
#   OK        checked and not affected
#   INFO      context only
# Lines starting with '#' are comments. The last line is a summary.
#
# Usage:
#   check.sh [--probe HOST[:PORT]]... [--no-containers] [--k8s]
#   ssh host 'sudo bash -s' < check.sh          # remote host
#
# Exit code: 0 nothing to do, 1 ACTION or MITIGATE found, 2 usage error.

set -u
SCRIPT_VERSION="1.0.0"

usage() {
  if [ -f "$0" ]; then sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'
  else echo "usage: check.sh [--probe HOST[:PORT]]... [--no-containers] [--k8s]"; fi
}

PROBES=""
CONTAINERS=1
K8S=0
while [ $# -gt 0 ]; do
  case $1 in
    --probe) [ $# -ge 2 ] || { usage >&2; exit 2; }; PROBES="$PROBES $2"; shift 2 ;;
    --no-containers) CONTAINERS=0; shift ;;
    --k8s) K8S=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

HOST=$(hostname 2>/dev/null || uname -n)
OS=$(uname -s)
ARCH=$(uname -m)
SUDO=""
if [ "$(id -u)" != 0 ] && command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
  SUDO="sudo -n"
fi

emit() { printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4"; }

# ver_ge A B: true when dotted version A >= B (non-numeric suffixes ignored).
ver_ge() {
  local i x y
  local -a a b
  IFS=. read -ra a <<< "$1"
  IFS=. read -ra b <<< "$2"
  i=0
  while [ $i -lt ${#a[@]} ] || [ $i -lt ${#b[@]} ]; do
    x=${a[$i]:-0}; y=${b[$i]:-0}
    x=${x%%[!0-9]*}; y=${y%%[!0-9]*}
    x=${x:-0}; y=${y:-0}
    [ $((10#$x)) -gt $((10#$y)) ] && return 0
    [ $((10#$x)) -lt $((10#$y)) ] && return 1
    i=$((i + 1))
  done
  return 0
}

# rx runs a command on the current target: the host, a Docker container (CID),
# or the mount namespace of a process from another container runtime (NSPID).
CID=""
NSPID=""
DOCKER="docker"
rx() {
  if [ -n "$CID" ]; then $DOCKER exec "$CID" "$@"
  elif [ -n "$NSPID" ]; then $SUDO nsenter -t "$NSPID" -m -p -- "$@"
  else "$@"; fi
}
rxs() { if [ -n "$CID" ] || [ -n "$NSPID" ]; then rx "$@"; else $SUDO "$@"; fi; }

# Processes in another mount namespace belong to containers. They are checked
# through Docker or nsenter, never with host paths.
MYNS=$(readlink /proc/$$/ns/mnt 2>/dev/null)
FOREIGN=""      # "pid:kind" entries found in other mount namespaces
COVERED_NS=""   # mount namespaces already checked through docker exec
is_foreign() { # $1 pid
  local ns
  [ -n "$MYNS" ] || return 1
  ns=$($SUDO readlink "/proc/$1/ns/mnt" 2>/dev/null) || return 1
  [ "$ns" != "$MYNS" ]
}

# True when the installed distro package changelog mentions the CVE (backported fix).
pkg_has_fix() { # $1 = CVE id, $2 = package name pattern
  rx sh -c "for f in /usr/share/doc/$2/changelog.Debian.gz; do [ -f \"\$f\" ] && zcat \"\$f\"; done 2>/dev/null;
            command -v rpm >/dev/null 2>&1 && rpm -qa --changelog '$2' 2>/dev/null;
            command -v apk >/dev/null 2>&1 && apk info -a '$2' 2>/dev/null" 2>/dev/null | grep -q "$1"
}

# ---------------------------------------------------------------- CPU (Java4Shell gate)
CPU_VULN=0
CPU_DETAIL=""
cpu_check() {
  local flags="" missing="" f
  # Test hook: CHECK_TEST_CPU="x86_64:flag flag ..." overrides arch and flags.
  if [ -n "${CHECK_TEST_CPU:-}" ]; then
    ARCH=${CHECK_TEST_CPU%%:*}; flags=$(printf '%s\n' ${CHECK_TEST_CPU#*:})
  fi
  case $ARCH in
    aarch64|arm64|armv*) CPU_DETAIL="arch=$ARCH (ARM, Java4Shell path not reachable)"; return ;;
  esac
  if [ -n "$flags" ]; then
    :
  elif [ -r /proc/cpuinfo ]; then
    flags=$(grep -m1 '^flags' /proc/cpuinfo | tr ' ' '\n')
  elif [ "$OS" = Darwin ]; then
    flags=$(sysctl -n machdep.cpu.features machdep.cpu.leaf7_features 2>/dev/null | tr ' A-Z' '\na-z' | sed 's/\.//g')
  fi
  for f in avx512f avx512bw avx512vbmi bmi2; do
    printf '%s\n' "$flags" | grep -qx "$f" || missing="$missing $f"
  done
  if [ -z "$missing" ]; then
    CPU_VULN=1; CPU_DETAIL="arch=$ARCH has avx512f avx512bw avx512vbmi bmi2"
  else
    CPU_DETAIL="arch=$ARCH missing:$missing"
  fi
}

# ---------------------------------------------------------------- NGINX
nginx_logs_check() { # $1 target label, $2 config text
  local target=$1 conf=$2 logs hits=0 f n
  if [ -n "$CID" ]; then
    hits=$($DOCKER logs --since 168h "$CID" 2>&1 | grep -Eci 'exited on signal (6|11)|signal 11|segfault')
  elif [ -n "$NSPID" ]; then
    hits=$($SUDO grep -Eci 'exited on signal (6|11)|signal 11|segfault' "/proc/$NSPID/root/var/log/nginx/error.log" 2>/dev/null)
  else
    logs=$(printf '%s\n' "$conf" | sed 's/#.*//' | awk '$1=="error_log"{gsub(";","",$2); print $2}' | sort -u)
    for f in /var/log/nginx/error.log $logs; do
      [ -f "$f" ] || continue
      n=$($SUDO grep -Eci 'exited on signal (6|11)|signal 11|segfault' "$f" 2>/dev/null)
      hits=$((hits + ${n:-0}))
    done
    if command -v journalctl >/dev/null 2>&1; then
      n=$($SUDO journalctl -k --since "-7d" --no-pager 2>/dev/null | grep -ci 'nginx.*segfault')
      hits=$((hits + ${n:-0}))
    fi
  fi
  if [ "${hits:-0}" -gt 0 ]; then
    emit REVIEW IR-NGINX "$target" "$hits worker crash lines (signal 11/6, segfault) in error log or kernel log; investigate before closing"
  fi
}

nginx_check() { # $1 target label, $2 binary
  local target=$1 bin=$2 vout ver core vuln=1 conf clean pkgnote=""
  vout=$(rx "$bin" -v 2>&1) || true
  [ -n "$vout" ] || return 0
  ver=$(printf '%s' "$vout" | sed -n 's/.*\/\([0-9][0-9.]*\).*/\1/p' | head -1)
  core=$(printf '%s' "$ver" | cut -d. -f1-3)

  if printf '%s' "$vout" | grep -qi 'plus'; then
    emit REVIEW NGX-PATCH "$target" "NGINX Plus ($vout): compare with the F5 fixed build for your branch (e.g. 37.0.8.1, 37.3.0.1)"
  elif printf '%s' "$vout" | grep -qi 'tengine'; then
    emit REVIEW NGX-PATCH "$target" "Tengine ($vout): check the vendor advisory for the NGINX2Root fixes"
  elif [ -z "$core" ]; then
    emit REVIEW NGX-PATCH "$target" "could not parse version from: $vout"
  elif ver_ge "$core" 1.31.9; then
    vuln=0; emit OK NGX-PATCH "$target" "nginx $ver >= 1.31.9 (mainline fix)"
  elif [ "$(printf '%s' "$core" | cut -d. -f1-2)" = 1.30 ] && ver_ge "$core" 1.30.7; then
    vuln=0; emit OK NGX-PATCH "$target" "nginx $ver >= 1.30.7 (stable fix)"
  elif pkg_has_fix CVE-2026-123007 'nginx*'; then
    vuln=0; emit OK NGX-PATCH "$target" "nginx $ver, distro package changelog lists CVE-2026-123007 (backported fix)"
  else
    case $vout in *openresty*) pkgnote=" (OpenResty: core $core)" ;; esac
    emit ACTION NGX-PATCH "$target" "nginx $ver$pkgnote is in the affected range and no backported fix was found"
  fi

  conf=$(rxs "$bin" -T 2>/dev/null)
  if [ -z "$conf" ]; then
    [ $vuln = 1 ] && emit REVIEW NGX-CONF "$target" "could not read config with '$bin -T' (run as root); protocol and module exposure unknown"
    nginx_logs_check "$target" ""
    return 0
  fi
  clean=$(printf '%s\n' "$conf" | sed 's/#.*//')

  if [ $vuln = 1 ]; then
    if printf '%s\n' "$clean" | grep -Eq '(^|[[:space:]])listen[[:space:]][^;]*[[:space:]]http2([[:space:];]|$)|(^|[[:space:];{])http2[[:space:]]+on[[:space:]]*;'; then
      emit MITIGATE NGX-H2-OFF "$target" "HTTP/2 enabled (CVE-2026-123007, CVE-2026-123633)"
    fi
    if printf '%s\n' "$clean" | grep -Eq '(^|[[:space:]])listen[[:space:]][^;]*[[:space:]]quic([[:space:];]|$)|(^|[[:space:];{])http3[[:space:]]+on[[:space:]]*;'; then
      emit MITIGATE NGX-H3-OFF "$target" "HTTP/3 or QUIC listener (CVE-2026-121810)"
    fi
    if printf '%s\n' "$clean" | grep -Eq '(^|[[:space:];{])resolver[[:space:]]'; then
      if printf '%s\n' "$clean" | grep -Eq '(^|[[:space:];{])(mirror[[:space:]]+[^o]|ssi[[:space:]]+on)|proxy_pass[[:space:]][^;]*\$'; then
        emit MITIGATE NGX-RESOLVER "$target" "resolver with mirror/SSI subrequests or a variable proxy_pass (CVE-2026-123634)"
      else
        emit INFO NGX-RESOLVER "$target" "resolver configured without mirror/SSI/variable proxy_pass; patch still required"
      fi
    fi
    if printf '%s\n' "$clean" | grep -Eq '(^|[[:space:];{])auth_http[[:space:]]' && printf '%s\n' "$clean" | grep -Eq '(^|[[:space:];{])proxy[[:space:]]+on[[:space:]]*;'; then
      emit MITIGATE NGX-MAIL "$target" "mail proxy with auth_http and proxy on (CVE-2026-113425)"
    fi
  fi
  nginx_logs_check "$target" "$conf"
}

nginx_host() {
  local bins="" b pid exe
  b=$(command -v nginx 2>/dev/null) && bins="$b"
  for b in /usr/sbin/nginx /usr/local/sbin/nginx /usr/local/nginx/sbin/nginx /usr/local/openresty/nginx/sbin/nginx /opt/homebrew/bin/nginx; do
    [ -x "$b" ] && bins="$bins $b"
  done
  if [ -d /proc ]; then
    for pid in $(pgrep -f '^nginx: master' 2>/dev/null); do
      if is_foreign "$pid"; then FOREIGN="$FOREIGN $pid:nginx"; continue; fi
      exe=$($SUDO readlink "/proc/$pid/exe" 2>/dev/null) || continue
      case $exe in
        *" (deleted)")
          emit ACTION NGX-RESTART "$HOST:pid $pid" "running nginx master uses a replaced binary ($exe); restart to load the installed one" ;;
        *) bins="$bins $exe" ;;
      esac
    done
  fi
  bins=$(printf '%s\n' $bins | awk 'NF && !seen[$0]++')
  [ -n "$bins" ] || { emit INFO NGX-PATCH "$HOST" "no nginx binary found on host"; return 0; }
  for b in $bins; do
    nginx_check "$HOST:$b" "$b"
  done
}

# ---------------------------------------------------------------- Java
java_fixed_for() { # prints the fixed version for a vulnerable family, or nothing
  case $1 in
    17) echo 17.0.21.1 ;; 21) echo 21.0.13.1 ;; 25) echo 25.0.5.1 ;; 27) echo 27.0.1.1 ;;
  esac
}

java_eval() { # $1 target, $2 `java -version` output, $3 command line + env text, $4 dirs to scan for hs_err logs
  local target=$1 vout=$2 opts=$3 dirs=${4:-} ver major fixed state mitig="" vendor hs
  ver=$(printf '%s' "$vout" | sed -n 's/.*version "\([^"]*\)".*/\1/p' | head -1)
  vendor=$(printf '%s' "$vout" | sed -n '2p' | sed 's/ (build.*//' | cut -c1-60)
  [ -n "$ver" ] || { emit REVIEW JAVA-PATCH "$target" "could not parse java version"; return; }
  major=${ver%%.*}
  [ "$major" = 1 ] && major=$(printf '%s' "$ver" | cut -d. -f2)
  major=${major%%[!0-9]*}

  state=""
  if [ "$major" = 8 ]; then
    if printf '%s' "$vout" | grep -qi 'perf'; then
      emit REVIEW JAVA-PATCH "$target" "Java $ver looks like Oracle Java 8 Enterprise Performance Pack; fixed in 8u513-perf"
    else
      emit OK JAVA-PATCH "$target" "Java $ver ($vendor): Java 8 is not affected by CVE-2026-114938"
    fi
    return
  elif [ "${major:-0}" -le 16 ]; then
    emit OK JAVA-PATCH "$target" "Java $ver ($vendor): not affected by CVE-2026-114938"
    return
  elif [ "$major" -gt 27 ]; then
    emit OK JAVA-PATCH "$target" "Java $ver: newer than the affected families"
    return
  fi
  fixed=$(java_fixed_for "$major")
  if [ -n "$fixed" ] && ver_ge "$ver" "$fixed"; then
    emit OK JAVA-PATCH "$target" "Java $ver ($vendor) >= $fixed"
    return
  fi
  if [ "$major" = 17 ] && ! ver_ge "$ver" 17.0.6; then
    emit OK JAVA-PATCH "$target" "Java $ver predates the affected 17.0.6+ builds (still outdated; update on normal cycle)"
    return
  fi
  [ -n "$fixed" ] && state="below fixed $fixed" || state="non-LTS release with no fix; move to a patched LTS"

  if printf '%s' "$opts" | grep -Eq -- '-XX:-UseBASE64Intrinsics|-XX:UseAVX=[0-2]([^0-9]|$)'; then
    mitig=" (temporary mitigation flag present)"
  fi
  if [ $CPU_VULN = 1 ]; then
    emit ACTION JAVA-PATCH "$target" "Java $ver ($vendor) $state; CPU has AVX-512 VBMI$mitig"
    [ -z "$mitig" ] && emit MITIGATE JAVA-MITIGATE "$target" "no -XX:-UseBASE64Intrinsics on this JVM"
  else
    emit INFO JAVA-PATCH "$target" "Java $ver $state, but $CPU_DETAIL; patch on the normal cycle and recheck if the VM moves to another CPU type"
  fi

  if [ -n "$dirs" ]; then
    # shellcheck disable=SC2086
    hs=$($SUDO find $dirs -maxdepth 1 -name 'hs_err_pid*.log' -mtime -14 2>/dev/null | head -5 | tr '\n' ' ')
    [ -n "$hs" ] && emit REVIEW IR-JAVA "$target" "recent JVM crash logs: $hs"
  fi
}

proc_opts() { # command line plus JVM option env vars of a process
  printf '%s %s' "$($SUDO tr '\0' ' ' < "/proc/$1/cmdline" 2>/dev/null)" \
    "$($SUDO tr '\0' '\n' < "/proc/$1/environ" 2>/dev/null | grep -E '^(JAVA_TOOL_OPTIONS|JDK_JAVA_OPTIONS|_JAVA_OPTIONS)=' | tr '\n' ' ')"
}

java_host() {
  local pid exe vout opts cwd seen="" found=0 pj
  if [ -d /proc ] && [ "$OS" = Linux ]; then
    for pid in $(pgrep -x java 2>/dev/null; pgrep -f '/bin/java( |$)' 2>/dev/null); do
      case " $seen " in *" $pid "*) continue ;; esac
      seen="$seen $pid"
      if is_foreign "$pid"; then FOREIGN="$FOREIGN $pid:java"; continue; fi
      found=1
      exe=$($SUDO readlink "/proc/$pid/exe" 2>/dev/null) || continue
      exe=${exe% (deleted)}
      [ -x "$exe" ] || { emit REVIEW JAVA-PATCH "$HOST:pid $pid" "JVM binary $exe is gone (replaced?); check with: jcmd $pid VM.version"; continue; }
      vout=$("$exe" -version 2>&1)
      cwd=$($SUDO readlink "/proc/$pid/cwd" 2>/dev/null)
      java_eval "$HOST:pid $pid ($exe)" "$vout" "$(proc_opts "$pid")" "$cwd /tmp"
    done
  else
    for pid in $(pgrep -x java 2>/dev/null); do
      opts=$(ps -o args= -p "$pid" 2>/dev/null)
      exe=${opts%% *}
      [ -x "$exe" ] || exe=java
      java_eval "$HOST:pid $pid ($exe)" "$("$exe" -version 2>&1)" "$opts" ""
      found=1
    done
  fi
  pj=$(command -v java 2>/dev/null)
  if [ -n "$pj" ] && vout=$(java -version 2>&1) && printf '%s' "$vout" | grep -q 'version "'; then
    java_eval "$HOST:PATH java ($pj)" "$vout" "${JAVA_TOOL_OPTIONS:-} ${JDK_JAVA_OPTIONS:-}" ""
    found=1
  fi
  [ $found = 1 ] || emit INFO JAVA-PATCH "$HOST" "no Java runtime found on host (outside containers)"
}

# ---------------------------------------------------------------- containers
containers_check() {
  local id image name label jbin vout opts hs ns
  command -v docker >/dev/null 2>&1 || return 0
  if ! docker ps -q >/dev/null 2>&1; then
    if [ -n "$SUDO" ] && $SUDO docker ps -q >/dev/null 2>&1; then DOCKER="$SUDO docker"; else
      emit REVIEW CONTAINERS "$HOST" "docker CLI found but the daemon is not reachable (not running or no permission); containers not checked"
      return 0
    fi
  fi
  while read -r id image name; do
    [ -n "$id" ] || continue
    CID=$id
    ns=$($SUDO readlink "/proc/$($DOCKER inspect -f '{{.State.Pid}}' "$id" 2>/dev/null)/ns/mnt" 2>/dev/null) && COVERED_NS="$COVERED_NS $ns"
    label="$HOST:docker:$name ($image)"
    if $DOCKER exec "$id" nginx -v >/dev/null 2>&1; then
      nginx_check "$label" nginx
    elif $DOCKER exec "$id" /usr/local/openresty/nginx/sbin/nginx -v >/dev/null 2>&1; then
      nginx_check "$label" /usr/local/openresty/nginx/sbin/nginx
    fi
    jbin=""
    if $DOCKER exec "$id" java -version >/dev/null 2>&1; then
      jbin=java
    else
      jbin=$($DOCKER top "$id" -eo args 2>/dev/null | awk 'NR>1 && $1 ~ /(^|\/)java$/ {print $1; exit}')
    fi
    if [ -n "$jbin" ]; then
      vout=$($DOCKER exec "$id" "$jbin" -version 2>&1)
      opts="$($DOCKER top "$id" -eo args 2>/dev/null | grep -E '(^|/)java ' | tr '\n' ' ') $($DOCKER inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$id" 2>/dev/null | grep -E '^(JAVA_TOOL_OPTIONS|JDK_JAVA_OPTIONS|_JAVA_OPTIONS)=' | tr '\n' ' ')"
      java_eval "$label" "$vout" "$opts" ""
      hs=$($DOCKER exec "$id" sh -c 'ls /tmp/hs_err_pid*.log hs_err_pid*.log 2>/dev/null' 2>/dev/null | head -5 | tr '\n' ' ')
      [ -n "$hs" ] && emit REVIEW IR-JAVA "$label" "JVM crash logs in container: $hs"
    fi
    CID=""
  done <<EOF_PS
$($DOCKER ps --format '{{.ID}} {{.Image}} {{.Names}}' 2>/dev/null)
EOF_PS
}

# Container processes not reachable through Docker (containerd, CRI-O, podman, k8s nodes).
foreign_check() {
  local entry pid kind ns ctr label exe seen_ns=""
  for entry in $FOREIGN; do
    pid=${entry%%:*}; kind=${entry#*:}
    ns=$($SUDO readlink "/proc/$pid/ns/mnt" 2>/dev/null) || continue
    case " $COVERED_NS " in *" $ns "*) continue ;; esac
    ctr=$($SUDO grep -oE '[0-9a-f]{64}' "/proc/$pid/cgroup" 2>/dev/null | head -1 | cut -c1-12)
    exe=$($SUDO readlink "/proc/$pid/exe" 2>/dev/null); exe=${exe% (deleted)}
    label="$HOST:container ${ctr:-?} pid $pid ($exe)"
    if [ "$(id -u)" != 0 ] && [ -z "$SUDO" ] || ! command -v nsenter >/dev/null 2>&1; then
      emit REVIEW CONTAINERS "$label" "$kind runs in a container this user cannot enter; rerun as root (needs nsenter)"
      continue
    fi
    NSPID=$pid
    case $kind in
      nginx)
        case " $seen_ns " in *" $ns "*) ;; *) nginx_check "$label" "$exe" ;; esac
        seen_ns="$seen_ns $ns" ;;
      java)
        java_eval "$label" "$(rx "$exe" -version 2>&1)" "$(proc_opts "$pid")" "/proc/$pid/root/tmp" ;;
    esac
    NSPID=""
  done
}

# ---------------------------------------------------------------- Kubernetes
k8s_check() {
  local imgs
  command -v kubectl >/dev/null 2>&1 || { emit REVIEW K8S "$HOST" "--k8s given but kubectl not found"; return; }
  imgs=$(kubectl get pods -A -o jsonpath='{range .items[*]}{range .spec.containers[*]}{.image}{"\n"}{end}{end}' 2>/dev/null | grep -Ei 'nginx|openresty|ingress' | sort -u | tr '\n' ' ')
  if [ -n "$imgs" ]; then
    emit REVIEW NGX-PATCH "k8s:$(kubectl config current-context 2>/dev/null)" "nginx-based images running: $imgs; map each to its bundled nginx version"
  else
    emit INFO NGX-PATCH "k8s:$(kubectl config current-context 2>/dev/null)" "no nginx/ingress images found in running pods"
  fi
}

# ---------------------------------------------------------------- Linux SCTP
sctp_check() {
  local kver blocked=0 target
  [ "$OS" = Linux ] || { emit INFO KRN-SCTP "$HOST" "not Linux ($OS); SCTP kernel issue does not apply"; return; }
  kver=$(uname -r); target="$HOST:kernel $kver"
  if [ -f /.dockerenv ] || grep -qaE '(docker|containerd|kubepods)' /proc/1/cgroup 2>/dev/null; then
    emit REVIEW KRN-SCTP "$target" "running inside a container; run this check on the host kernel"
    return
  fi
  if grep -rEqs '^[[:space:]]*install[[:space:]]+sctp[[:space:]]+/bin/(false|true)' /etc/modprobe.d /usr/lib/modprobe.d /lib/modprobe.d; then
    blocked=1
  fi
  if grep -q '^sctp ' /proc/modules 2>/dev/null; then
    emit ACTION KRN-SCTP "$target" "sctp module is loaded$( [ $blocked = 1 ] && echo ' (blocked for future loads, still resident)'); confirm nothing uses it, then unload"
  elif grep -qs '/sctp\.ko' "/lib/modules/$kver/modules.builtin"; then
    emit REVIEW KRN-SCTP "$target" "SCTP is built into the kernel; modprobe block cannot apply, needs a vendor kernel fix"
  elif [ $blocked = 1 ]; then
    emit OK KRN-SCTP "$target" "sctp module load blocked via modprobe.d"
  elif modinfo sctp >/dev/null 2>&1 || find "/lib/modules/$kver" -name 'sctp.ko*' 2>/dev/null | grep -q .; then
    emit ACTION KRN-SCTP "$target" "sctp module can be autoloaded; block it unless SCTP is in use"
  else
    emit OK KRN-SCTP "$target" "no sctp module available for this kernel"
  fi
}

# ---------------------------------------------------------------- external probes
probe_check() {
  local p hostpart port alpn altsvc
  for p in $PROBES; do
    hostpart=${p%%:*}; port=${p##*:}; [ "$port" = "$p" ] && port=443
    alpn=$(openssl s_client -connect "$hostpart:$port" -servername "$hostpart" -alpn h2 </dev/null 2>&1 | grep 'ALPN protocol')
    case $alpn in
      *h2*) emit INFO PROBE "$hostpart:$port" "negotiates HTTP/2 (this may be a CDN or load balancer, not the origin nginx)" ;;
      "") emit REVIEW PROBE "$hostpart:$port" "TLS probe failed or no ALPN" ;;
      *) emit INFO PROBE "$hostpart:$port" "no HTTP/2 negotiated ($alpn)" ;;
    esac
    altsvc=$(curl -sS -o /dev/null -D - --max-time 8 "https://$hostpart:$port/" 2>/dev/null | grep -i '^alt-svc:.*h3')
    [ -n "$altsvc" ] && emit INFO PROBE "$hostpart:$port" "advertises HTTP/3: $(printf '%s' "$altsvc" | tr -d '\r')"
  done
}

# ---------------------------------------------------------------- run
OUT=$(
  echo "# nginx2root-java4shell check v$SCRIPT_VERSION host=$HOST os=$OS arch=$ARCH date=$(date -u +%Y-%m-%dT%H:%M:%SZ) root=$([ "$(id -u)" = 0 ] || [ -n "$SUDO" ] && echo yes || echo no)"
  printf 'STATUS\tID\tTARGET\tDETAIL\n'
  cpu_check
  emit INFO CPU "$HOST" "$CPU_DETAIL"
  nginx_host
  java_host
  [ $CONTAINERS = 1 ] && containers_check
  [ $CONTAINERS = 1 ] && foreign_check
  [ $K8S = 1 ] && k8s_check
  sctp_check
  [ -n "$PROBES" ] && probe_check
  true
)
printf '%s\n' "$OUT"
count() { printf '%s\n' "$OUT" | grep -c "^$1	"; }
A=$(count ACTION) M=$(count MITIGATE) R=$(count REVIEW) K=$(count OK) I=$(count INFO)
echo "# summary host=$HOST ACTION=$A MITIGATE=$M REVIEW=$R OK=$K INFO=$I"
[ "$A" -gt 0 ] || [ "$M" -gt 0 ] && exit 1
exit 0
