# Compromise checks

Run these when `check.sh` prints `IR-NGINX` or `IR-JAVA`, or when an affected target was internet-facing before it was patched. Read-only until step "Contain".

Facts to keep in mind:
- CVE-2026-123007 uses HTTP/2 control frames. They may never show up in the access log. A clean access log proves nothing.
- A worker crash is not proof of a successful attack. A crash plus an unexpected child process or outbound connection is.
- Base64 decode errors happen in normal traffic. Do not treat them alone as evidence.

## 1. Preserve evidence first

Before restarting or redeploying:

```bash
TS=$(date +%Y%m%d%H%M); D=/root/ir-$TS; sudo mkdir -p $D
sudo cp -a /var/log/nginx $D/ 2>/dev/null
sudo journalctl --since "-14d" --no-pager > $D/journal.txt
ps -eo pid,ppid,user,lstart,args > $D/ps.txt
sudo ss -tanp > $D/ss.txt
sudo coredumpctl list > $D/coredumps.txt 2>&1
# containers: docker logs <id> > $D/<name>.log ; docker diff <id> > $D/<name>.diff
# java: copy hs_err_pid*.log from the service working dir and /tmp
```

## 2. NGINX signals

```bash
sudo grep -Ei 'worker process.*exited|signal 11|segfault' /var/log/nginx/error.log*
ps -eo pid,ppid,user,args | awk '$3 ~ /nginx|www-data/'     # workers must have no shell children
sudo ls -la /proc/$(pgrep -f 'nginx: worker' | head -1)/fd 2>/dev/null | grep -v -E 'socket|log|pipe'
sudo find / -xdev -user www-data -newer /etc/nginx/nginx.conf -type f 2>/dev/null | grep -vE '^/(proc|var/cache|var/lib/nginx)'
sudo ss -tanp | grep nginx | grep -v ':443\|:80'          # outbound connections from nginx
```

Suspicious: `sh`, `bash`, `curl`, `wget`, `python` under an nginx worker; new files owned by the nginx user outside cache dirs; nginx connecting out to unknown IPs; very long HTTP/2 connections with large inbound volume.

## 3. Java signals

```bash
ls -la <service-cwd>/hs_err_pid*.log /tmp/hs_err_pid*.log
journalctl -u <svc> --since "-14d" | grep -Ei 'restart|SIGSEGV|core dumped'
ps -eo pid,ppid,user,args --forest | grep -A3 '[j]ava'     # children of the JVM
sudo ss -tanp | grep java
```

Suspicious: JVM restarts lining up with odd `Authorization`, JWT, SAML or upload requests; child processes of the JVM that the product does not normally start; the service account reading files outside its app dir; new outbound connections.

## 4. If anything is suspicious: contain

1. Restrict network access to the instance (security group, firewall), keep it running for analysis if possible.
2. Review the service account and cloud role of the instance; check cloud audit logs for its credentials.
3. Rotate every secret the process could read: environment variables, config files, DB passwords, API keys, tokens, TLS private keys.
4. Redeploy from a patched, trusted image or a rebuilt host. If host root compromise is possible (nginx RCE plus loadable SCTP), recreating containers is not enough: rebuild the host.
5. Look for lateral movement from this instance to others.

Report what was found, what was preserved, and what was rotated.
