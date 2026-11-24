#!/usr/bin/env python3
"""Generate lab/expected/run{1,2,3}.json (ground truth for the scan lab).

Single source of truth for what each lab variant exposes. Stdlib only:
    python3 lab/gen_expected.py          # rewrites lab/expected/*.json
    python3 lab/gen_expected.py --check  # exit 1 if the files on disk are stale

Service fields:
  port, proto      - TCP port actually listening on the container (verified with nmap -p- in run1)
  product, version - what `nmap -sV --version-light` reports for it ("" when nmap cannot name it);
                     checked against real scans of the lab
  actual           - the software really running (informational; differs from product when nmap
                     misidentifies it, e.g. CoreDNS -> "NLnet Labs NSD")
  in_top1000       - false when the port is NOT in nmap's --top-ports 1000 list, i.e. the reference
                     phase-2 scan cannot see it (MQTT 1883, Redis 6379, NATS 4222, ...)
  detections       - intended signature/fingerprint IDs for that endpoint (see lab/README.md)

changes_from_prev kinds (match the `changes` table): host_up, host_down, new, gone, changed, unstable.
Host-level changes use port 0 and proto "". A host that appears/disappears also lists each of its
services as new/gone. `unstable` = host flipped state >= 2 times within the last 5 runs.
"""
import copy
import json
import sys
from pathlib import Path

OUT = Path(__file__).resolve().parent / "expected"
NETWORK = "10.20.0.0/18"
INFRA = {
    "10.20.0.0": "network address, answered by the docker bridge (same MAC as gateway)",
    "10.20.0.1": "docker bridge gateway",
    "10.20.63.251": "RampartEye app (compose.demo.yml)",
}
NOT_TOP1000 = {1883, 4222, 6379, 11211, 33060}


def svc(port, product="", version="", actual="", detections=(), proto="tcp"):
    return {
        "port": port,
        "proto": proto,
        "product": product,
        "version": version,
        "actual": actual,
        "in_top1000": port not in NOT_TOP1000,
        "detections": list(detections),
    }


RUN1 = {
    "10.20.0.10": ("nginx-web", [svc(80, "nginx", "1.27.3", "nginx 1.27.3", ["staging-vhost"])]),
    "10.20.0.11": ("nginx-tls", [
        svc(80, "nginx", "1.27.3", "nginx 1.27.3 (301 -> https)"),
        svc(443, "nginx", "1.27.3", "nginx 1.27.3 TLS", ["tls-self-signed"]),
    ]),
    "10.20.1.20": ("wordpress", [svc(80, "Apache httpd", "2.4.62", "WordPress 6.6.2 on Apache 2.4.62", ["wordpress"])]),
    "10.20.1.21": ("wp-db", [svc(3306, "MariaDB", "11.4.4", "MariaDB 11.4.4")]),
    "10.20.1.30": ("phpmyadmin", [svc(80, "Apache httpd", "2.4.62", "phpMyAdmin 5.2.1 on Apache 2.4.62", ["phpmyadmin"])]),
    "10.20.2.40": ("jenkins", [
        svc(8080, "Jetty", "12.0.16", "Jenkins 2.479.3 (Jetty 12.0.16)", ["jenkins"]),
        svc(50000, "", "", "Jenkins inbound agent (JNLP) port"),
    ]),
    "10.20.3.50": ("grafana", [svc(3000, "Grafana http", "", "Grafana 11.3.0", ["grafana"])]),
    "10.20.4.60": ("tomcat", [svc(8080, "Apache Tomcat", "9.0.97", "Apache Tomcat 9.0.97 + manager app", ["tomcat", "tomcat-manager"])]),
    "10.20.5.70": ("gitea", [
        svc(22, "OpenSSH", "9.7", "OpenSSH 9.7 (gitea image)"),
        svc(3000, "Golang net/http server", "", "Gitea 1.22.3", ["gitea"]),
    ]),
    "10.20.6.80": ("sshd", [svc(22, "OpenSSH", "9.7", "OpenSSH 9.7p1 (alpine 3.20)")]),
    "10.20.7.90": ("mysql", [
        svc(3306, "MySQL", "8.4.3", "MySQL 8.4.3"),
        svc(33060, "MySQL X protocol listener", "", "MySQL 8.4.3 X protocol"),
    ]),
    "10.20.8.100": ("mosquitto", [svc(1883, "", "", "Eclipse Mosquitto 2.0.20 (anonymous allowed)", ["mqtt-anonymous"])]),
    "10.20.9.110": ("admin-app", [svc(80, "nginx", "1.27.3", "nginx 1.27.3 app with /login and /admin", ["login-panel", "admin-panel"])]),
    "10.20.10.120": ("postgres", [svc(5432, "PostgreSQL DB", "16.0 - 16.2", "PostgreSQL 16.6")]),
    "10.20.11.130": ("redis", [svc(6379, "Redis key-value store", "7.4.1", "Redis 7.4.1")]),
    "10.20.12.140": ("nats", [
        svc(4222, "", "", "NATS 2.10.22 client port"),
        svc(8222, "Golang net/http server", "", "NATS 2.10.22 monitoring", ["nats-monitoring"]),
    ]),
    "10.20.16.10": ("bb-http", [svc(80, "", "", "busybox 1.36.1 httpd")]),
    "10.20.16.11": ("bb-http-alt", [svc(8080, "", "", "busybox 1.36.1 httpd")]),
    "10.20.20.20": ("ftp-banner", [svc(21, "vsftpd", "3.0.3", "socat fake banner (vsFTPd 3.0.3)")]),
    "10.20.20.21": ("smtp-banner", [svc(25, "Postfix smtpd", "", "socat fake banner (Postfix)")]),
    "10.20.24.30": ("telnet-iot", [
        svc(23, "BusyBox telnetd", "", "socat fake banner (BusyBox telnetd negotiation + login prompt)"),
        svc(80, "", "", "busybox-extras httpd (router web UI)", ["router-login"]),
    ]),
    "10.20.28.40": ("legacy-ssh", [svc(22, "OpenSSH", "7.4", "socat fake banner (OpenSSH_7.4)")]),
    "10.20.32.50": ("ipcam", [svc(80, "", "", "busybox 1.36.1 httpd (camera page)", ["ip-camera"])]),
    "10.20.36.60": ("memcached", [svc(11211, "Memcached", "1.6.32", "Memcached 1.6.32")]),
    "10.20.40.70": ("apache", [svc(80, "Apache httpd", "2.4.58", "Apache httpd 2.4.58")]),
    "10.20.44.80": ("adminer", [svc(8080, "PHP cli server", "5.5 or later", "Adminer 4.8.1 (PHP 7.4.33)", ["adminer"])]),
    "10.20.48.90": ("coredns", [svc(53, "NLnet Labs NSD", "", "CoreDNS 1.11.3 (nmap misidentifies)")]),
    "10.20.52.100": ("haproxy", [svc(80, "HAProxy http proxy", "2.0.0 or later", "HAProxy 3.0.6", ["haproxy-stats"])]),
    "10.20.56.110": ("web-8443", [svc(8443, "nginx", "1.27.3", "nginx 1.27.3 TLS, expired cert", ["tls-self-signed", "tls-expired"])]),
    "10.20.60.120": ("flappy", [svc(80, "", "", "busybox 1.36.1 httpd (unstable host)")]),
}


def variant(base, drop_hosts=(), add_hosts=None, drop_svcs=(), add_svcs=None, patch=None):
    v = copy.deepcopy(base)
    for ip in drop_hosts:
        del v[ip]
    for ip, entry in (add_hosts or {}).items():
        v[ip] = copy.deepcopy(entry)
    for ip, port in drop_svcs:
        v[ip][1][:] = [s for s in v[ip][1] if s["port"] != port]
    for ip, s in (add_svcs or {}).items():
        v[ip][1].append(copy.deepcopy(s))
        v[ip][1].sort(key=lambda x: x["port"])
    for (ip, port), fields in (patch or {}).items():
        for s in v[ip][1]:
            if s["port"] == port:
                s.update(fields)
    return v


INTRANET = ("intranet", [svc(80, "Apache httpd", "2.4.62", "Apache httpd 2.4.62 (ACME Intranet)")])

RUN2 = variant(
    RUN1,
    drop_hosts=["10.20.60.120", "10.20.36.60"],
    add_hosts={"10.20.58.10": INTRANET},
    drop_svcs=[("10.20.24.30", 23)],
    add_svcs={"10.20.16.10": svc(8000, "", "", "busybox 1.36.1 httpd (second port)")},
    patch={
        ("10.20.40.70", 80): {"version": "2.4.62", "actual": "Apache httpd 2.4.62"},
        ("10.20.28.40", 22): {"version": "8.9p1 Ubuntu 3ubuntu0.10",
                              "actual": "socat fake banner (OpenSSH_8.9p1 Ubuntu-3ubuntu0.10)"},
    },
)

RUN3 = variant(
    RUN2,
    add_hosts={"10.20.60.120": RUN1["10.20.60.120"]},
    patch={
        ("10.20.20.21", 25): {"product": "Exim smtpd", "version": "4.96", "actual": "socat fake banner (Exim 4.96)"},
        ("10.20.0.10", 80): {"version": "1.26.2", "actual": "nginx 1.26.2"},
    },
)

RUNS = [("run1", RUN1), ("run2", RUN2), ("run3", RUN3)]


def ip_key(ip):
    return tuple(int(x) for x in ip.split("."))


def diff(prev, curr, history):
    """history: list of host-sets for all runs up to and including curr (for `unstable`)."""
    ch = []
    if prev is None:
        return ch
    for ip in sorted(set(prev) | set(curr), key=ip_key):
        p = {(s["port"], s["proto"]): s for s in prev.get(ip, ("", []))[1]}
        c = {(s["port"], s["proto"]): s for s in curr.get(ip, ("", []))[1]}
        if ip not in prev:
            ch.append({"kind": "host_up", "ip": ip, "port": 0, "proto": ""})
        if ip not in curr:
            ch.append({"kind": "host_down", "ip": ip, "port": 0, "proto": ""})
        for k in sorted(set(p) | set(c)):
            base = {"ip": ip, "port": k[0], "proto": k[1], "in_top1000": k[0] not in NOT_TOP1000}
            if k not in p:
                ch.append({"kind": "new", **base})
            elif k not in c:
                ch.append({"kind": "gone", **base})
            elif (p[k]["product"], p[k]["version"]) != (c[k]["product"], c[k]["version"]):
                ch.append({"kind": "changed", **base,
                           "old": f'{p[k]["product"]} {p[k]["version"]}'.strip(),
                           "new": f'{c[k]["product"]} {c[k]["version"]}'.strip()})
        # unstable: >= 2 up/down flips within the last 5 runs (inactive_after_misses 3, window 5)
        states = [ip in h for h in history[-5:]]
        flips = sum(1 for a, b in zip(states, states[1:]) if a != b)
        if flips >= 2 and states[-1] != states[-2]:
            ch.append({"kind": "unstable", "ip": ip, "port": 0, "proto": ""})
    return ch


def build():
    docs, prev, history = {}, None, []
    for name, hosts in RUNS:
        history.append(set(hosts))
        docs[name] = {
            "run": name,
            "network": NETWORK,
            "infra": [{"ip": ip, "note": note} for ip, note in INFRA.items()],
            "hosts": [{"ip": ip, "name": hosts[ip][0], "services": hosts[ip][1]}
                      for ip in sorted(hosts, key=ip_key)],
            "changes_from_prev": diff(prev, hosts, history),
        }
        prev = hosts
    return docs


def main():
    check = "--check" in sys.argv
    stale = False
    for name, doc in build().items():
        text = json.dumps(doc, indent=2, ensure_ascii=False) + "\n"
        path = OUT / f"{name}.json"
        if check:
            if not path.exists() or path.read_text() != text:
                print(f"stale: {path}", file=sys.stderr)
                stale = True
        else:
            OUT.mkdir(exist_ok=True)
            path.write_text(text)
            print(f"wrote {path} ({len(doc['hosts'])} hosts, {len(doc['changes_from_prev'])} changes)")
    sys.exit(1 if stale else 0)


if __name__ == "__main__":
    main()
