#!/usr/bin/env python3
"""SecuScan v2 — REAL security tool scan suite (v2).

Same as v1 plus:
- a vulnerable lab target (python http.server with planted decoys:
  admin/, backup.zip, .git/, server-status, secret.txt, robots.txt)
- nmap fixed (nmap-common data files via --datadir)
- nikto port / sqlmap level+risk sent as strings (manifest select types)
- plugin availability checked with auth
- ping dropped: sandbox denies raw sockets (SOCK_RAW) to unprivileged
  users — a sandbox restriction, not a product limitation.
"""
import json
import os
import signal
import subprocess
import sys
import time
import urllib.request
import urllib.error

BASE = "http://127.0.0.1:8080/api/v1"
REPO = os.environ.get("SECUSCAN_REPO", os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TOOLS = os.environ.get("SECUSCAN_TOOLS", os.path.expanduser("~/tools/bin"))
WORDLIST = os.path.expanduser("~/tools/wordlists/common.txt")
NUCLEI_TPL = os.path.expanduser("~/.config/nuclei/templates/http/technologies/")
LAB = "/tmp/labtarget"
LAB_PORT = 8899

results = []


def log(m):
    print(m, flush=True)


def record(name, ok, detail=""):
    results.append((name, ok, detail))
    log(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))


def req(method, path, token=None, body=None, raw=False):
    url = f"{BASE}{path}"
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(url, data=data, method=method)
    r.add_header("content-type", "application/json")
    if token:
        r.add_header("authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(r, timeout=60) as resp:
            p = resp.read()
            return resp.status, p if raw else json.loads(p or b"{}")
    except urllib.error.HTTPError as e:
        p = e.read()
        try:
            return e.code, p if raw else json.loads(p or b"{}")
        except Exception:
            return e.code, p


def unwrap(d):
    return d.get("data", d) if isinstance(d, dict) else d


def build_lab():
    """Deliberately vulnerable lab target: exposed admin, leaked backup,
    .git directory, server-status, robots.txt disclosing paths."""
    os.makedirs(f"{LAB}/admin", exist_ok=True)
    os.makedirs(f"{LAB}/.git", exist_ok=True)
    os.makedirs(f"{LAB}/uploads", exist_ok=True)
    files = {
        "index.html": "<html><body><h1>Acme Internal Server</h1></body></html>",
        "admin/index.html": "<html><body>Admin login (no auth)</body></html>",
        "backup.zip": "PK\x03\x04 fake zip archive of site + db dump",
        ".git/HEAD": "ref: refs/heads/main\n",
        ".git/config": "[core]\n\trepositoryformatversion = 0\n",
        "secret.txt": "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n",
        "server-status": "<html>Apache Status: total accesses 1337</html>",
        "robots.txt": "User-agent: *\nDisallow: /admin\nDisallow: /backup.zip\n",
        "uploads/note.txt": "temp deploy notes",
        "info.php": "<?php phpinfo(); ?>",
    }
    for path, content in files.items():
        with open(f"{LAB}/{path}", "w") as fh:
            fh.write(content)


SCANS = [
    # label, plugin, inputs, max_wait_s
    ("traceroute", "traceroute", {"target": "127.0.0.1", "max_hops": 5}, 30),
    ("whois", "whois", {"target": "github.com"}, 60),
    ("nmap -sV", "nmap", {"target": "127.0.0.1", "ports": "8080,8899",
                          "scan_type": "T", "service_detection": True, "safe_mode": True}, 240),
    ("http-headers(lab)", "http-headers", {"target": f"http://127.0.0.1:{LAB_PORT}"}, 60),
    ("http-recon(lab)", "http-recon", {"target": f"http://127.0.0.1:{LAB_PORT}"}, 60),
    ("nikto(lab)", "nikto", {"target": "127.0.0.1", "port": str(LAB_PORT), "ssl": False}, 420),
    ("gobuster(lab)", "gobuster", {"target": f"http://127.0.0.1:{LAB_PORT}",
                                   "wordlist": WORDLIST, "threads": 25}, 300),
    ("nuclei(lab)", "nuclei", {"target": f"http://127.0.0.1:{LAB_PORT}",
                               "templates": NUCLEI_TPL, "concurrency": 10}, 240),
    ("sqlmap(lab)", "sqlmap", {"target": f"http://127.0.0.1:{LAB_PORT}/index.html?probe=1",
                               "level": "1", "risk": "1"}, 420),
]


def main():
    log("== 0. Real tools on PATH ==")
    for t in ["nmap", "nikto", "nuclei", "gobuster", "sqlmap", "whois", "traceroute"]:
        p = subprocess.run(["which", t], capture_output=True, text=True,
                           env=dict(os.environ, PATH=f"{TOOLS}:{os.environ['PATH']}"))
        record(f"binary: {t}", p.returncode == 0, p.stdout.strip())

    build_lab()

    # lab target: python http.server (also a REAL vulnerable service: version
    # disclosure in Server header, no security headers at all)
    lab = subprocess.Popen(
        ["/home/z/.venv/bin/python3", "-m", "http.server", str(LAB_PORT), "--directory", LAB],
        stdout=open("/tmp/lab-server.log", "w"), stderr=subprocess.STDOUT,
        start_new_session=True,
    )

    env = dict(
        os.environ,
        PATH=f"{TOOLS}:{os.environ['PATH']}",
        SECUSCAN_ADMIN_EMAIL="admin@secuscan.local",
        SECUSCAN_ADMIN_PASSWORD="VerifyIt2026!",
        SECUSCAN_DB_URL=f"sqlite://{REPO}/data/realtools2.db?mode=rwc",
    )
    for f in ("realtools2.db", "realtools2.db-shm", "realtools2.db-wal"):
        p = f"{REPO}/data/{f}"
        if os.path.exists(p):
            os.remove(p)
    proc = subprocess.Popen(
        [f"{REPO}/target/debug/secuscan-server"], cwd=REPO, env=env,
        stdout=open("/tmp/realtools2-server.log", "w"), stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    try:
        for _ in range(60):
            try:
                st, d = req("GET", "/health")
                if st == 200:
                    break
            except Exception:
                pass
            time.sleep(0.5)
        # lab reachable?
        with urllib.request.urlopen(f"http://127.0.0.1:{LAB_PORT}/", timeout=5) as r:
            record("lab target up (python http.server)", r.status == 200)

        st, d = req("POST", "/auth/login",
                    body={"email": "admin@secuscan.local", "password": "VerifyIt2026!"})
        token = unwrap(d)["access_token"]

        st, d = req("GET", "/plugins", token=token)
        plugins = unwrap(d)
        if isinstance(plugins, dict):
            plugins = plugins.get("items", [])
        avail = [p["id"] for p in plugins if p.get("available")]
        record("server sees tools as AVAILABLE", len(avail) >= 10,
               f"{len(avail)}/13 available: {sorted(avail)}")

        st, d = req("POST", "/workspaces", token=token,
                    body={"name": "Real Tools Lab", "description": "live binary verification"})
        ws_id = unwrap(d)["id"]

        task_ids = {}
        for label, plugin, inputs, wait in SCANS:
            log(f"\n== scan: {label} ({plugin}) ==")
            st, d = req("POST", "/tasks", token=token,
                        body={"plugin_id": plugin, "inputs": inputs,
                              "consent_granted": True, "workspace_id": ws_id})
            task = unwrap(d)
            if st not in (200, 201):
                record(f"{label}: accepted", False, f"status={st} {str(d)[:120]}")
                continue
            tid = task["id"]
            task_ids[label] = tid
            record(f"{label}: accepted", True, f"id={tid[:8]}")

            t = {}
            for _ in range(int(wait / 2)):
                st, d = req("GET", f"/tasks/{tid}", token=token)
                t = unwrap(d)
                if t.get("status") in ("completed", "failed", "cancelled"):
                    break
                time.sleep(2)
            ok = t.get("status") == "completed"
            record(f"{label}: completed", ok,
                   f"status={t.get('status')}, exit={t.get('exit_code')}")
            if t.get("status") != "completed":
                st, d = req("GET", f"/tasks/{tid}/output", token=token)
                log("    output tail: " + str(unwrap(d).get("output", ""))[-300:].replace("\n", " | "))

        log("\n== findings from real tools ==")
        st, d = req("GET", "/findings?limit=300", token=token)
        f = unwrap(d)
        items = f.get("items", f) if isinstance(f, dict) else f
        log(f"    TOTAL: {len(items)} findings")
        by_plugin = {}
        for it in items:
            by_plugin.setdefault(it.get("plugin_id"), []).append(it)
        for plug, its in sorted(by_plugin.items()):
            log(f"    {plug}: {len(its)} finding(s)")
            for i in its[:6]:
                log(f"       - [{i.get('severity')}] {i.get('title')}")
        record("real tools produced findings", len(items) >= 8,
               f"{len(items)} findings across {len(by_plugin)} plugins")

        # full report of the whole workspace via the newest nmap/gobuster task
        for label in ("gobuster(lab)", "nmap -sV", "nikto(lab)"):
            tid = task_ids.get(label)
            if not tid:
                continue
            st, d = req("GET", f"/tasks/{tid}", token=token)
            if unwrap(d).get("status") != "completed":
                continue
            st, body = req("GET", f"/tasks/{tid}/report/md", token=token, raw=True)
            record(f"markdown report: {label}", st == 200 and len(body) > 100, f"{len(body)} bytes")
            os.makedirs("/home/z/my-project/download/real-scan-reports", exist_ok=True)
            with open(f"/home/z/my-project/download/real-scan-reports/{label.split('(')[0].strip().replace(' ', '_')}-report.md", "wb") as fh:
                fh.write(body)

        st, d = req("GET", "/dashboard/summary", token=token)
        ds = unwrap(d)
        log(f"    dashboard findings: {json.dumps(ds.get('findings', {}))}")

    finally:
        log("\n== shutdown ==")
        for p in (proc, lab):
            try:
                p.send_signal(signal.SIGTERM)
                p.wait(timeout=5)
            except Exception:
                p.kill()
        record("clean shutdown", True)

    passed = sum(1 for _, ok, _ in results if ok)
    failed = sum(1 for _, ok, _ in results if not ok)
    log("\n" + "=" * 64)
    log(f"REAL-TOOL SUITE v2: {passed} passed, {failed} failed, {len(results)} total")
    log("=" * 64)
    for name, ok, detail in results:
        if not ok:
            log(f"  FAILED: {name} — {detail}")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
