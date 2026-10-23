#!/usr/bin/env python3
"""Final proof run: real tools -> SecuScan UI, end to end.

Boots the vulnerable lab + SecuScan server with REAL binaries on PATH,
runs nmap/gobuster/nikto scans via the API against the lab, then drives
the React SPA in headless Chromium to capture screenshots showing:
  - scanners page with real tools AVAILABLE (vs old 'Missing binary' shots)
  - findings page populated by real tool output
"""
import json
import os
import signal
import subprocess
import time
import urllib.request
import urllib.error
from playwright.sync_api import sync_playwright

BASE = "http://127.0.0.1:8080/api/v1"
REPO = "/home/z/secuscan-v2"
TOOLS = os.path.expanduser("~/tools/bin")
WORDLIST = os.path.expanduser("~/tools/wordlists/common.txt")
LAB = "/tmp/labtarget"
LAB_PORT = 8899
SHOTS = "/home/z/my-project/download/ui-screens"
os.makedirs(SHOTS, exist_ok=True)


def log(m):
    print(m, flush=True)


def req(method, path, token=None, body=None):
    url = f"{BASE}{path}"
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(url, data=data, method=method)
    r.add_header("content-type", "application/json")
    if token:
        r.add_header("authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(r, timeout=90) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except Exception:
            return e.code, {}


def unwrap(d):
    return d.get("data", d) if isinstance(d, dict) else d


def build_lab():
    os.makedirs(f"{LAB}/admin", exist_ok=True)
    os.makedirs(f"{LAB}/.git", exist_ok=True)
    files = {
        "index.html": "<html><body><h1>Acme Internal Server</h1></body></html>",
        "admin/index.html": "<html><body>Admin login (no auth)</body></html>",
        "backup.zip": "PK\x03\x04 fake zip archive of site + db dump",
        ".git/HEAD": "ref: refs/heads/main\n",
        ".git/config": "[core]\n\trepositoryformatversion = 0\n",
        "secret.txt": "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n",
        "server-status": "<html>Apache Status: total accesses 1337</html>",
        "robots.txt": "User-agent: *\nDisallow: /admin\nDisallow: /backup.zip\n",
        "info.php": "<?php phpinfo(); ?>",
    }
    for path, content in files.items():
        with open(f"{LAB}/{path}", "w") as fh:
            fh.write(content)


def run_scan(token, ws_id, plugin, inputs, label, max_wait):
    st, d = req("POST", "/tasks", token=token,
                body={"plugin_id": plugin, "inputs": inputs,
                      "consent_granted": True, "workspace_id": ws_id})
    if st not in (200, 201):
        log(f"  {label}: submit failed {st} {d}")
        return False
    task_id = unwrap(d).get("id") or unwrap(d).get("task", {}).get("id")
    t0 = time.time()
    while time.time() - t0 < max_wait:
        st, d = req("GET", f"/tasks/{task_id}", token=token)
        status = unwrap(d).get("status", "")
        if status in ("completed", "failed"):
            fd = unwrap(d).get("findings_count", unwrap(d).get("findings", 0))
            log(f"  {label}: {status}, findings={fd} ({time.time()-t0:.0f}s)")
            return status == "completed"
        time.sleep(2)
    log(f"  {label}: TIMEOUT after {max_wait}s")
    return False


def main():
    build_lab()
    lab = subprocess.Popen(
        ["/home/z/.venv/bin/python3", "-m", "http.server", str(LAB_PORT),
         "--directory", LAB],
        stdout=open("/tmp/lab-server.log", "w"), stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    db = "realui"
    env = dict(
        os.environ,
        PATH=f"{TOOLS}:{os.environ['PATH']}",
        SECUSCAN_ADMIN_EMAIL="admin@secuscan.local",
        SECUSCAN_ADMIN_PASSWORD="VerifyIt2026!",
        SECUSCAN_DB_URL=f"sqlite://{REPO}/data/{db}.db?mode=rwc",
    )
    for f in (f"{db}.db", f"{db}.db-shm", f"{db}.db-wal"):
        p = f"{REPO}/data/{f}"
        if os.path.exists(p):
            os.remove(p)
    proc = subprocess.Popen(
        [f"{REPO}/target/debug/secuscan-server"], cwd=REPO, env=env,
        stdout=open("/tmp/realui-server.log", "w"), stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    try:
        for _ in range(60):
            try:
                urllib.request.urlopen(f"{BASE}/health", timeout=2)
                break
            except Exception:
                time.sleep(0.5)

        st, d = req("POST", "/auth/login",
                    body={"email": "admin@secuscan.local",
                          "password": "VerifyIt2026!"})
        token = unwrap(d)["access_token"]

        st, d = req("GET", "/plugins", token=token)
        plugins = unwrap(d)
        if isinstance(plugins, dict):
            plugins = plugins.get("items", [])
        avail = sorted(p["id"] for p in plugins if p.get("available"))
        log(f"AVAILABLE SCANNERS ({len(avail)}/{len(plugins)}): {', '.join(avail)}")

        st, d = req("POST", "/workspaces", token=token,
                    body={"name": "Real Tools Lab",
                          "description": "live binary verification"})
        ws_id = unwrap(d)["id"]
        req("POST", f"/workspaces/{ws_id}/targets", token=token,
            body={"name": "127.0.0.1",
                  "description": "vulnerable lab host (python http.server)"})

        log("== real-tool scans against lab target ==")
        ok = True
        ok &= run_scan(token, ws_id, "nmap",
                       {"target": "127.0.0.1", "ports": "8080,8899",
                        "scan_type": "T", "service_detection": True,
                        "safe_mode": True}, "nmap -sV", 240)
        ok &= run_scan(token, ws_id, "gobuster",
                       {"target": f"http://127.0.0.1:{LAB_PORT}",
                        "wordlist": WORDLIST, "threads": 25},
                       "gobuster", 300)
        ok &= run_scan(token, ws_id, "nikto",
                       {"target": "127.0.0.1", "port": str(LAB_PORT),
                        "ssl": False}, "nikto", 420)

        st, d = req("GET", "/findings", token=token)
        items = unwrap(d)
        if isinstance(items, dict):
            items = items.get("items", [])
        log(f"TOTAL FINDINGS IN DB: {len(items)}")

        log("== browser screenshots (real data) ==")
        with sync_playwright() as p:
            browser = p.chromium.launch()
            ctx = browser.new_context(viewport={"width": 1440, "height": 900})
            # pre-select the "Real Tools Lab" workspace before the app boots
            ctx.add_init_script(
                f"localStorage.setItem('secuscan:workspace', '{ws_id}')")
            page = ctx.new_page()
            page.goto("http://127.0.0.1:8080/", wait_until="networkidle",
                      timeout=30000)
            page.fill('input[type="email"]', "admin@secuscan.local")
            page.fill('input[type="password"]', "VerifyIt2026!")
            page.click('button[type="submit"]')
            page.wait_for_url("http://127.0.0.1:8080/", timeout=15000)
            page.wait_for_load_state("networkidle")
            time.sleep(1.5)
            page.screenshot(path=f"{SHOTS}/6-dashboard-realtools.png")

            page.goto("http://127.0.0.1:8080/scanners",
                      wait_until="networkidle")
            time.sleep(1)
            page.screenshot(path=f"{SHOTS}/7-scanners-realtools.png",
                            full_page=True)
            body = page.inner_text("body")
            nmap_idx = body.lower().find("nmap")
            log("scanners page: nmap card present: " + str(nmap_idx >= 0))
            log("scanners page: missing-binary mentions: " +
                str(body.lower().count("missing binary")))

            page.goto("http://127.0.0.1:8080/findings",
                      wait_until="networkidle")
            time.sleep(1)
            page.screenshot(path=f"{SHOTS}/8-findings-realtools.png",
                            full_page=True)
            body = page.inner_text("body")
            log("findings page shows count row: " +
                str([ln for ln in body.splitlines() if "finding" in ln.lower()][:2]))

            page.goto("http://127.0.0.1:8080/tasks",
                      wait_until="networkidle")
            time.sleep(1)
            page.screenshot(path=f"{SHOTS}/10-tasks-realtools.png",
                            full_page=True)
            body = page.inner_text("body")
            for needle in ["nmap", "gobuster", "nikto", "completed"]:
                log(f"tasks page mentions {needle}: " +
                    str(needle in body.lower()))

            page.goto("http://127.0.0.1:8080/targets",
                      wait_until="networkidle")
            time.sleep(1)
            page.screenshot(path=f"{SHOTS}/9-targets-realtools.png")
            browser.close()
        log(f"SCANS OK: {ok}")
        log("DONE")
    finally:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
        lab.send_signal(signal.SIGTERM)
        try:
            lab.wait(timeout=5)
        except Exception:
            lab.kill()


if __name__ == "__main__":
    main()
