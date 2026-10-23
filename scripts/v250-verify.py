#!/usr/bin/env python3
"""SecuScan v2.5.0 live verification: all 13 tools + new native scanners.

Boots vulnerable lab + SecuScan server with all real binaries on PATH,
runs a mix of native + CLI scans, captures screenshots proving the
catalogue is now full (every CLI scanner AVAILABLE, new native scanners
like dns-lookup / subdomain-finder / cors-check also exposed).
"""
import json, os, signal, subprocess, time, urllib.request, urllib.error
from playwright.sync_api import sync_playwright

BASE = "http://127.0.0.1:8080/api/v1"
REPO = "/home/z/secuscan-v2"
TOOLS = os.path.expanduser("~/tools/bin")
WORDLIST = os.path.expanduser("~/tools/wordlists/common.txt")
LAB = "/tmp/labtarget"
LAB_PORT = 8899
SHOTS = "/home/z/my-project/download/ui-screens/v250"
os.makedirs(SHOTS, exist_ok=True)


def log(m): print(m, flush=True)


def req(method, path, token=None, body=None):
    url = f"{BASE}{path}"
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(url, data=data, method=method)
    r.add_header("content-type", "application/json")
    if token: r.add_header("authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(r, timeout=120) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        try: return e.code, json.loads(e.read() or b"{}")
        except Exception: return e.code, {}


def unwrap(d): return d.get("data", d)


def boot_lab():
    os.makedirs(LAB, exist_ok=True)
    # planted vulns
    for sub in ["admin", "backup", "secret", ".git/objects", "dev"]:
        os.makedirs(os.path.join(LAB, sub), exist_ok=True)
    open(os.path.join(LAB, "index.html"), "w").write("<h1>vulnerable lab</h1>")
    open(os.path.join(LAB, "admin", "index.html"), "w").write("<h1>admin</h1>")
    open(os.path.join(LAB, "backup.zip"), "w").write("PK\x03\x04" + "x" * 200)
    open(os.path.join(LAB, "secret.txt"), "w").write("AKIA-TEST-KEY")
    open(os.path.join(LAB, ".git", "HEAD"), "w").write("ref: refs/heads/main\n")
    open(os.path.join(LAB, "robots.txt"), "w").write("User-agent: *\nDisallow: /admin\n")
    open(os.path.join(LAB, "info.php"), "w").write("<?php phpinfo(); ?>")
    open(os.path.join(LAB, "server-status"), "w").write("Apache Status")
    p = subprocess.Popen(
        ["python3", "-m", "http.server", str(LAB_PORT), "--bind", "127.0.0.1"],
        cwd=LAB, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True)
    time.sleep(1)
    return p


def boot_server():
    env = dict(os.environ)
    env["PATH"] = f"{TOOLS}:{env['PATH']}"
    env["SECUSCAN_DB_URL"] = "sqlite:////home/z/secuscan-v2/data/v250-proof.db"
    env["SECUSCAN_JWT_SECRET"] = "v250-proof-secret-32bytes-long-aaaa"
    env["SECUSSCAN_LISTEN_ADDR"] = "127.0.0.1:8080"
    env["SECUSCAN_LISTEN_ADDR"] = "127.0.0.1:8080"
    env["RUST_LOG"] = "info"
    env["SECUSCAN_ALLOW_REGISTER"] = "true"
    env["SECUSCAN_ADMIN_EMAIL"] = "admin@secuscan.local"
    env["SECUSCAN_ADMIN_PASSWORD"] = "VerifyIt2026!"
    # fresh DB
    try: os.unlink("/home/z/secuscan-v2/data/v250-proof.db")
    except FileNotFoundError: pass
    p = subprocess.Popen(
        [f"{REPO}/target/release/secuscan-server"], cwd=REPO,
        env=env, stdout=open("/tmp/v250_server.log", "w"),
        stderr=subprocess.STDOUT, start_new_session=True)
    # wait for ready
    for _ in range(60):
        try:
            urllib.request.urlopen("http://127.0.0.1:8080/api/v1/auth/login", timeout=1)
        except urllib.error.HTTPError:
            break  # 405 = server up
        except Exception:
            time.sleep(0.5)
    else:
        log("SERVER FAILED TO START"); print(open("/tmp/v250_server.log").read()[-2000:]); raise SystemExit(1)
    log("server up")
    return p


def login():
    s, b = req("POST", "/auth/register", body={
        "email": "admin@secuscan.local", "password": "VerifyIt2026!",
        "name": "Admin"})
    if s not in (200, 201, 409):
        log(f"register status {s}: {b}"); raise SystemExit(1)
    s, b = req("POST", "/auth/login", body={
        "email": "admin@secuscan.local", "password": "VerifyIt2026!"})
    if s != 200:
        log(f"login failed: {s} {b}"); raise SystemExit(1)
    return b.get("access_token") or unwrap(b).get("access_token")


def create_workspace(token):
    s, b = req("POST", "/workspaces", token=token, body={"name": "v250 Proof"})
    if s not in (200, 201):
        log(f"workspace: {s} {b}"); raise SystemExit(1)
    return unwrap(b)["id"]


def get_catalog(token):
    s, b = req("GET", "/plugins", token=token)
    return b.get("items", []) if s == 200 else []


def run_scan(token, workspace_id, plugin_id, target=None, inputs=None, consent=True):
    inp = dict(inputs or {})
    if target is not None: inp["target"] = target
    body = {
        "plugin_id": plugin_id,
        "workspace_id": workspace_id,
        "consent_granted": consent,
        "inputs": inp,
    }
    s, b = req("POST", "/tasks", token=token, body=body)
    if s not in (200, 201):
        log(f"  ! task create failed ({plugin_id}): {s} {b}")
        return None
    task = unwrap(b)
    # poll
    tid = task["id"]
    for _ in range(120):
        time.sleep(1)
        s, b = req("GET", f"/tasks/{tid}", token=token)
        if s == 200:
            t = unwrap(b)
            if t.get("status") in ("completed", "failed", "cancelled"):
                return t
    return None


def main():
    log("=== v2.5.0 verification ===")
    log("tools on PATH: " + ", ".join(sorted(os.listdir(TOOLS))))
    lab = boot_lab()
    try:
        srv = boot_server()
        try:
            token = login()
            ws = create_workspace(token)
            log(f"workspace: {ws}")
            catalog = get_catalog(token)
            log(f"catalogue: {len(catalog)} plugins")
            # show availability
            avail = sum(1 for p in catalog if p.get("available"))
            log(f"available: {avail}/{len(catalog)}")

            # register target
            target_url = f"http://127.0.0.1:{LAB_PORT}"
            s, b = req("POST", f"/workspaces/{ws}/targets", token=token, body={
                "name": target_url, "description": "v250 lab target"})
            log(f"target: {s}")

            # pick a representative mix: native + CLI
            # URL-based tools scan the lab target on port 8899
            # Host-based tools use 127.0.0.1 (recon against localhost)
            # Domain-based tools use example.com
            picks = [
                ("nikto", target_url, {}),
                ("gobuster", target_url, {"wordlist": WORDLIST, "extensions": "php,txt,html,zip"}),
                ("nuclei", target_url, {}),
                ("ffuf", target_url, {"wordlist": WORDLIST}),
                ("sqlmap", target_url, {}),
                ("whatweb", target_url, {}),
                ("cors-check", target_url, {}),
                ("http-headers", target_url, {}),
                ("waf-detect", target_url, {}),
                ("testssl", target_url, {}),
                ("xss-scanner", target_url, {}),
                ("tls-check", target_url, {}),
                ("http-recon", target_url, {}),
                ("vhost-finder", target_url, {}),
                ("password-audit", target_url, {}),
                ("wordpress-audit", target_url, {}),
                # host-based
                ("nmap", "127.0.0.1", {"ports": "8899", "scan_type": "T"}),
                ("port-scanner", "127.0.0.1", {"ports": "8899"}),
                ("ping", "127.0.0.1", {}),
                ("traceroute", "127.0.0.1", {}),
                ("reverse-dns", "127.0.0.1", {}),
                # domain-based
                ("subfinder", "example.com", {}),
                ("dns-lookup", "example.com", {"record_type": "A"}),
                ("email-security", "example.com", {}),
                ("subdomain-finder", "example.com", {}),
                ("whois", "example.com", {}),
                ("google-dorks", "example.com", {}),
            ]
            results = []
            for plugin_id, target, inputs in picks:
                # find plugin in catalog
                meta = next((p for p in catalog if p["id"] == plugin_id), None)
                if not meta:
                    log(f"  SKIP {plugin_id}: not in catalogue")
                    continue
                if not meta.get("available"):
                    log(f"  SKIP {plugin_id}: not available ({meta.get('availability_message','')})")
                    continue
                log(f"  -> {plugin_id} ({target})")
                t = run_scan(token, ws, plugin_id, target=target, inputs=inputs)
                if t:
                    findings = t.get("findings_count", 0) if isinstance(t.get("findings_count"), int) else 0
                    log(f"     status={t.get('status')} findings={findings}")
                    results.append((plugin_id, t.get("status"), findings))
                else:
                    log(f"     TIMEOUT")
                    results.append((plugin_id, "timeout", 0))

            # screenshots via playwright
            log("capturing screenshots…")
            with sync_playwright() as pw:
                b = pw.chromium.launch(headless=True)
                ctx = b.new_context(viewport={"width": 1440, "height": 900})
                ctx.add_init_script(
                    f"localStorage.setItem('secuscan:workspace','{ws}')")
                page = ctx.new_page()
                # log in via the UI form so the in-memory access token gets set
                page.goto("http://127.0.0.1:8080/", wait_until="networkidle", timeout=30000)
                page.fill('input[type="email"]', "admin@secuscan.local")
                page.fill('input[type="password"]', "VerifyIt2026!")
                page.click('button[type="submit"]')
                page.wait_for_url("http://127.0.0.1:8080/", timeout=15000)
                page.wait_for_load_state("networkidle")
                time.sleep(1.5)
                page.screenshot(path=f"{SHOTS}/01_dashboard.png", full_page=False)
                log("  shot: 01_dashboard")
                for path, name in [
                    ("/scanners", "02_scanners"),
                    ("/findings", "03_findings"),
                    ("/tasks", "04_tasks"),
                    ("/targets", "05_targets"),
                ]:
                    page.goto(f"http://127.0.0.1:8080{path}")
                    page.wait_for_load_state("networkidle", timeout=15000)
                    time.sleep(1.5)
                    page.screenshot(path=f"{SHOTS}/{name}.png", full_page=False)
                    log(f"  shot: {name}")
                b.close()

            # count actual findings via the findings endpoint
            s, b = req("GET", "/findings?limit=500", token=token)
            all_findings = b.get("items", []) if s == 200 else []
            log(f"=== SUMMARY ===")
            log(f"plugins in catalogue: {len(catalog)}")
            log(f"available: {avail}/{len(catalog)}")
            log(f"scans executed: {len(results)}")
            ok = sum(1 for _, st, _ in results if st == "completed")
            log(f"  completed: {ok}")
            log(f"  failed/timeout: {len(results) - ok}")
            log(f"total findings in DB: {len(all_findings)}")
            # breakdown by plugin
            by_plugin = {}
            by_severity = {}
            for f in all_findings:
                pid = f.get("plugin_id", "?")
                sev = f.get("severity", "?")
                by_plugin[pid] = by_plugin.get(pid, 0) + 1
                by_severity[sev] = by_severity.get(sev, 0) + 1
            log(f"findings by plugin: {json.dumps(by_plugin, indent=2)}")
            log(f"findings by severity: {json.dumps(by_severity, indent=2)}")

            # also save full catalog JSON for the record
            with open(f"{SHOTS}/catalog.json", "w") as f:
                json.dump(catalog, f, indent=2)

        finally:
            os.killpg(os.getpgid(srv.pid), signal.SIGTERM)
    finally:
        os.killpg(os.getpgid(lab.pid), signal.SIGTERM)


if __name__ == "__main__":
    main()
