#!/usr/bin/env python3
"""SecuScan v3.1.0 live verification — Sniper, People Hunter, VPN profiles."""
import json, os, signal, subprocess, time, urllib.request, urllib.error

BASE = "http://127.0.0.1:8080/api/v1"
REPO = "/home/z/secuscan-v2"


def log(m): print(m, flush=True)


def req(method, path, token=None, body=None):
    url = f"{BASE}{path}"
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(url, data=data, method=method)
    r.add_header("content-type", "application/json")
    if token: r.add_header("authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(r, timeout=180) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        try: return e.code, json.loads(e.read() or b"{}")
        except: return e.code, {}


def boot_server():
    env = dict(os.environ)
    env["SECUSCAN_DB_URL"] = "sqlite:////home/z/secuscan-v2/data/v310-proof.db"
    env["SECUSCAN_JWT_SECRET"] = "v310-proof-secret-32bytes-long-aaaa"
    env["SECUSCAN_ADDR"] = "127.0.0.1:8080"
    env["SECUSCAN_ADMIN_EMAIL"] = "admin@secuscan.local"
    env["SECUSCAN_ADMIN_PASSWORD"] = "VerifyIt2026!"
    env["RUST_LOG"] = "info"
    try:
        for suffix in ["", "-wal", "-shm"]:
            try: os.unlink(f"/home/z/secuscan-v2/data/v310-proof.db{suffix}")
            except FileNotFoundError: pass
    except Exception: pass
    p = subprocess.Popen(
        [f"{REPO}/target/release/secuscan-server"],
        cwd=REPO, env=env,
        stdout=open("/tmp/v310_server.log", "w"),
        stderr=subprocess.STDOUT, start_new_session=True)
    for _ in range(60):
        try:
            urllib.request.urlopen("http://127.0.0.1:8080/api/v1/auth/login", timeout=1)
        except urllib.error.HTTPError:
            break
        except Exception:
            time.sleep(0.5)
    else:
        log("SERVER FAILED TO START")
        print(open("/tmp/v310_server.log").read()[-2000:])
        raise SystemExit(1)
    log("server up")
    return p


def main():
    log("=== v3.1.0 verification ===")
    srv = boot_server()
    try:
        s, b = req("POST", "/auth/login", body={
            "email": "admin@secuscan.local", "password": "VerifyIt2026!"})
        token = b.get("access_token")
        log("login OK")

        # === 1. Plugin catalog: people-hunter present ===
        log("\n--- 1. Plugin catalog ---")
        s, b = req("GET", "/plugins", token=token)
        plugins = b.get("items", [])
        log(f"total plugins: {len(plugins)}")
        for pid in ["people-hunter", "sqli-exploiter", "xss-exploiter", "http-request-logger"]:
            p = next((p for p in plugins if p["id"] == pid), None)
            if p:
                log(f"  {pid:25s} available={p.get('available')}")
            else:
                log(f"  {pid:25s} MISSING!")

        # === 2. People Hunter ===
        log("\n--- 2. People Hunter ---")
        s, b = req("POST", "/tasks", token=token, body={
            "plugin_id": "people-hunter",
            "inputs": {"target": "127.0.0.1"},
            "consent_granted": True,
        })
        log(f"people-hunter task: {s}")
        if b.get("id"):
            task_id = b["id"]
            for _ in range(30):
                time.sleep(1)
                s, b2 = req("GET", f"/tasks/{task_id}", token=token)
                if b2.get("status") in ("completed", "failed", "cancelled"):
                    log(f"  status: {b2.get('status')}")
                    s, b3 = req("GET", f"/tasks/{task_id}/result", token=token)
                    findings = b3.get("findings", [])
                    log(f"  findings: {len(findings)}")
                    for f in findings[:3]:
                        log(f"    - [{f.get('severity')}] {f.get('title','')[:70]}")
                    break

        # === 3. VPN profiles ===
        log("\n--- 3. VPN profiles ---")
        s, b = req("POST", "/vpn-profiles", token=token, body={
            "name": "lab-openvpn",
            "config_text": "client\ndev tun\nproto udp\nremote 203.0.113.10 1194\n"
                           "ca [cert]\ncert [cert]\nkey [key]\n",
        })
        log(f"create vpn profile: {s} id={b.get('id')}")
        vpn_id = b.get("id")

        s, b = req("GET", "/vpn-profiles", token=token)
        log(f"  profiles listed: {len(b.get('items', []))}")

        if vpn_id:
            s, b = req("POST", f"/vpn-profiles/{vpn_id}/connect", token=token)
            log(f"  connect: {s} status={b.get('status')} error={str(b.get('error',''))[:80]}")
            # In a sandbox without openvpn this will error gracefully.
            s, b = req("POST", f"/vpn-profiles/{vpn_id}/disconnect", token=token)
            log(f"  disconnect: {s} status={b.get('status')}")

        # Attach to workspace
        s, b = req("POST", "/workspaces", token=token, body={"name": "v310-test"})
        ws_id = b.get("id")
        if ws_id and vpn_id:
            r = urllib.request.Request(
                f"{BASE}/workspaces/{ws_id}/vpn",
                data=json.dumps({"vpn_profile_id": vpn_id}).encode(),
                method="PUT",
                headers={"content-type": "application/json", "authorization": f"Bearer {token}"})
            try:
                with urllib.request.urlopen(r, timeout=30) as resp:
                    log(f"  attach to workspace: {resp.status}")
            except urllib.error.HTTPError as e:
                log(f"  attach to workspace: {e.code}")

        # === 4. Sniper ===
        log("\n--- 4. Sniper Auto-Exploiter ---")
        # Find a finding to snipe — use a fresh http-headers scan's output.
        s, b = req("POST", "/tasks", token=token, body={
            "plugin_id": "http-headers",
            "inputs": {"target": "http://127.0.0.1:8080/"},
            "consent_granted": True,
        })
        scan_id = b.get("id")
        if scan_id:
            for _ in range(30):
                time.sleep(1)
                s, b2 = req("GET", f"/tasks/{scan_id}", token=token)
                if b2.get("status") in ("completed", "failed", "cancelled"):
                    break
            s, b = req("GET", "/findings?limit=5", token=token)
            findings = b.get("items", [])
            log(f"  findings available: {len(findings)}")
            if findings:
                fid = findings[0]["id"]
                log(f"  sniping finding: {findings[0].get('title','')[:60]}")
                s, b = req("POST", "/sniper/run", token=token, body={
                    "finding_id": fid,
                    "workspace_id": ws_id,
                })
                log(f"  sniper run start: {s} run_id={b.get('run_id')}")
                run_id = b.get("run_id")
                if run_id:
                    # Wait up to 90s for the chain to finish (http-recon + http-headers are fast).
                    for _ in range(90):
                        time.sleep(1)
                        s, b = req("GET", f"/sniper/runs/{run_id}", token=token)
                        if b.get("status") in ("completed", "failed", "cancelled"):
                            log(f"  sniper run: {b.get('status')} outcome={b.get('outcome')}")
                            steps = b.get("steps", [])
                            log(f"  steps: {len(steps)}")
                            for st in steps:
                                log(f"    - [{st.get('status')}] {st.get('label')} ({st.get('plugin_id')}) findings={st.get('findings_count')}")
                            if b.get("proof"):
                                log(f"  proof (first 150): {b['proof'][:150]}")
                            break
            else:
                log("  (no findings to snipe — skipped)")

        log("\n=== v3.1.0 verification DONE ===")

    finally:
        os.killpg(os.getpgid(srv.pid), signal.SIGTERM)


if __name__ == "__main__":
    main()
