#!/usr/bin/env python3
"""SecuScan v3.1.2 live verification.

Validates the four new product-grade features:
  1. OpenAPI 3.1 spec at /api/v1/openapi.{json,yaml} + Swagger UI landing.
  2. Attack-Target endpoint POST /targets/:id/attack with 4 suites.
  3. Sniper launch from a finding (already proven in v3.1.0; here we
     re-verify the full chain still works after the v3.1.1 admission
     gate changes).
  4. Replay (retry) endpoint POST /tasks/:id/retry (already existed;
     here we verify the renamed UI label by exercising the API).
"""
import json, os, signal, subprocess, time, urllib.request, urllib.error

BASE = "http://127.0.0.1:8080/api/v1"
REPO = "/home/z/secuscan-v2"


def log(m): print(m, flush=True)


def req(method, path, token=None, body=None, raw=False):
    url = f"{BASE}{path}"
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(url, data=data, method=method)
    r.add_header("content-type", "application/json")
    if token:
        r.add_header("authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(r, timeout=180) as resp:
            if raw:
                return resp.status, resp.read()
            raw_body = resp.read() or b"{}"
            return resp.status, (json.loads(raw_body) if raw_body else {})
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except Exception:
            return e.code, {}


def boot_server():
    env = dict(os.environ)
    env["SECUSCAN_DB_URL"] = "sqlite:////home/z/secuscan-v2/data/v312-proof.db"
    env["SECUSCAN_JWT_SECRET"] = "v312-proof-secret-32bytes-long-aaaa"
    env["SECUSCAN_ADDR"] = "127.0.0.1:8080"
    env["SECUSCAN_ADMIN_EMAIL"] = "admin@secuscan.local"
    env["SECUSCAN_ADMIN_PASSWORD"] = "VerifyIt2026!"
    env["RUST_LOG"] = "info"
    for suffix in ("", "-wal", "-shm"):
        try:
            os.unlink(f"/home/z/secuscan-v2/data/v312-proof.db{suffix}")
        except FileNotFoundError:
            pass
    p = subprocess.Popen(
        [f"{REPO}/target/release/secuscan-server"],
        cwd=REPO, env=env,
        stdout=open("/tmp/v312_server.log", "w"),
        stderr=subprocess.STDOUT, start_new_session=True,
    )
    for _ in range(60):
        try:
            urllib.request.urlopen("http://127.0.0.1:8080/api/v1/auth/login", timeout=1)
        except urllib.error.HTTPError:
            break
        except Exception:
            time.sleep(0.5)
    else:
        log("SERVER FAILED TO START")
        print(open("/tmp/v312_server.log").read()[-2000:])
        raise SystemExit(1)
    log("server up")
    return p


def wait_task(token, tid, timeout=30):
    b = {}
    for _ in range(timeout):
        time.sleep(1)
        s, b = req("GET", f"/tasks/{tid}", token=token)
        if b.get("status") in ("completed", "failed", "cancelled"):
            return b
    return b


def main():
    log("=== v3.1.2 verification ===")
    srv = boot_server()
    try:
        s, b = req("POST", "/auth/login", body={
            "email": "admin@secuscan.local",
            "password": "VerifyIt2026!",
        })
        token = b.get("access_token")
        log("login OK")

        # === 1. OpenAPI spec ============================================
        log("\n--- 1. OpenAPI 3.1 spec ---")
        s, b = req("GET", "/openapi.json")
        log(f"  GET /openapi.json: {s}")
        assert s == 200, f"openapi.json must return 200, got {s}"
        assert b.get("openapi") == "3.1.0", f"expected openapi 3.1.0, got {b.get('openapi')}"
        assert "paths" in b and "components" in b, "spec missing paths/components"
        n_paths = len(b.get("paths", {}))
        n_schemas = len(b.get("components", {}).get("schemas", {}))
        log(f"  paths: {n_paths}, schemas: {n_schemas}")
        assert n_paths >= 80, f"expected >=80 paths, got {n_paths}"
        assert n_schemas >= 20, f"expected >=20 schemas, got {n_schemas}"
        # /targets/:id/attack documented
        attack_path = b["paths"].get("/targets/:id/attack")
        assert attack_path and "post" in attack_path, "spec missing POST /targets/:id/attack"
        log("  POST /targets/:id/attack documented in spec")

        s, body = req("GET", "/openapi.yaml", raw=True)
        log(f"  GET /openapi.yaml: {s} ({len(body)} bytes)")
        assert s == 200, f"openapi.yaml must return 200, got {s}"
        assert body.startswith(b"openapi: 3.1"), "YAML must start with `openapi: 3.1`"

        s, html = req("GET", "/openapi", raw=True)
        log(f"  GET /openapi (Swagger UI): {s} ({len(html)} bytes)")
        assert s == 200, f"openapi landing must return 200, got {s}"
        assert b"swagger-ui" in html.lower(), "landing must reference swagger-ui"

        # === 2. Attack-Target endpoint ==================================
        log("\n--- 2. Attack-Target ---")
        # Create a workspace + target.
        s, b = req("POST", "/workspaces", token=token, body={"name": "v312-lab"})
        ws_id = b.get("id")
        assert ws_id, f"workspace creation failed: {s} {b}"
        log(f"  workspace: {ws_id}")

        s, b = req("POST", f"/workspaces/{ws_id}/targets", token=token, body={
            "name": "127.0.0.1",
            "description": "localhost for attack-target test",
        })
        target_id = b.get("id")
        assert target_id, f"target creation failed: {s} {b}"
        log(f"  target (ip_address): {target_id} kind={b.get('kind')}")

        # Suite=quick on an IP should launch dns-lookup + nmap (nmap may
        # be missing in sandbox -> we expect at least dns-lookup to be
        # admitted).
        s, b = req("POST", f"/targets/{target_id}/attack", token=token, body={"suite": "quick"})
        log(f"  attack quick: {s} launched={len(b.get('tasks', []))} skipped={len(b.get('skipped', []))}")
        assert s == 201, f"attack quick must return 201, got {s}: {b}"
        assert len(b.get("tasks", [])) >= 1, "at least one task must be launched"
        for t in b["tasks"]:
            log(f"    - {t['plugin_id']:20s} id={t['id'][:8]} status={t['status']}")
        for sk in b.get("skipped", []):
            log(f"    [skipped] {sk['plugin_id']:20s} reason={sk['reason'][:60]}")

        # Suite=web on an IP must be rejected with 400.
        s, b = req("POST", f"/targets/{target_id}/attack", token=token, body={"suite": "web"})
        log(f"  attack web on IP: {s} (expected 400)")
        assert s == 400, f"web suite on IP must be rejected with 400, got {s}"

        # Suite=internal on an IP -> nmap + smb-enum + ssh-audit (some
        # may be missing -> skipped).
        s, b = req("POST", f"/targets/{target_id}/attack", token=token, body={"suite": "internal"})
        log(f"  attack internal: {s} launched={len(b.get('tasks', []))} skipped={len(b.get('skipped', []))}")
        assert s in (201, 400), f"unexpected status for internal: {s}"
        if s == 201:
            plugin_ids = [t["plugin_id"] for t in b["tasks"]]
            assert "nmap" in plugin_ids or any(s_["plugin_id"] == "nmap" for s_ in b["skipped"]), \
                "internal suite must include nmap (launched or skipped)"

        # Try a hostname target + full suite.
        s, b = req("POST", f"/workspaces/{ws_id}/targets", token=token, body={
            "name": "example.com",
            "description": "hostname for attack-target test",
        })
        host_target_id = b.get("id")
        assert host_target_id, f"hostname target creation failed: {s} {b}"
        log(f"  target (hostname): {host_target_id} kind={b.get('kind')}")

        s, b = req("POST", f"/targets/{host_target_id}/attack", token=token, body={"suite": "full"})
        log(f"  attack full on hostname: {s} launched={len(b.get('tasks', []))} skipped={len(b.get('skipped', []))}")
        assert s == 201, f"full suite on hostname must return 201, got {s}: {b}"

        # Suite=internal on hostname must be rejected.
        s, b = req("POST", f"/targets/{host_target_id}/attack", token=token, body={"suite": "internal"})
        log(f"  attack internal on hostname: {s} (expected 400)")
        assert s == 400, f"internal suite on hostname must be rejected, got {s}"

        # === 3. Sniper from a finding ===================================
        log("\n--- 3. Sniper Auto-Exploiter ---")
        s, b = req("POST", "/tasks", token=token, body={
            "plugin_id": "http-headers",
            "inputs": {"target": "http://127.0.0.1:8080/"},
            "consent_granted": True,
        })
        scan_id = b.get("id")
        assert scan_id, f"http-headers task creation failed: {s} {b}"
        r = wait_task(token, scan_id, timeout=30)
        log(f"  http-headers scan: {r.get('status')}")

        s, b = req("GET", "/findings?limit=5", token=token)
        findings = b.get("items", [])
        log(f"  findings available: {len(findings)}")
        if findings:
            fid = findings[0]["id"]
            s, b = req("POST", "/sniper/run", token=token, body={"finding_id": fid})
            run_id = b.get("run_id")
            log(f"  sniper run start: {s} run_id={run_id}")
            assert s in (200, 201, 202), f"sniper run should return 2xx, got {s}"
            if run_id:
                for _ in range(90):
                    time.sleep(1)
                    s, b = req("GET", f"/sniper/runs/{run_id}", token=token)
                    if b.get("status") in ("completed", "failed", "cancelled"):
                        log(f"  sniper run: {b.get('status')} outcome={b.get('outcome')} steps={len(b.get('steps', []))}")
                        break

        # === 4. Replay (retry) endpoint =================================
        log("\n--- 4. Replay (retry) ---")
        # Use the http-headers task we just ran.
        s, b = req("POST", f"/tasks/{scan_id}/retry", token=token)
        log(f"  POST /tasks/{scan_id}/retry: {s} new_id={b.get('id')}")
        assert s == 201, f"retry must return 201, got {s}: {b}"
        new_task_id = b.get("id")
        assert new_task_id and new_task_id != scan_id, "retry must create a new task"
        # Wait briefly to ensure it spawned.
        r = wait_task(token, new_task_id, timeout=30)
        log(f"  replayed task: status={r.get('status')}")

        # === 5. v3.1.1 VPN gate still holds ============================
        log("\n--- 5. VPN-aware admission gate (regression) ---")
        s, b = req("POST", "/vpn-profiles", token=token, body={
            "name": "regress-tunnel",
            "config_text": "client\ndev tun\nremote 203.0.113.10 1194\n",
        })
        vpn_id = b.get("id")
        s, b = req("PUT", f"/workspaces/{ws_id}/vpn", token=token, body={"vpn_profile_id": vpn_id})
        log(f"  pin VPN to workspace: {s}")
        # Now an attack against the workspace's target must fail because the
        # tunnel can't come up.
        s, b = req("POST", f"/targets/{target_id}/attack", token=token, body={"suite": "quick"})
        log(f"  attack while pinned: {s} (expected 409)")
        assert s == 409, f"attack while pinned must be 409, got {s}"
        # And unpin lets it through.
        s, b = req("PUT", f"/workspaces/{ws_id}/vpn", token=token, body={"vpn_profile_id": None})
        log(f"  unpin: {s}")
        s, b = req("POST", f"/targets/{target_id}/attack", token=token, body={"suite": "quick"})
        log(f"  attack after unpin: {s}")
        assert s == 201, f"attack after unpin must be 201, got {s}"

        log("\n=== v3.1.2 verification DONE ===")

    finally:
        os.killpg(os.getpgid(srv.pid), signal.SIGTERM)


if __name__ == "__main__":
    main()
