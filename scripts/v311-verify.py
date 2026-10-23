#!/usr/bin/env python3
"""SecuScan v3.1.1 live verification — VPN-aware scanning admission gate.

Validates the security property added on top of v3.1.0:

  * workspaces carry an optional `vpn_profile_id` pin;
  * `GET /workspaces/:id/vpn` returns the pinned profile (or null);
  * `PUT /workspaces/:id/vpn` sets/clears the pin;
  * Tasks admitted in a pinned workspace are blocked when the tunnel cannot
    be brought up (sandbox: no openvpn binary → 409 Conflict) — preventing
    an internal scan from quietly probing the wrong routes;
  * `task_to_json` exposes `vpn_profile_id` (audit trail: which profile
    guaranteed this task's route);
  * Clearing the pin lets the task through.
"""
import json, os, signal, subprocess, time, urllib.request, urllib.error

BASE = "http://127.0.0.1:8080/api/v1"
REPO = "/home/z/secuscan-v2"


def log(m): print(m, flush=True)


def req(method, path, token=None, body=None):
    url = f"{BASE}{path}"
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(url, data=data, method=method)
    r.add_header("content-type", "application/json")
    if token:
        r.add_header("authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(r, timeout=60) as resp:
            raw = resp.read() or b"{}"
            return resp.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except Exception:
            return e.code, {}


def boot_server():
    env = dict(os.environ)
    env["SECUSCAN_DB_URL"] = "sqlite:////home/z/secuscan-v2/data/v311-proof.db"
    env["SECUSCAN_JWT_SECRET"] = "v311-proof-secret-32bytes-long-aaaa"
    env["SECUSCAN_ADDR"] = "127.0.0.1:8080"
    env["SECUSCAN_ADMIN_EMAIL"] = "admin@secuscan.local"
    env["SECUSCAN_ADMIN_PASSWORD"] = "VerifyIt2026!"
    env["RUST_LOG"] = "info"
    for suffix in ("", "-wal", "-shm"):
        try:
            os.unlink(f"/home/z/secuscan-v2/data/v311-proof.db{suffix}")
        except FileNotFoundError:
            pass
    p = subprocess.Popen(
        [f"{REPO}/target/release/secuscan-server"],
        cwd=REPO, env=env,
        stdout=open("/tmp/v311_server.log", "w"),
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
        print(open("/tmp/v311_server.log").read()[-2000:])
        raise SystemExit(1)
    log("server up")
    return p


def wait_task(token, tid, timeout=30):
    for _ in range(timeout):
        time.sleep(1)
        s, b = req("GET", f"/tasks/{tid}", token=token)
        if b.get("status") in ("completed", "failed", "cancelled"):
            return b
    return b


def main():
    log("=== v3.1.1 verification (VPN-aware admission) ===")
    srv = boot_server()
    try:
        s, b = req("POST", "/auth/login", body={
            "email": "admin@secuscan.local",
            "password": "VerifyIt2026!",
        })
        token = b.get("access_token")
        log("login OK")

        # --- 1. Workspace creation + initial VPN state --------------------
        log("\n--- 1. Workspace creation ---")
        s, b = req("POST", "/workspaces", token=token, body={"name": "v311-internal"})
        ws_id = b.get("id")
        log(f"  workspace created: id={ws_id}")
        assert ws_id, "workspace creation failed"

        s, b = req("GET", f"/workspaces/{ws_id}/vpn", token=token)
        log(f"  GET /workspaces/{{id}}/vpn: {s} profile={b.get('profile')}")
        assert s == 200, "GET workspace-vpn should succeed"
        assert b.get("profile") is None, "fresh workspace must have no VPN pin"

        # --- 2. Create a VPN profile (openvpn binary absent in sandbox) ---
        log("\n--- 2. VPN profile ---")
        s, b = req("POST", "/vpn-profiles", token=token, body={
            "name": "corp-tunnel",
            "config_text": (
                "client\ndev tun\nproto udp\nremote 203.0.113.10 1194\n"
                "<ca>\nMIIB...\n</ca>\n"
            ),
        })
        vpn_id = b.get("id")
        log(f"  profile created: id={vpn_id} status={b.get('status')}")

        # --- 3. Pin the profile to the workspace -------------------------
        log("\n--- 3. Pin profile → workspace ---")
        s, b = req("PUT", f"/workspaces/{ws_id}/vpn", token=token, body={
            "vpn_profile_id": vpn_id,
        })
        log(f"  PUT pin: {s}")
        assert s in (200, 204), f"pin should succeed, got {s}: {b}"

        s, b = req("GET", f"/workspaces/{ws_id}/vpn", token=token)
        profile = b.get("profile") or {}
        log(f"  pinned profile: name={profile.get('name')} "
            f"status={profile.get('status')} "
            f"openvpn_available={profile.get('openvpn_available')}")
        assert profile.get("id") == vpn_id, "GET should return the pinned profile"
        assert profile.get("openvpn_available") is False, \
            "sandbox must report openvpn unavailable"

        # --- 4. Task admission in pinned workspace — must be BLOCKED -----
        log("\n--- 4. Task admission while pinned (tunnel down) ---")
        s, b = req("POST", "/tasks", token=token, body={
            "plugin_id": "http-headers",
            "inputs": {"target": "http://127.0.0.1:8080/"},
            "workspace_id": ws_id,
            "consent_granted": True,
        })
        log(f"  POST /tasks: {s} body={str(b)[:160]}")
        assert s == 409, (
            f"expected 409 (tunnel down) — got {s}. "
            "Pinned workspace must refuse scans when the tunnel cannot come up."
        )
        err = b.get("error")
        if isinstance(err, dict):
            err_msg = err.get("message", "")
        else:
            err_msg = str(err or "")
        assert "corp-tunnel" in err_msg, \
            f"409 must name the pinned profile — got: {err_msg!r}"

        # --- 5. Clear the pin → task must now succeed -------------------
        log("\n--- 5. Unpin workspace → task admitted ---")
        s, b = req("PUT", f"/workspaces/{ws_id}/vpn", token=token, body={
            "vpn_profile_id": None,
        })
        log(f"  PUT clear pin: {s}")
        assert s in (200, 204)

        s, b = req("GET", f"/workspaces/{ws_id}/vpn", token=token)
        assert b.get("profile") is None, "pin must be cleared"

        s, b = req("POST", "/tasks", token=token, body={
            "plugin_id": "http-headers",
            "inputs": {"target": "http://127.0.0.1:8080/"},
            "workspace_id": ws_id,
            "consent_granted": True,
        })
        log(f"  POST /tasks: {s} id={b.get('id')}")
        assert s == 201, f"task should be admitted once unpinned, got {s}: {b}"

        # --- 6. Task JSON exposes vpn_profile_id (null here) -------------
        tid = b.get("id")
        s, b = req("GET", f"/tasks/{tid}", token=token)
        log(f"  task.vpn_profile_id = {b.get('vpn_profile_id')}")
        assert "vpn_profile_id" in b, \
            "task JSON must include vpn_profile_id (audit trail)"
        assert b.get("vpn_profile_id") is None, \
            "task admitted without pin must record NULL vpn_profile_id"

        # --- 7. Workspace list includes vpn_profile_id ------------------
        s, b = req("GET", "/workspaces", token=token)
        items = b.get("items", [])
        ws = next((w for w in items if w.get("id") == ws_id), {})
        log(f"  workspace.vpn_profile_id in list: {ws.get('vpn_profile_id')}")
        assert "vpn_profile_id" in ws, \
            "workspace JSON must include vpn_profile_id"

        # --- 8. Sniper/People Hunter remain functional ------------------
        log("\n--- 6. Sniper + People Hunter still work ---")
        s, b = req("GET", "/sniper/runs", token=token)
        log(f"  sniper runs list: {s} count={len(b.get('items', []))}")
        assert s == 200

        s, b = req("POST", "/tasks", token=token, body={
            "plugin_id": "people-hunter",
            "inputs": {"target": "127.0.0.1"},
            "consent_granted": True,
        })
        ph_id = b.get("id")
        if ph_id:
            r = wait_task(token, ph_id, timeout=30)
            log(f"  people-hunter task: {r.get('status')}")

        log("\n=== v3.1.1 verification DONE ===")

    finally:
        os.killpg(os.getpgid(srv.pid), signal.SIGTERM)


if __name__ == "__main__":
    main()
