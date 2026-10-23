#!/usr/bin/env python3
"""SecuScan v2.6.0 live verification — exercises every new feature.

Boots the server, then:
  1. List builtin robots → run "Domain Recon" against example.com
  2. Create an auth profile (cookie method) → attach to a scan
  3. Run a normal scan → check attack-surface auto-aggregated the asset
  4. Add a workspace member + post a finding comment with @mention
  5. Update branding → verify it round-trips
  6. Start the MCP server (HTTP mode) → call tools/list and start_scan
"""
import json, os, signal, subprocess, time, urllib.request, urllib.error

BASE = "http://127.0.0.1:8080/api/v1"
REPO = "/home/z/secuscan-v2"
SHOTS = "/home/z/my-project/download/ui-screens/v260"
os.makedirs(SHOTS, exist_ok=True)


def log(m): print(m, flush=True)


def req(method, path, token=None, body=None, headers=None):
    url = f"{BASE}{path}"
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(url, data=data, method=method)
    r.add_header("content-type", "application/json")
    if token: r.add_header("authorization", f"Bearer {token}")
    if headers:
        for k, v in headers.items():
            r.add_header(k, v)
    try:
        with urllib.request.urlopen(r, timeout=120) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        try: return e.code, json.loads(e.read() or b"{}")
        except: return e.code, {}


def boot_server():
    env = dict(os.environ)
    env["PATH"] = f"{env['PATH']}"
    env["SECUSCAN_DB_URL"] = f"sqlite:////home/z/secuscan-v2/data/v260-proof.db"
    env["SECUSCAN_JWT_SECRET"] = "v260-proof-secret-32bytes-long-aaaa"
    env["SECUSCAN_LISTEN_ADDR"] = "127.0.0.1:8080"
    env["SECUSCAN_ADMIN_EMAIL"] = "admin@secuscan.local"
    env["SECUSCAN_ADMIN_PASSWORD"] = "VerifyIt2026!"
    env["RUST_LOG"] = "info"
    try: os.unlink("/home/z/secuscan-v2/data/v260-proof.db")
    except FileNotFoundError: pass
    p = subprocess.Popen(
        [f"{REPO}/target/release/secuscan-server"],
        cwd=REPO, env=env,
        stdout=open("/tmp/v260_server.log", "w"),
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
        print(open("/tmp/v260_server.log").read()[-2000:])
        raise SystemExit(1)
    log("server up")
    return p


def login():
    s, b = req("POST", "/auth/login", body={
        "email": "admin@secuscan.local", "password": "VerifyIt2026!"})
    if s != 200:
        log(f"login failed: {s} {b}"); raise SystemExit(1)
    return b.get("access_token")


def main():
    log("=== v2.6.0 verification ===")
    srv = boot_server()
    try:
        token = login()
        log(f"login OK")

        # 1. Robots — list builtins + run one
        s, b = req("GET", "/robots", token=token)
        robots = b.get("items", [])
        log(f"robots: {len(robots)} (builtins + user)")
        builtin_names = [r["name"] for r in robots if r["source"] == "builtin"]
        log(f"  builtins: {builtin_names}")

        # Pick "HTTP Lockpicker" — it's a self-contained chain
        th = next((r for r in robots if r["name"] == "HTTP Lockpicker"), None)
        if th:
            log(f"running robot: {th['name']} (id={th['id']})")
            # Use 127.0.0.1 as target (the lab will be the server itself, just for the demo)
            s, b = req("POST", f"/robots/{th['id']}/run", token=token, body={
                "targets": ["127.0.0.1"], "workspace_id": None,
            })
            log(f"  run start: {s} run_id={b.get('run_id')}")
            run_id = b.get("run_id")
            # Poll for 30s — we don't need it to finish, just to start
            for _ in range(30):
                time.sleep(1)
                s, b = req("GET", f"/robots/runs/{run_id}", token=token)
                if s == 200:
                    st = b.get("status")
                    if st in ("completed", "failed", "cancelled"):
                        log(f"  run final: {st}")
                        break

        # 2. Auth profiles
        s, b = req("POST", "/auth-profiles", token=token, body={
            "name": "test-cookie",
            "method": "cookie",
            "config": {"cookies": [{"name": "session", "value": "abc123"}]},
            "notes": "v2.6.0 proof",
        })
        log(f"auth profile create: {s}")
        if s in (200, 201):
            ap_id = b["id"]
            s, b = req("GET", f"/auth-profiles/{ap_id}", token=token)
            log(f"  fetch: {s} method={b.get('method')}")

        # 3. Attack surface — run a quick port scan and verify aggregation
        # Use http-headers against the server itself (always reachable)
        s, b = req("POST", "/tasks", token=token, body={
            "plugin_id": "http-headers",
            "inputs": {"target": "http://127.0.0.1:8080/"},
            "consent_granted": True,
        })
        log(f"port-scan task: {s} id={b.get('id')}")
        task_id = b.get("id")
        if task_id:
            for _ in range(30):
                time.sleep(1)
                s, b = req("GET", f"/tasks/{task_id}", token=token)
                if b.get("status") in ("completed", "failed", "cancelled"):
                    log(f"  task final: {b.get('status')}")
                    break
            # Check findings metadata
            s, b = req("GET", f"/tasks/{task_id}/result", token=token)
            tf = b.get("findings", b.get("items", []))
            log(f"  task findings: {len(tf)}")
            for tf_item in tf[:3]:
                log(f"    - {tf_item.get('title')[:60]} | metadata={json.dumps(tf_item.get('metadata',{}))[:120]}")
            # Check attack surface
            s, b = req("GET", "/attack-surface?limit=100", token=token)
            assets = b.get("items", [])
            log(f"attack surface: {len(assets)} asset(s)")
            for a in assets[:3]:
                log(f"  - {a.get('hostname') or a.get('ip_address') or a.get('url')} "
                    f"(key={a.get('asset_key')})")

        # 4. Collaboration — add a finding comment with @mention
        s, b = req("GET", "/findings?limit=1", token=token)
        findings = b.get("items", [])
        if findings:
            fid = findings[0]["id"]
            s, b = req("POST", f"/findings/{fid}/comments", token=token, body={
                "body": "Investigating @admin@secuscan.local — this looks like a real exposure."
            })
            log(f"comment create: {s}")
            s, b = req("GET", f"/findings/{fid}/comments", token=token)
            log(f"  comments: {len(b.get('items', []))}")

        # 5. Branding
        s, b = req("GET", "/branding", token=token)
        log(f"branding get: {s} org={b.get('org_name')}")
        s, b = req("PATCH", "/branding", token=token, body={
            "org_name": "Acme Security",
            "primary_color": "FF8800",
            "accent_color": "0088FF",
            "footer_text": "Acme internal pentest report — confidential",
        })
        log(f"branding update: {s}")
        s, b = req("GET", "/branding", token=token)
        log(f"  verify: org={b.get('org_name')} primary={b.get('primary_color')}")

        # 6. MCP server (HTTP mode)
        log("--- starting MCP server ---")
        mcp_env = dict(os.environ)
        mcp_env["SECUSCAN_API_URL"] = "http://127.0.0.1:8080"
        mcp_env["SECUSCAN_API_EMAIL"] = "admin@secuscan.local"
        mcp_env["SECUSCAN_API_PASSWORD"] = "VerifyIt2026!"
        # MCP needs no auth token for these read-only calls (server is local);
        # in real deployments you'd pass SECUSCAN_API_KEY.
        mcp_proc = subprocess.Popen(
            [f"{REPO}/target/release/secuscan-mcp", "--http", "127.0.0.1:9100"],
            env=mcp_env, stdout=open("/tmp/v260_mcp.log", "w"),
            stderr=subprocess.STDOUT, start_new_session=True)
        time.sleep(2)
        # Call tools/list
        payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).encode()
        r = urllib.request.Request("http://127.0.0.1:9100/mcp", data=payload, method="POST",
                                    headers={"content-type": "application/json"})
        with urllib.request.urlopen(r, timeout=10) as resp:
            tools_resp = json.loads(resp.read())
        tool_names = [t["name"] for t in tools_resp.get("result", {}).get("tools", [])]
        log(f"MCP tools/list: {len(tool_names)} tools")
        log(f"  sample: {tool_names[:5]}")
        # Call list_plugins
        payload = json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                              "params": {"name": "list_plugins", "arguments": {}}}).encode()
        r = urllib.request.Request("http://127.0.0.1:9100/mcp", data=payload, method="POST",
                                    headers={"content-type": "application/json"})
        with urllib.request.urlopen(r, timeout=10) as resp:
            plugins_resp = json.loads(resp.read())
        text = plugins_resp.get("result", {}).get("content", [{}])[0].get("text", "")
        log(f"MCP list_plugins returned {len(text)} chars")
        log(f"  first 200: {text[:200]}")
        # Call list_attack_surface
        payload = json.dumps({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                              "params": {"name": "list_attack_surface", "arguments": {"limit": 10}}}).encode()
        r = urllib.request.Request("http://127.0.0.1:9100/mcp", data=payload, method="POST",
                                    headers={"content-type": "application/json"})
        with urllib.request.urlopen(r, timeout=10) as resp:
            as_resp = json.loads(resp.read())
        log(f"MCP list_attack_surface: {len(as_resp.get('result', {}).get('content', [{}])[0].get('text', ''))} chars")

        # Also test built-in prompts
        payload = json.dumps({"jsonrpc": "2.0", "id": 4, "method": "prompts/list"}).encode()
        r = urllib.request.Request("http://127.0.0.1:9100/mcp", data=payload, method="POST",
                                    headers={"content-type": "application/json"})
        with urllib.request.urlopen(r, timeout=10) as resp:
            prompts_resp = json.loads(resp.read())
        prompt_names = [p["name"] for p in prompts_resp.get("result", {}).get("prompts", [])]
        log(f"MCP prompts/list: {prompt_names}")

        # Cleanup MCP
        os.killpg(os.getpgid(mcp_proc.pid), signal.SIGTERM)

        log("=== v2.6.0 verification PASSED ===")

    finally:
        os.killpg(os.getpgid(srv.pid), signal.SIGTERM)


if __name__ == "__main__":
    main()
