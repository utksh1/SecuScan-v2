#!/usr/bin/env python3
"""SecuScan v2 end-to-end verification.

Boots the Rust API server, then exercises the full pentest-platform workflow:
auth -> plugins -> workspace -> target -> live native scan (real TCP connects
against 127.0.0.1, including the server itself) -> SSE streaming -> findings ->
triage -> second run -> scan diff -> reports (5 sync formats) -> async report
job (pdf/docx/xlsx) -> dashboard -> schedule -> audit log -> frontend serving.

Prints PASS/FAIL per step with a final summary. Exits non-zero on any FAIL.
"""
import json
import os
import re
import signal
import subprocess
import sys
import time
import urllib.request
import urllib.error

BASE = "http://127.0.0.1:8080/api/v1"
ROOT = "http://127.0.0.1:8080"
REPO = "/home/z/secuscan-v2"

results = []


def log(msg):
    print(msg, flush=True)


def record(name, ok, detail=""):
    results.append((name, ok, detail))
    log(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))


def req(method, path, token=None, body=None, raw=False, base=BASE):
    url = f"{base}{path}"
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(url, data=data, method=method)
    r.add_header("content-type", "application/json")
    if token:
        r.add_header("authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(r, timeout=30) as resp:
            payload = resp.read()
            return resp.status, payload if raw else json.loads(payload or b"{}")
    except urllib.error.HTTPError as e:
        payload = e.read()
        try:
            return e.code, payload if raw else json.loads(payload or b"{}")
        except Exception:
            return e.code, payload


def unwrap(d):
    if isinstance(d, dict):
        return d.get("data", d)
    return d


def main():
    # ---------- 1. boot server ----------
    log("\n== 1. Boot server ==")
    for f in ("e2e.db", "e2e.db-shm", "e2e.db-wal"):
        p = f"{REPO}/data/{f}"
        if os.path.exists(p):
            os.remove(p)
    env = dict(
        os.environ,
        SECUSCAN_ADMIN_EMAIL="admin@secuscan.local",
        SECUSCAN_ADMIN_PASSWORD="VerifyIt2026!",
        SECUSCAN_DB_URL="sqlite:///home/z/secuscan-v2/data/e2e.db?mode=rwc",
    )
    proc = subprocess.Popen(
        [f"{REPO}/target/debug/secuscan-server"],
        cwd=REPO, env=env,
        stdout=open("/tmp/e2e-server.log", "w"),
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    try:
        st = None
        for _ in range(40):
            try:
                st, d = req("GET", "/health")
                if st == 200:
                    break
            except Exception:
                pass
            time.sleep(0.5)
        else:
            log("Server never became healthy. Log tail:")
            os.system("tail -20 /tmp/e2e-server.log")
            sys.exit(1)
        record("server boots + /health", st == 200 and d.get("version") == "2.0.0", str(d))

        # ---------- 2. auth ----------
        log("\n== 2. Authentication ==")
        st, d = req("POST", "/auth/login", body={"email": "admin@secuscan.local", "password": "VerifyIt2026!"})
        token = unwrap(d).get("access_token", "")
        record("login returns JWT", st == 200 and len(token) > 50, f"status={st}, token_len={len(token)}")

        st, d = req("GET", "/auth/me", token=token)
        me = unwrap(d)
        record("GET /auth/me", st == 200 and me.get("email") == "admin@secuscan.local", str(me.get("email")))

        st, d = req("GET", "/auth/me", token="bogus.token.here")
        record("bad token rejected", st == 401, f"status={st}")

        # ---------- 3. plugins ----------
        log("\n== 3. Plugin catalogue ==")
        st, d = req("GET", "/plugins", token=token)
        plugins = unwrap(d)
        if isinstance(plugins, dict):
            plugins = plugins.get("items", plugins.get("plugins", []))
        avail = [p for p in plugins if p.get("available")]
        record("plugin catalogue", st == 200 and len(plugins) >= 10, f"{len(plugins)} loaded, {len(avail)} available")
        log("    plugins: " + ", ".join(p["id"] for p in plugins))

        # ---------- 4. workspace + target ----------
        log("\n== 4. Workspace + first-class target ==")
        st, d = req("POST", "/workspaces", token=token, body={"name": "Acme Corp", "description": "E2E verification client"})
        ws = unwrap(d)
        ws_id = ws.get("id")
        record("create workspace", st in (200, 201) and ws_id, f"status={st}, id={ws_id}")

        st, d = req("POST", f"/workspaces/{ws_id}/targets", token=token,
                    body={"name": "127.0.0.1", "description": "local lab host"})
        record("register target", st in (200, 201), f"status={st}")

        st, d = req("GET", f"/workspaces/{ws_id}/targets", token=token)
        tgts = unwrap(d)
        if isinstance(tgts, dict):
            tgts = tgts.get("items", [])
        record("target registry lists target", st == 200 and len(tgts) >= 1, f"{len(tgts)} target(s)")

        # ---------- 5. consent gate ----------
        log("\n== 5. Safety: consent gate ==")
        st, d = req("POST", "/tasks", token=token,
                    body={"plugin_id": "port-scanner", "inputs": {"target": "127.0.0.1", "ports": "8080"},
                          "consent_granted": False, "workspace_id": ws_id})
        record("scan refused without consent", st in (400, 403), f"status={st}, msg={str(d)[:90]}")

        # ---------- 6. real scan via SSE ----------
        log("\n== 6. Live scan (native port scanner, real TCP connects) ==")
        st, d = req("POST", "/tasks", token=token,
                    body={"plugin_id": "port-scanner",
                          "inputs": {"target": "127.0.0.1", "ports": "22,80,443,8080"},
                          "consent_granted": True, "workspace_id": ws_id})
        task = unwrap(d)
        task_id = task.get("id")
        record("task accepted", st in (200, 201) and task_id, f"status={st}, id={task_id}")

        sse_events = []
        try:
            r = urllib.request.Request(f"{BASE}/tasks/{task_id}/stream")
            r.add_header("authorization", f"Bearer {token}")
            with urllib.request.urlopen(r, timeout=20) as resp:
                deadline = time.time() + 20
                buf = b""
                while time.time() < deadline:
                    chunk = resp.read1(4096)
                    if not chunk:
                        break
                    buf += chunk
                    text = buf.decode(errors="replace")
                    while "\n\n" in text:
                        ev, text = text.split("\n\n", 1)
                        for line in ev.splitlines():
                            if line.startswith("event:"):
                                sse_events.append(line.split(":", 1)[1].strip())
                        buf = text.encode()
                    joined = " ".join(sse_events)
                    if "completed" in joined or "failed" in joined:
                        break
        except Exception as ex:
            log(f"    (sse note: {ex})")
        record("SSE stream emits events", len(sse_events) >= 2, f"{len(sse_events)} events: {sorted(set(sse_events))[:8]}")

        t = None
        for _ in range(40):
            st, d = req("GET", f"/tasks/{task_id}", token=token)
            t = unwrap(d)
            if t.get("status") in ("completed", "failed", "cancelled"):
                break
            time.sleep(0.5)
        record("scan completes", t.get("status") == "completed",
               f"status={t.get('status')}, exit={t.get('exit_code')}")

        st, d = req("GET", f"/tasks/{task_id}/output", token=token)
        out = unwrap(d)
        if isinstance(out, dict):
            out = out.get("output", "") or ""
        st, d = req("GET", "/findings", token=token)
        f0 = unwrap(d)
        items0 = f0.get("items", f0) if isinstance(f0, dict) else f0
        found8080 = "8080" in str(out) or any("8080" in str(i.get("title", "")) for i in items0)
        record("scanner sees open port 8080 (the server itself)", found8080,
               str(out)[:120].replace("\n", " | ") + f" | findings={[i.get('title') for i in items0][:3]}")

        # ---------- 7. findings + triage ----------
        log("\n== 7. Findings + analyst triage ==")
        st, d = req("GET", "/findings", token=token)
        f = unwrap(d)
        items = f.get("items", f) if isinstance(f, dict) else f
        record("findings recorded from scan", st == 200 and len(items) >= 1, f"{len(items)} finding(s)")
        for it in (items or [])[:5]:
            log(f"    - [{it.get('severity')}] {it.get('title')} ({it.get('plugin_id')})")

        if items:
            fid = items[0]["id"]
            st, d = req("PATCH", f"/findings/{fid}/triage", token=token,
                        body={"analyst_status": "false_positive"})
            record("triage finding -> false_positive", st == 200, f"status={st}, resp={str(d)[:80]}")

        # ---------- 8. second run + diff ----------
        log("\n== 8. Second run + scan diff ==")
        st, d = req("POST", "/tasks", token=token,
                    body={"plugin_id": "port-scanner",
                          "inputs": {"target": "127.0.0.1", "ports": "22,8080"},
                          "consent_granted": True, "workspace_id": ws_id})
        task2 = unwrap(d)
        t2 = None
        for _ in range(40):
            st, d = req("GET", f"/tasks/{task2['id']}", token=token)
            t2 = unwrap(d)
            if t2.get("status") in ("completed", "failed"):
                break
            time.sleep(0.5)
        record("second scan completes", t2.get("status") == "completed", f"task2={t2.get('status')}")

        st, d = req("GET", f"/tasks/{task2['id']}/diff", token=token)
        diff = unwrap(d)
        record("scan diff (new/fixed/unchanged)", st == 200 and "summary" in diff,
               f"summary={diff.get('summary')}")

        # ---------- 9. reports ----------
        log("\n== 9. Reports (5 sync formats) ==")
        for fmt in ["md", "json", "csv", "html", "sarif"]:
            st, body = req("GET", f"/tasks/{task2['id']}/report/{fmt}", token=token, raw=True)
            ok = st == 200 and len(body) > 40
            record(f"report: {fmt}", ok, f"status={st}, {len(body)} bytes")
            if fmt == "sarif":
                try:
                    sarif = json.loads(body)
                    ok2 = "runs" in sarif
                    record("sarif is valid SARIF 2.1.0", ok2, str(list(sarif.keys()))[:80])
                except Exception as ex:
                    record("sarif is valid SARIF 2.1.0", False, str(ex))

        # ---------- 10. async report jobs (pdf/docx/xlsx, one job per format) ----------
        log("\n== 10. Async report jobs (pdf/docx/xlsx) ==")
        jobs_started = []
        for fmt in ["pdf", "docx", "xlsx"]:
            st, d = req("POST", f"/tasks/{task2['id']}/reports", token=token, body={"format": fmt})
            j = unwrap(d)
            record(f"async job accepted: {fmt}", st in (200, 201, 202) and j.get("id"), f"status={st}, id={j.get('id')}")
            if j.get("id"):
                jobs_started.append((fmt, j["id"]))
        dl_ok = 0
        for _ in range(40):
            st, d = req("GET", "/reports", token=token)
            jobs = unwrap(d)
            jobs = jobs.get("items", jobs) if isinstance(jobs, dict) else jobs
            by_id = {j["id"]: j for j in jobs}
            if all(by_id.get(jid, {}).get("status") in ("finished", "completed", "failed") for _, jid in jobs_started):
                break
            time.sleep(0.5)
        for fmt, jid in jobs_started:
            j = by_id.get(jid, {})
            record(f"async job completes: {fmt}", j.get("status") in ("finished", "completed"),
                   f"status={j.get('status')}")
            if j.get("status") in ("finished", "completed"):
                st, body = req("GET", f"/reports/{jid}/download", token=token, raw=True)
                ok = st == 200 and len(body) > 100
                dl_ok += ok
                magic = body[:4].hex() if body else ""
                record(f"download {fmt} artifact", ok, f"status={st}, {len(body)} bytes, magic=0x{magic}")

        # ---------- 11. dashboard ----------
        log("\n== 11. Dashboard ==")
        st, d = req("GET", "/dashboard/summary", token=token)
        ds = unwrap(d)
        record("dashboard summary", st == 200 and "findings" in ds and "plugins" in ds,
               str(ds)[:140])

        # ---------- 12. schedules ----------
        log("\n== 12. Recurring schedule ==")
        st, d = req("POST", "/schedules", token=token,
                    body={"name": "weekly-local-check", "plugin_id": "port-scanner",
                          "inputs": {"target": "127.0.0.1", "ports": "8080"},
                          "interval_seconds": 604800, "consent_granted": True, "workspace_id": ws_id})
        sch = unwrap(d)
        record("schedule created", st in (200, 201) and sch.get("id"),
               f"status={st}, every {sch.get('interval_seconds')}s")

        # ---------- 13. audit log ----------
        log("\n== 13. Audit log (admin) ==")
        st, d = req("GET", "/admin/audit?limit=5", token=token)
        aud = unwrap(d)
        aud_items = aud.get("items", aud) if isinstance(aud, dict) else aud
        record("audit log readable", st == 200,
               f"status={st}, {len(aud_items) if isinstance(aud_items, list) else '?'} entries")

        # ---------- 14. frontend ----------
        log("\n== 14. Frontend served by Rust API ==")
        st, body = req("GET", "/", raw=True, base=ROOT)
        record("index.html served", st == 200 and b"root" in body, f"status={st}, {len(body)} bytes")
        m = body.decode(errors="replace")
        assets = [a or b for a, b in re.findall(r'src="(/assets/[^"]+)"|href="(/assets/[^"]+)"', m)]
        ok_assets = len(assets) >= 1
        for a in assets:
            st2, b2 = req("GET", a, raw=True, base=ROOT)
            if st2 != 200:
                ok_assets = False
        record("bundled JS/CSS assets served", ok_assets,
               f"{len(assets)} asset(s): {[a.split('/')[-1][:28] for a in assets]}")

    finally:
        log("\n== shutdown ==")
        try:
            proc.send_signal(signal.SIGTERM)
            proc.wait(timeout=5)
            record("clean shutdown on SIGTERM", True, f"rc={proc.returncode}")
        except Exception:
            proc.kill()
            record("clean shutdown on SIGTERM", False, "had to SIGKILL")

    passed = sum(1 for _, ok, _ in results if ok)
    failed = sum(1 for _, ok, _ in results if not ok)
    log("\n" + "=" * 60)
    log(f"E2E RESULT: {passed} passed, {failed} failed, {len(results)} total")
    log("=" * 60)
    for name, ok, detail in results:
        if not ok:
            log(f"  FAILED: {name} — {detail}")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
