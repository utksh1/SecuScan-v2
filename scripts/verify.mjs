#!/usr/bin/env node
/**
 * SecuScan v2 — consolidated end-to-end verification (zero dependencies,
 * Node >= 18 global fetch). Replaces the retired per-version Python
 * harnesses; this is the single living E2E proof script.
 *
 * Boots a fresh server against a throwaway SQLite DB, then validates the
 * full product surface:
 *
 *   1. Auth + health
 *   2. Plugin catalog (35 plugins)
 *   3. OpenAPI 3.1 spec endpoints (/openapi.json, /openapi.yaml, /openapi)
 *   4. Attack-Target suites (quick / web / full / internal + kind gates)
 *   5. Sniper Auto-Exploiter chain from a finding
 *   6. Replay (POST /tasks/:id/retry) + scan diff endpoint
 *   7. People Hunter scan
 *   8. VPN-aware admission gate regression (pin -> 409 -> unpin -> 201)
 *   9. VPN profile CRUD + graceful error path
 *  10. SPA serving + SSE replay + SARIF report artifact
 *
 * Usage:  node scripts/verify.mjs
 * Exit code 0 = all checks passed.
 */
import { spawn } from "node:child_process";
import { unlinkSync, openSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SERVER = path.join(ROOT, "target", "release", "secuscan-server");
const DB = "/tmp/secuscan-verify-e2e.db";
const PORT = 8080;
const BASE = `http://127.0.0.1:${PORT}/api/v1`;
const ADMIN = { email: "admin@secuscan.local", password: "VerifyIt2026!" };

let passed = 0;
let failed = 0;

function ok(cond, label) {
  if (cond) {
    passed++;
    console.log(`  PASS  ${label}`);
  } else {
    failed++;
    console.log(`  FAIL  ${label}`);
  }
}

function section(name) {
  console.log(`\n=== ${name} ===`);
}

async function req(method, p, { token, body, raw } = {}) {
  const headers = { "content-type": "application/json" };
  if (token) headers.authorization = `Bearer ${token}`;
  const res = await fetch(`${BASE}${p}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (raw) return { status: res.status, text: await res.text() };
  let json = {};
  try { json = await res.json(); } catch { /* empty body */ }
  return { status: res.status, json };
}

function bootServer() {
  for (const s of ["", "-wal", "-shm"]) {
    try { unlinkSync(DB + s); } catch { /* absent */ }
  }
  const env = {
    ...process.env,
    SECUSCAN_DB_URL: `sqlite:///${DB}`,
    SECUSCAN_JWT_SECRET: "e2e-verify-secret-32bytes-long-aaaa",
    SECUSCAN_ADDR: `127.0.0.1:${PORT}`,
    SECUSCAN_ADMIN_EMAIL: ADMIN.email,
    SECUSCAN_ADMIN_PASSWORD: ADMIN.password,
    RUST_LOG: "info",
  };
  const logFd = openSync("/tmp/secuscan-verify-server.log", "w");
  const child = spawn(SERVER, [], { cwd: ROOT, env, stdio: ["ignore", logFd, logFd], detached: true });
  child.on("error", (e) => console.error(`[server spawn error] ${e.message}`));
  child.on("exit", (code, sig) => console.error(`[server exited] code=${code} sig=${sig}`));
  return child;
}

// Tear down the spawned server on EVERY exit path. Node does not run
// 'exit' handlers on SIGTERM/SIGINT by default, so without explicit
// signal handlers the detached server would leak and poison the next
// run (port 8080 already in use).
function registerCleanup(server) {
  const killServer = () => {
    try { process.kill(-server.pid, "SIGTERM"); } catch { /* already gone */ }
  };
  process.on("exit", killServer);
  for (const sig of ["SIGTERM", "SIGINT", "SIGHUP"]) {
    process.on(sig, () => {
      killServer();
      process.exit(0);
    });
  }
}

async function waitReady() {
  for (let i = 0; i < 60; i++) {
    try {
      const r = await fetch(`${BASE}/health`);
      if (r.ok) return true;
    } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 500));
  }
  console.error("SERVER FAILED TO START — last log lines:");
  try { console.error(readFileSync("/tmp/secuscan-verify-server.log", "utf8").slice(-2000)); } catch {}
  return false;
}

async function assertPortFree() {
  try {
    const r = await fetch(`${BASE}/health`, { signal: AbortSignal.timeout(2000) });
    if (r.ok) {
      console.error(`FATAL: something is already listening on port ${PORT} (stale secuscan-server?). Kill it and re-run.`);
      process.exit(2);
    }
  } catch { /* port free — expected */ }
}

async function waitTask(token, id, timeoutMs = 30_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 1000));
    const { json } = await req("GET", `/tasks/${id}`, { token });
    if (["completed", "failed", "cancelled"].includes(json.status)) return json;
  }
  return {};
}

async function main() {
  section("boot");
  await assertPortFree();
  const server = bootServer();
  registerCleanup(server);
  ok(await waitReady(), "server reachable on /health");

  const { status: ls, json: login } = await req("POST", "/auth/login", { body: ADMIN });
  ok(ls === 200 && !!login.access_token, "login issues JWT");
  const token = login.access_token;

  // --- plugin catalog -------------------------------------------------------
  section("plugin catalog");
  const { json: cat } = await req("GET", "/plugins", { token });
  const plugins = cat.items ?? [];
  ok(plugins.length >= 39, `catalog has >=39 plugins (got ${plugins.length})`);
  const byId = Object.fromEntries(plugins.map((p) => [p.id, p]));
  ok(!!byId["people-hunter"]?.available, "people-hunter available");
  ok(!!byId["xss-exploiter"]?.available, "xss-exploiter available");
  ok(!!byId["website-scanner"]?.available, "website-scanner available");
  ok(!!byId["api-scanner"]?.available, "api-scanner available");
  ok(!!byId["smb-enum"], "smb-enum in catalog");
  ok(!!byId["ssh-audit"], "ssh-audit in catalog");

  // --- OpenAPI ---------------------------------------------------------------
  section("OpenAPI 3.1 spec");
  const { status: oj, json: spec } = await req("GET", "/openapi.json");
  ok(oj === 200, "GET /openapi.json -> 200");
  ok(spec.openapi === "3.1.0", "spec declares openapi 3.1.0");
  const nPaths = Object.keys(spec.paths ?? {}).length;
  const nSchemas = Object.keys(spec.components?.schemas ?? {}).length;
  ok(nPaths >= 80, `spec documents >=80 paths (got ${nPaths})`);
  ok(nSchemas >= 20, `spec documents >=20 schemas (got ${nSchemas})`);
  ok(!!spec.paths?.["/targets/:id/attack"]?.post, "POST /targets/:id/attack documented");
  const oy = await req("GET", "/openapi.yaml", { raw: true });
  ok(oy.status === 200 && oy.text.trimStart().startsWith("openapi:"), "GET /openapi.yaml serves YAML");
  const ol = await req("GET", "/openapi", { raw: true });
  ok(ol.status === 200 && ol.text.toLowerCase().includes("swagger-ui"), "GET /openapi serves Swagger UI landing");

  // --- workspace + targets ---------------------------------------------------
  section("workspace + targets");
  const { status: ws1, json: ws } = await req("POST", "/workspaces", { token, body: { name: "e2e-lab" } });
  ok(ws1 === 201 && !!ws.id, "workspace created");
  const wsId = ws.id;
  const { status: t1, json: ipTarget } = await req("POST", `/workspaces/${wsId}/targets`, {
    token, body: { name: "127.0.0.1", description: "loopback" },
  });
  ok(t1 === 201 && ipTarget.kind === "ip_address", "IP target registered");
  const { status: t2, json: hostTarget } = await req("POST", `/workspaces/${wsId}/targets`, {
    token, body: { name: "example.com", description: "hostname" },
  });
  ok(t2 === 201 && hostTarget.kind === "hostname", "hostname target registered");

  // --- Attack-Target -----------------------------------------------------------
  section("Attack-Target suites");
  const { status: aq, json: quick } = await req("POST", `/targets/${ipTarget.id}/attack`, {
    token, body: { suite: "quick" },
  });
  ok(aq === 201, "quick suite on IP -> 201");
  ok((quick.tasks ?? []).length >= 1, `quick launched >=1 task (got ${(quick.tasks ?? []).length})`);
  const quickIds = (quick.tasks ?? []).map((t) => t.plugin_id);
  ok(quickIds.includes("dns-lookup"), "quick on IP includes dns-lookup");
  ok((quick.skipped ?? []).every((s) => s.reason), "every skip carries a reason");

  const aw = await req("POST", `/targets/${ipTarget.id}/attack`, { token, body: { suite: "web" } });
  ok(aw.status === 400, "web suite on IP rejected (400)");

  const ai = await req("POST", `/targets/${ipTarget.id}/attack`, { token, body: { suite: "internal" } });
  ok(ai.status === 201 || ai.status === 400, "internal suite on IP -> 201 or 400 (all binaries missing)");

  const af = await req("POST", `/targets/${hostTarget.id}/attack`, { token, body: { suite: "full" } });
  ok(af.status === 201 && (af.json.tasks ?? []).length >= 1, "full suite on hostname -> 201 with tasks");
  const anh = await req("POST", `/targets/${hostTarget.id}/attack`, { token, body: { suite: "internal" } });
  ok(anh.status === 400, "internal suite on hostname rejected (400)");

  // --- Sniper ------------------------------------------------------------------
  section("Sniper Auto-Exploiter");
  const { status: sc, json: scan } = await req("POST", "/tasks", {
    token,
    body: { plugin_id: "http-headers", inputs: { target: `http://127.0.0.1:${PORT}/` }, consent_granted: true },
  });
  ok(sc === 201 && !!scan.id, "http-headers scan created");
  await waitTask(token, scan.id);
  const { json: fl } = await req("GET", "/findings?limit=5", { token });
  const findings = fl.items ?? [];
  ok(findings.length > 0, `findings collected (${findings.length})`);
  if (findings.length > 0) {
    const { status: sr, json: run } = await req("POST", "/sniper/run", {
      token, body: { finding_id: findings[0].id, consent_granted: true },
    });
    ok(sr === 201 && !!run.run_id, "sniper run launched");
    let finalRun = {};
    for (let i = 0; i < 90; i++) {
      await new Promise((r) => setTimeout(r, 1000));
      const g = await req("GET", `/sniper/runs/${run.run_id}`, { token });
      finalRun = g.json;
      if (["completed", "failed", "cancelled"].includes(finalRun.status)) break;
    }
    ok(finalRun.status === "completed", "sniper run completes");
    ok(Array.isArray(finalRun.steps) && finalRun.steps.length > 0, "sniper run has steps");
    ok(["proven", "not_proven", "inconclusive"].includes(finalRun.outcome ?? ""), "sniper run has outcome");
  }

  // --- Replay + diff -------------------------------------------------------------
  section("Replay + diff");
  const { status: rr, json: replay } = await req("POST", `/tasks/${scan.id}/retry`, { token });
  ok(rr === 201 && replay.id && replay.id !== scan.id, "retry creates a NEW task");
  await waitTask(token, replay.id);
  // The replay is the second run of the same plugin+target. Diffing the
  // replay against the original (auto-baseline = the previous run)
  // exercises GET /tasks/:id/diff end-to-end. Diffing the FIRST run
  // has no baseline and would 404.
  const { status: dr, json: diff } = await req("GET", `/tasks/${replay.id}/diff`, { token });
  ok(dr === 200 && diff && typeof diff === "object", "GET /tasks/:id/diff -> 200 (auto-baseline = previous run)");
  ok(diff?.baseline?.id === scan.id, "diff auto-baseline is the original run");

  // --- People Hunter ---------------------------------------------------------------
  section("People Hunter");
  const { status: ph, json: pht } = await req("POST", "/tasks", {
    token, body: { plugin_id: "people-hunter", inputs: { target: "127.0.0.1" }, consent_granted: true },
  });
  ok(ph === 201 && !!pht.id, "people-hunter scan created");
  const phDone = await waitTask(token, pht.id);
  ok(phDone.status === "completed", "people-hunter scan completes");

  // --- VPN profiles + admission gate -------------------------------------------------
  section("VPN profiles + admission gate");
  const { status: vc, json: vpn } = await req("POST", "/vpn-profiles", {
    token,
    body: { name: "e2e-tunnel", config_text: "client\ndev tun\nproto udp\nremote 203.0.113.10 1194\n" },
  });
  ok(vc === 201 && !!vpn.id, "VPN profile created");
  const vg = await req("POST", `/vpn-profiles/${vpn.id}/connect`, { token });
  ok(vg.status === 200 && vg.json.status === "error", "connect without openvpn binary fails gracefully");
  const vd = await req("POST", `/vpn-profiles/${vpn.id}/disconnect`, { token });
  ok(vd.status === 200, "disconnect -> 200");

  // Create a workspace-scoped task BEFORE pinning the VPN profile, so it
  // admits cleanly and we have a task id whose retry we can test against
  // the gate. (Creating a workspace-scoped task AFTER pinning would
  // itself be blocked by the admission gate, which is the very behavior
  // we want to assert via retry.)
  const wtResp = await req("POST", "/tasks", {
    token,
    body: {
      plugin_id: "http-headers",
      inputs: { target: `http://127.0.0.1:${PORT}/` },
      consent_granted: true,
      workspace_id: wsId,
    },
  });
  ok(
    wtResp.status === 201 && !!wtResp.json.id,
    `workspace-scoped task created (before pin) — got ${wtResp.status}`,
  );
  const wsTaskId = wtResp.json.id;
  if (wsTaskId) await waitTask(token, wsTaskId);

  // Now pin and verify the gate blocks retries + attacks.
  const pv = await req("PUT", `/workspaces/${wsId}/vpn`, { token, body: { vpn_profile_id: vpn.id } });
  ok(pv.status === 204, "pin VPN profile to workspace");
  const wp = await req("GET", `/workspaces/${wsId}/vpn`, { token });
  ok(wp.status === 200 && wp.json.profile?.id === vpn.id, "GET workspace pin returns profile");

  const blocked = await req("POST", `/tasks/${wsTaskId}/retry`, { token });
  ok(blocked.status === 409, "workspace-scoped task retry blocked while tunnel down (409)");
  const blockedAttack = await req("POST", `/targets/${ipTarget.id}/attack`, { token, body: { suite: "quick" } });
  ok(blockedAttack.status === 409, "attack-target blocked while tunnel down (409, propagated)");

  const uv = await req("PUT", `/workspaces/${wsId}/vpn`, { token, body: { vpn_profile_id: null } });
  ok(uv.status === 204, "unpin workspace");
  const unblocked = await req("POST", `/tasks/${wsTaskId}/retry`, { token });
  ok(unblocked.status === 201, "workspace-scoped task retry admitted after unpin (201)");
  const { json: t2b } = await req("GET", `/tasks/${unblocked.json.id}`, { token });
  ok(t2b.vpn_profile_id === null, "task records NULL vpn_profile_id when unpinned");

  // --- SPA + SSE + SARIF ----------------------------------------------------------
  section("SPA serving + SSE replay + SARIF report");

  // SPA is served at / with the SecuScan title and hashed asset bundle.
  const spa = await fetch(`http://127.0.0.1:${PORT}/`);
  const spaHtml = await spa.text();
  ok(spa.status === 200 && spaHtml.includes("<title>SecuScan</title>"), "SPA served with SecuScan title");
  ok(/assets\/index-[^"]+\.js/.test(spaHtml), "SPA references hashed JS bundle");

  // SSE replay of the finished scan contains the terminal event.
  const sseCtl = new AbortController();
  let sseHasFinished = false;
  try {
    const sseRes = await fetch(`${BASE}/tasks/${scan.id}/stream`, {
      headers: { authorization: `Bearer ${token}` },
      signal: sseCtl.signal,
    });
    const reader = sseRes.body.getReader();
    const decoder = new TextDecoder();
    const sseDeadline = Date.now() + 5000;
    let buf = "";
    while (Date.now() < sseDeadline) {
      const { value, done } = await Promise.race([
        reader.read(),
        new Promise((r) => setTimeout(() => r({ done: true }), sseDeadline - Date.now())),
      ]);
      if (done) break;
      buf += decoder.decode(value, { stream: true });
      if (buf.includes('"finished"') || buf.includes("event: finished")) {
        sseHasFinished = true;
        break;
      }
    }
  } catch { /* stream errors count as failure via flag */ }
  sseCtl.abort();
  ok(sseHasFinished, "SSE replay contains finished event");

  // SARIF report job: queue on the completed scan, poll to finished, download.
  const { status: sj, json: sarifJob } = await req("POST", `/tasks/${scan.id}/reports`, {
    token, body: { format: "sarif" },
  });
  ok(sj === 202 && !!sarifJob.id, "SARIF report job queued");
  let sarifStatus = "";
  for (let i = 0; i < 40; i++) {
    await new Promise((r) => setTimeout(r, 300));
    const g = await req("GET", `/reports/${sarifJob.id}`, { token });
    sarifStatus = g.json.status ?? "";
    if (["finished", "failed"].includes(sarifStatus)) break;
  }
  ok(sarifStatus === "finished", "SARIF report job finishes");
  let sarifOk = false;
  {
    const dl = await fetch(`${BASE}/reports/${sarifJob.id}/download`, {
      headers: { authorization: `Bearer ${token}` },
    });
    const text = await dl.text();
    sarifOk = dl.status === 200 && text.includes('"2.1.0"') && text.includes("sarif");
  }
  ok(sarifOk, "SARIF artifact downloads and declares version 2.1.0");

  // --- Cockpit APIs (3.2.0) -----------------------------------------------------------
  section("cockpit APIs");
  const ap = await req("GET", "/auth-profiles", { token });
  ok(ap.status === 200 && Array.isArray(ap.json.items), "GET /auth-profiles");
  const apc = await req("POST", "/auth-profiles", {
    token,
    body: { name: "e2e-cookie", method: "cookie", config: { cookies: [{ name: "sid", value: "x" }] } },
  });
  ok(apc.status === 201 && !!apc.json.id, "auth-profile created");

  const badHook = await req("POST", "/notifications", {
    token,
    body: {
      name: "ssrf",
      rules: {
        triggers: [{ kind: "scan_status", status: "completed" }],
        actions: [{ kind: "webhook", url: "http://127.0.0.1/hook" }],
      },
    },
  });
  ok(badHook.status === 400, "notification webhook to loopback rejected");

  const goodHook = await req("POST", "/notifications", {
    token,
    body: {
      name: "ok-hook",
      rules: {
        triggers: [{ kind: "vuln_found", severity: ">=high" }],
        actions: [{ kind: "webhook", url: "https://example.com/hook" }],
      },
    },
  });
  ok(goodHook.status === 201, "notification webhook to public host accepted");

  const br = await req("GET", "/branding", { token });
  ok(br.status === 200 && typeof br.json.org_name === "string", "GET /branding");

  const wl = await req("GET", "/wordlists", { token });
  ok(wl.status === 200 && Array.isArray(wl.json.items), "GET /wordlists");

  const badVpn = await req("POST", "/vpn-profiles", {
    token,
    body: { name: "evil", config_text: "client\nup /bin/true\nremote 203.0.113.10 1194\n" },
  });
  ok(badVpn.status === 400, "OpenVPN up directive rejected");

  const vt = await req("POST", `/vpn-profiles/${vpn.id}/test`, { token });
  ok(vt.status === 200 && vt.json.ok === true, "VPN test dry-run ok");

  const snNo = await req("POST", "/sniper/run", {
    token,
    body: { finding_id: (findings[0] && findings[0].id) || "missing", consent_granted: false },
  });
  ok(snNo.status === 400, "sniper without consent rejected");

  // --- summary ------------------------------------------------------------------------
  section("summary");
  console.log(`\n${passed} passed, ${failed} failed`);
  if (failed > 0) process.exitCode = 1;
}

main().catch((e) => {
  console.error("FATAL:", e);
  process.exit(1);
});

// Surface any unhandled promise rejection so silent crashes can't happen.
process.on("unhandledRejection", (reason) => {
  console.error("UNHANDLED REJECTION:", reason);
  process.exit(1);
});
