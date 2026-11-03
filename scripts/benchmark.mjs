#!/usr/bin/env node
/**
 * SecuScan v2 — baseline benchmark harness (Max-Parity Plan, Phase 0).
 *
 * Boots a fresh server + the local vuln-app fixture and captures the four
 * Phase-0 baseline metrics so later phases can prove improvement:
 *
 *   1. FP suppression rate   — FP-mark a finding, re-scan, count how many
 *                              re-appeared findings were auto-suppressed.
 *   2. Scan latency          — native scanner (http-headers on vuln-app),
 *                              p50/p95 over N runs.
 *   3. OOB hit rate          — create an OOB handler, hit the callback URL
 *                              like an injected payload would, count the
 *                              registered hit (pipeline end-to-end proof).
 *   4. Report generation     — per-format wall time for a task with
 *                              findings.
 *
 * Usage:   node scripts/benchmark.mjs [--runs 5]
 * Output:  JSON baseline written to data/baseline-metrics.json (gitignored
 *          by convention) + human-readable table on stdout.
 *
 * Zero dependencies (Node >= 18 global fetch), mirroring verify.mjs.
 */
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { unlinkSync, openSync, writeFileSync, mkdirSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SERVER = path.join(ROOT, "target", "release", "secuscan-server");
const VULN_APP = path.join(ROOT, "scripts", "vuln-app.mjs");
const DB = "/tmp/secuscan-bench.db";
const PORT = 8091;
const BASE = `http://127.0.0.1:${PORT}/api/v1`;
const ADMIN = { email: "admin@secuscan.local", password: "BenchIt2026!" };

const args = process.argv.slice(2);
let RUNS = 5;
{
  const i = args.indexOf("--runs");
  if (i !== -1 && args[i + 1]) RUNS = Math.max(1, parseInt(args[i + 1], 10) || 5);
}

function ms(t0) {
  return Number((performance.now() - t0).toFixed(1));
}

function pctl(sorted, p) {
  if (sorted.length === 1) return sorted[0];
  const idx = Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1);
  return sorted[Math.max(0, idx)];
}

async function req(method, p, { token, body } = {}) {
  const headers = { "content-type": "application/json" };
  if (token) headers.authorization = `Bearer ${token}`;
  const res = await fetch(`${BASE}${p}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  let json = {};
  try { json = await res.json(); } catch { /* empty body */ }
  return { status: res.status, json };
}

async function waitTask(token, id, timeoutMs = 120_000) {
  const t0 = performance.now();
  for (;;) {
    if (performance.now() - t0 > timeoutMs) throw new Error(`task ${id} timed out`);
    const { json } = await req("GET", `/tasks/${id}`, { token });
    if (["completed", "failed", "cancelled"].includes(json.status)) return { json, wallMs: ms(t0) };
    await new Promise((r) => setTimeout(r, 250));
  }
}

function boot(env) {
  const child = spawn(SERVER, [], { cwd: ROOT, env, stdio: ["ignore", "ignore", "ignore"], detached: true });
  child.on("error", (e) => { console.error(`[server spawn error] ${e.message}`); process.exit(1); });
  return child;
}

function bootVulnApp() {
  const child = spawn(process.execPath, [VULN_APP], { stdio: "ignore", detached: true });
  child.on("error", (e) => { console.error(`[vuln-app spawn error] ${e.message}`); process.exit(1); });
  return child;
}

async function awaitUp(url, timeoutMs = 30_000) {
  const t0 = performance.now();
  for (;;) {
    if (performance.now() - t0 > timeoutMs) throw new Error(`${url} never came up`);
    try {
      const r = await fetch(url);
      if (r.status < 500) return;
    } catch { /* not yet */ }
    await new Promise((r) => setTimeout(r, 200));
  }
}

const kill = (child) => { try { process.kill(-child.pid, "SIGTERM"); } catch { try { child.kill("SIGTERM"); } catch {} } };

async function main() {
  console.log(`SecuScan benchmark — ${RUNS} run(s) per latency sample\n`);

  for (const s of ["", "-wal", "-shm"]) {
    try { unlinkSync(DB + s); } catch { /* absent */ }
  }

  const env = {
    ...process.env,
    PATH: [path.join(os.homedir(), ".local", "bin"), process.env.PATH].join(":"),
    SECUSCAN_DB_URL: `sqlite:///${DB}`,
    SECUSCAN_ENV: "production",
    SECUSCAN_JWT_SECRET: randomBytes(32).toString("hex"),
    SECUSCAN_ADDR: `127.0.0.1:${PORT}`,
    SECUSCAN_ADMIN_EMAIL: ADMIN.email,
    SECUSCAN_ADMIN_PASSWORD: ADMIN.password,
    RUST_LOG: "warn",
  };
  const server = boot(env);
  const vulnApp = bootVulnApp();
  const results = {};

  try {
    await awaitUp(`${BASE.replace("/api/v1", "")}/health`);
    // The vuln-app fixture listens on 127.0.0.1:8899 (see scripts/vuln-app.mjs).
    await awaitUp("http://127.0.0.1:8899/");
    const vulnBase = "http://127.0.0.1:8899";

    const login = await req("POST", "/auth/login", { body: ADMIN });
    if (login.status !== 200) throw new Error("admin login failed");
    const token = login.json.access_token;

    // ---- 2) Scan latency (native scanner over vuln-app) ----------------
    console.log("[1/4] scan latency — http-headers on vuln-app");
    const latencies = [];
    for (let i = 0; i < RUNS; i++) {
      const t0 = performance.now();
      const created = await req("POST", "/tasks", {
        token,
        body: { plugin_id: "http-headers", inputs: { target: vulnBase }, consent_granted: true },
      });
      if (created.status !== 201) throw new Error(`task create failed: ${created.status}`);
      const { json } = await waitTask(token, created.json.id);
      if (json.status !== "completed") throw new Error(`task ${created.json.id} ${json.status}`);
      latencies.push(ms(t0));
    }
    const sorted = [...latencies].sort((a, b) => a - b);
    results.scan_latency_ms = {
      runs: latencies,
      p50: pctl(sorted, 50),
      p95: pctl(sorted, 95),
      min: sorted[0],
      max: sorted[sorted.length - 1],
    };
    console.log(`      p50=${results.scan_latency_ms.p50}ms p95=${results.scan_latency_ms.p95}ms\n`);

    // ---- 1) FP suppression rate ----------------------------------------
    console.log("[2/4] FP suppression — mark a finding, re-scan, count suppressed");
    const c1 = await req("POST", "/tasks", {
      token,
      body: { plugin_id: "http-headers", inputs: { target: vulnBase }, consent_granted: true },
    });
    const r1 = await waitTask(token, c1.json.id);
    const f1 = await req("GET", `/findings?task_id=${c1.json.id}`, { token });
    const items = f1.json.items ?? [];
    if (items.length === 0) throw new Error("baseline scan produced no findings");
    const target = items[0];
    const tri = await req("PATCH", `/findings/${target.id}/triage`, {
      token,
      body: { analyst_status: "false_positive", reason: "benchmark: intentional FP mark" },
    });
    if (tri.status !== 200) throw new Error(`triage failed: ${tri.status}`);
    const c2 = await req("POST", "/tasks", {
      token,
      body: { plugin_id: "http-headers", inputs: { target: vulnBase }, consent_granted: true },
    });
    await waitTask(token, c2.json.id);
    const f2 = await req("GET", `/findings?task_id=${c2.json.id}`, { token });
    const rerun = f2.json.items ?? [];
    const same = rerun.filter((f) => f.title === target.title);
    const suppressed = same.filter((f) => f.analyst_status === "false_positive").length;
    results.fp_suppression = {
      marked_title: target.title,
      rerun_matches: same.length,
      rerun_suppressed: suppressed,
      rate: same.length ? suppressed / same.length : null,
    };
    console.log(`      ${suppressed}/${same.length} re-scan copies auto-suppressed\n`);
    // Cleanup: un-mark so the DB stays neutral for later sections.
    await req("PATCH", `/findings/${target.id}/triage`, {
      token,
      body: { analyst_status: "confirmed" },
    });

    // ---- 3) OOB hit rate -------------------------------------------------
    console.log("[3/4] OOB callback — handler + beacon round-trip");
    const oobRuns = [];
    for (let i = 0; i < Math.min(RUNS, 5); i++) {
      const h = await req("POST", "/oob-handlers", {
        token,
        body: { name: `bench-${i}`, kind: "http_logger", config: {} },
      });
      if (h.status !== 201 && h.status !== 200) throw new Error(`handler create failed: ${h.status}`);
      const secret = h.json.secret;
      if (!secret) throw new Error(`no secret in response: ${JSON.stringify(h.json)}`);
      const t0 = performance.now();
      // Simulate the injected payload calling home (twice, like a real beacon).
      await fetch(`${BASE}/oob/${secret}`, { method: "GET", headers: { "user-agent": "bench-beacon" } });
      await fetch(`${BASE}/oob/${secret}?data=exfil-${i}`, { method: "POST" });
      let hits = null;
      for (let probe = 0; probe < 40; probe++) {
        const list = await req("GET", `/oob-handlers/${h.json.id}/hits`, { token });
        const n = (list.json.items ?? []).length;
        if (n > 0) { hits = n; break; }
        await new Promise((r) => setTimeout(r, 100));
      }
      oobRuns.push({ hits, wallMs: ms(t0) });
      await req("DELETE", `/oob-handlers/${h.json.id}`, { token });
    }
    const hitCount = oobRuns.filter((r) => (r.hits ?? 0) > 0).length;
    results.oob_pipeline = {
      runs: oobRuns,
      hit_rate: oobRuns.length ? hitCount / oobRuns.length : null,
    };
    console.log(`      callback registered on ${hitCount}/${oobRuns.length} handlers\n`);

    // ---- 4) Report generation time --------------------------------------
    console.log("[4/4] report generation — per format");
    const reportTimes = {};
    for (const fmt of ["md", "csv", "json", "sarif", "html"]) {
      const t0 = performance.now();
      const res = await fetch(`${BASE}/tasks/${c1.json.id}/report/${fmt}`, {
        headers: { authorization: `Bearer ${token}` },
      });
      const text = await res.text();
      reportTimes[fmt] = { ms: ms(t0), bytes: text.length, status: res.status };
    }
    results.report_generation = reportTimes;
    console.log(
      "      " +
        Object.entries(reportTimes)
          .map(([f, t]) => `${f}=${t.ms}ms(${t.bytes}b)`)
          .join(" ") +
        "\n"
    );

    // ---- persist baseline -------------------------------------------------
    results.captured_at = new Date().toISOString();
    results.server_version = (await req("GET", "/health", { token })).json.version ?? null;
    results.runs = RUNS;
    mkdirSync(path.join(ROOT, "data"), { recursive: true });
    const out = path.join(ROOT, "data", "baseline-metrics.json");
    writeFileSync(out, JSON.stringify(results, null, 2) + "\n");
    console.log(`baseline written: ${out}`);
  } finally {
    kill(server);
    kill(vulnApp);
  }
}

main().catch((e) => {
  console.error(`\nBENCHMARK FAILED: ${e.message}`);
  process.exit(1);
});
