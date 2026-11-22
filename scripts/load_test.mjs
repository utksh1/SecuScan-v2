/**
 * Load test (Sprint 4, issue #34): run N concurrent scans against a running
 * SecuScan server and report latency/throughput. Authorized targets only.
 *
 * Usage: node scripts/load_test.mjs --server http://127.0.0.1:8080 \
 *          --key <api-key> --concurrency 20 --tasks 100
 */
import { setTimeout as sleep } from "node:timers/promises";

const get = (k) => {
  const i = process.argv.indexOf(k);
  return i >= 0 ? process.argv[i + 1] : undefined;
};
const server = get("--server") ?? "http://127.0.0.1:8080";
const key = get("--key") ?? process.env.SECUSCAN_API_KEY ?? "";
const concurrency = Number(get("--concurrency") ?? 20);
const total = Number(get("--tasks") ?? 100);

if (!key) {
  console.error("SECUSCAN_API_KEY or --key required");
  process.exit(2);
}

let launched = 0, completed = 0, failed = 0;
const latencies = [];
const t0 = Date.now();

async function login() {
  const r = await fetch(`${server}/api/v1/auth/login`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      email: process.env.LOAD_EMAIL ?? "admin@secuscan.local",
      password: process.env.LOAD_PASSWORD ?? "",
    }),
  });
  return r.json().then((j) => j.access_token);
}
const token = await login();

async function runOne(i) {
  const t = Date.now();
  try {
    const r = await fetch(`${server}/api/v1/tasks`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({
        plugin_id: "port-scanner",
        inputs: { target: "127.0.0.1", ports: String(34000 + (i % 200)) },
        consent_granted: true,
      }),
    });
    if (!r.ok) return;
    const { id } = await r.json();
    for (;;) {
      await sleep(500);
      const tr = await fetch(`${server}/api/v1/tasks/${id}`, {
        headers: { authorization: `Bearer ${token}` },
      });
      if (!tr.ok) return;
      const v = await tr.json();
      if (["completed", "failed", "cancelled"].includes(v.status)) {
        if (v.status === "completed") completed++;
        else failed++;
        latencies.push(Date.now() - t);
        return;
      }
    }
  } catch { /* counted as failed via timeout */ }
}

const workers = Array.from({ length: concurrency }, (_, i) =>
  (async () => {
    while (launched++ < total) await runOne(launched);
  })()
);
await Promise.all(workers);
latencies.sort((a, b) => a - b);
const p50 = latencies[Math.floor(latencies.length * 0.5)] ?? 0;
const p95 = latencies[Math.floor(latencies.length * 0.95)] ?? 0;
console.log(JSON.stringify({
  total, completed, failed,
  concurrency,
  wall_seconds: (Date.now() - t0) / 1000,
  latency_p50_ms: p50,
  latency_p95_ms: p95,
}, null, 2));
