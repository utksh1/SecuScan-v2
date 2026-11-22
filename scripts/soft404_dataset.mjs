#!/usr/bin/env node
/**
 * Soft-404 labeled-corpus collector (Max-Parity Sprint 3.2, issue #31).
 *
 * Crawls a TARGET for 404-shaped responses and known-content pages, records
 * the extracted features and a human-reviewed label, and writes a JSON
 * corpus to stdout (or --out FILE). The corpus feeds OFFLINE weight
 * recalibration for `secuscan_core::soft404` — the shipped weights are
 * hand-calibrated against the fixture set in the unit tests; run this
 * against representative targets when you want to re-fit them.
 *
 * Usage:
 *   node scripts/soft404_dataset.mjs --target https://lab.example --paths 200 [--out corpus.json]
 *
 * Labels are heuristic-assisted but meant for human review: pages whose
 * status is 404/410 are labeled "hit" (true 404s are not soft — only 200s
 * with error-shaped content are soft-404 candidates), 200s are labeled
 * "candidate" and require review before use in precision metrics.
 *
 * Authorized use only — crawl systems you are permitted to assess.
 */
import { writeFileSync } from "node:fs";

const args = process.argv.slice(2);
const get = (k) => {
  const i = args.indexOf(k);
  return i >= 0 ? args[i + 1] : undefined;
};
const target = get("--target");
const maxPaths = Number(get("--paths") ?? 200);
const out = get("--out");

if (!target) {
  console.error("usage: soft404_dataset.mjs --target <base-url> [--paths 200] [--out file]");
  process.exit(2);
}

// Common discovery paths (same spirit as the website scanner's list) plus
// generated gibberish paths that virtually every server soft-404s.
const DISCOVERY = [
  "/.env", "/.git/config", "/phpinfo.php", "/admin", "/admin.php", "/login",
  "/backup", "/backups", "/config.php.bak", "/wp-admin/", "/administrator/",
  "/api", "/api/v1", "/debug", "/server-status", "/test", "/old", "/dev",
  "/dashboard", "/console", "/sql", "/db.sql", "/dump.sql", "/.DS_Store",
];
const GIBBERISH = Array.from({ length: 40 }, (_, i) => `/not-real-${i}-xyzzy`);

const rows = [];
let fetched = 0;
const paths = [...DISCOVERY, ...GIBBERISH].slice(0, maxPaths);

for (const path of paths) {
  const url = target.replace(/\/$/, "") + path;
  try {
    const res = await fetch(url, { redirect: "manual", signal: AbortSignal.timeout(8000) });
    const status = res.status;
    const body = await res.text();
    fetched++;
    const features = {
      body_len: body.length,
      word_count: body.split(/[\s<>"\/]+/).filter((w) => w.length > 1).length,
      link_count: (body.match(/<a /gi) ?? []).length,
      form_count: (body.match(/<form/gi) ?? []).length,
      script_count: (body.match(/<script/gi) ?? []).length,
      title_error_hits: /<title[^>]*>.*?(not found|404|cannot be found|does not exist|oops).*?<\/title>/i.test(body) ? 1 : 0,
      body_error_hits: ["not found", "404", "does not exist", "oops", "nothing here"].filter((k) => body.toLowerCase().includes(k)).length,
      requested_path_echo: path.split("/").filter(Boolean).at(-1)?.length > 3
        ? body.toLowerCase().includes(path.split("/").filter(Boolean).at(-1).toLowerCase())
        : false,
    };
    const label =
      status === 404 || status === 410
        ? "hit (true 404)"
        : status >= 200 && status < 300
          ? "candidate (review: 200 with this path)"
          : `other (${status})`;
    rows.push({ url, status, label, features });
  } catch (e) {
    rows.push({ url, error: String(e) });
  }
}

const corpus = {
  generated: new Date().toISOString(),
  target,
  count: rows.length,
  fetched,
  note: "404/410 rows are true negatives for soft-404; 200 rows with error-shaped content are soft-404 candidates requiring review before use in precision metrics.",
  rows,
};

if (out) writeFileSync(out, JSON.stringify(corpus, null, 2));
else console.log(JSON.stringify(corpus, null, 2));
console.error(`collected ${rows.length} rows from ${target} (${fetched} fetched)`);
