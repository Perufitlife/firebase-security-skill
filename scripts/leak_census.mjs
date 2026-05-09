#!/usr/bin/env node
// Leak census: scan N random Firebase projects from GitHub code search,
// probe a fixed set of common collections anonymously, tally leaks.
// Output: console table + JSON file for content marketing.
import { writeFileSync } from "node:fs";
import { execSync } from "node:child_process";

const COMMON = [
  "users", "profiles", "accounts",
  "posts", "messages", "chats",
  "orders", "purchases", "payments", "subscriptions", "invoices",
  "products", "items", "carts",
  "notifications", "events", "logs",
  "files", "uploads", "documents",
  "publicData", "testMode",
];

async function fetchFirebaseConfigs(limit = 50) {
  // Use gh CLI for code search (already authenticated).
  const out = execSync(`gh api "search/code?q=projectId+filename:firebase-config&per_page=${limit}"`, { encoding: "utf8" });
  const data = JSON.parse(out);
  return (data.items || []).map((i) => ({
    repo: i.repository.full_name,
    path: i.path,
  }));
}

async function fetchProjectId(repo, path) {
  // Use raw.githubusercontent.com to fetch the file content
  const branches = ["main", "master"];
  for (const branch of branches) {
    const url = `https://raw.githubusercontent.com/${repo}/${branch}/${path}`;
    try {
      const r = await fetch(url);
      if (r.status !== 200) continue;
      const text = await r.text();
      const m = text.match(/projectId\s*[:=]\s*["']([a-z0-9-]+)["']/i);
      if (m) return m[1];
    } catch {}
  }
  return null;
}

async function probe(pid, collection) {
  try {
    const url = `https://firestore.googleapis.com/v1/projects/${encodeURIComponent(pid)}/databases/(default)/documents/${encodeURIComponent(collection)}?pageSize=1`;
    const r = await fetch(url);
    if (r.status !== 200) return { leak: false, status: r.status };
    const data = await r.json();
    if ((data.documents || []).length > 0) {
      const fields = Object.keys(data.documents[0].fields || {});
      return { leak: true, status: 200, docCount: data.documents.length, fields };
    }
    return { leak: false, status: 200, note: "empty-but-accessible" };
  } catch (e) {
    return { leak: false, status: -1, error: e.message };
  }
}

async function main() {
  const N = parseInt(process.argv[2] || "30", 10);
  console.log(`Fetching ${N} Firebase configs from GitHub...`);
  const configs = await fetchFirebaseConfigs(N);
  console.log(`Got ${configs.length} configs. Extracting project IDs...`);

  const seenPids = new Set();
  const projects = [];
  for (const c of configs) {
    const pid = await fetchProjectId(c.repo, c.path);
    if (pid && !seenPids.has(pid)) {
      seenPids.add(pid);
      projects.push({ ...c, pid });
    }
  }
  console.log(`Got ${projects.length} unique project IDs.`);

  const results = [];
  let totalLeaks = 0;
  let projectsLeaking = 0;

  for (const p of projects) {
    const findings = [];
    for (const col of COMMON) {
      const r = await probe(p.pid, col);
      if (r.leak) {
        findings.push({ col, ...r });
        totalLeaks++;
      }
    }
    if (findings.length > 0) projectsLeaking++;
    results.push({ pid: p.pid, repo: p.repo, leak_count: findings.length, leaks: findings });
    console.log(`  ${p.pid.padEnd(35)} ${findings.length} leaks`);
  }

  const aggregate = {};
  for (const r of results) {
    for (const f of r.leaks) {
      aggregate[f.col] = (aggregate[f.col] || 0) + 1;
    }
  }

  const summary = {
    scanned_at: new Date().toISOString(),
    n_projects: projects.length,
    n_leaking: projectsLeaking,
    n_total_leaks: totalLeaks,
    pct_leaking: projects.length ? ((projectsLeaking / projects.length) * 100).toFixed(1) : "0",
    leaks_by_collection: Object.entries(aggregate).sort((a, b) => b[1] - a[1]),
  };

  console.log("\n=== SUMMARY ===");
  console.log(JSON.stringify(summary, null, 2));

  writeFileSync("./leak_census_result.json", JSON.stringify({ summary, results }, null, 2));
  console.log("\nFull data saved to ./leak_census_result.json");
}

main().catch((e) => { console.error(e); process.exit(1); });
