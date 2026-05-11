#!/usr/bin/env node
// Firebase Security — KEYLESS DISCOVER MODE.
//
// Parses the user's repo statically to find Firebase client SDK usage:
//   - collection(db, 'users') / collection(db, 'orders')
//   - doc(db, 'users/123')
//   - getFirestore(app) + firebase config { projectId: 'xxx' }
//   - firebaseConfig / env references
// Then probes Firestore REST anonymously to confirm leaks:
//   - GET https://firestore.googleapis.com/v1/projects/{pid}/databases/(default)/documents/{collection}
// No service-account, no admin SDK.
//
// Triggered by `firebase-security --discover [path]`

import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

const PATTERNS = {
  // collection(db, 'users')  |  collection(db, "orders")
  collection: /\bcollection\s*\(\s*\w+\s*,\s*['"`]([^'"`]+)['"`]/g,
  // doc(db, 'users/abc') — extract just the top-level collection
  doc: /\bdoc\s*\(\s*\w+\s*,\s*['"`]([^'"`/]+)/g,
  // projectId: 'foo-bar-12345'   (inside firebase config)
  projectId: /projectId\s*:\s*['"`]([a-z0-9-]+)['"`]/g,
  // NEXT_PUBLIC_FIREBASE_PROJECT_ID=foo-bar
  projectIdEnv: /(?:NEXT_PUBLIC_|VITE_|REACT_APP_)?FIREBASE_PROJECT_ID\s*=\s*['"`]?([a-z0-9-]+)/g,
};

const SKIP_DIRS = new Set([
  "node_modules", ".git", "dist", "build", ".next", "out", ".turbo",
  "coverage", ".cache", ".vercel", "__pycache__", ".firebase"
]);

const SCAN_EXTENSIONS = new Set([
  ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".vue", ".svelte",
  ".env", ".env.local", ".env.example", ".env.production"
]);

function walk(dir, files = []) {
  let entries;
  try { entries = readdirSync(dir, { withFileTypes: true }); } catch { return files; }
  for (const e of entries) {
    const p = join(dir, e.name);
    if (e.isDirectory()) {
      if (SKIP_DIRS.has(e.name)) continue;
      walk(p, files);
    } else {
      const lower = e.name.toLowerCase();
      const hasExt = [...SCAN_EXTENSIONS].some(x => lower.endsWith(x));
      if (hasExt || lower.startsWith(".env")) files.push(p);
    }
  }
  return files;
}

function readSafe(p) { try { return readFileSync(p, "utf8"); } catch { return ""; } }

export function staticScan(root) {
  const files = walk(root);
  const out = {
    projectId: null,
    collections: new Set(),
    sourceFiles: 0,
    envFiles: 0,
    rootDir: root,
  };

  for (const file of files) {
    const content = readSafe(file);
    if (!content) continue;
    const isEnv = file.toLowerCase().includes(".env");
    if (isEnv) out.envFiles++; else out.sourceFiles++;

    if (!out.projectId) {
      const p = PATTERNS.projectId.exec(content);
      if (p) out.projectId = p[1];
    }
    if (!out.projectId && isEnv) {
      const pe = PATTERNS.projectIdEnv.exec(content);
      if (pe) out.projectId = pe[1].replace(/[\s'"`].*$/, "");
    }

    for (const m of content.matchAll(PATTERNS.collection)) out.collections.add(m[1].split("/")[0]);
    for (const m of content.matchAll(PATTERNS.doc)) out.collections.add(m[1]);
  }

  return { ...out, collections: [...out.collections] };
}

async function probeCollection(projectId, collection) {
  try {
    const url = `https://firestore.googleapis.com/v1/projects/${encodeURIComponent(projectId)}/databases/(default)/documents/${encodeURIComponent(collection)}?pageSize=1`;
    const r = await fetch(url, {
      method: "GET",
      headers: { "User-Agent": "firebase-security/0.2 (discover)" },
    });
    const body = await r.text();
    let docCount = 0;
    if (r.status === 200) {
      try {
        const j = JSON.parse(body);
        docCount = (j.documents || []).length;
      } catch {}
    }
    return {
      status: r.status,
      rules_open: r.status === 200 && docCount > 0,
      doc_count_sample: docCount,
      body_preview: body.slice(0, 200),
    };
  } catch (e) {
    return { status: 0, error: e.message };
  }
}

export async function discover({ root = process.cwd(), projectId = null } = {}) {
  const scan = staticScan(root);
  const pid = projectId || scan.projectId;
  const findings = [];
  const probes = [];

  if (!pid) {
    return {
      mode: "discover",
      error: "No Firebase project ID detected in repo. Pass --project-id or set FIREBASE_PROJECT_ID in .env",
      files_scanned: { source: scan.sourceFiles, env: scan.envFiles },
      collections_found: scan.collections,
    };
  }

  for (const col of scan.collections) {
    const p = await probeCollection(pid, col);
    probes.push({ collection: col, ...p });
    if (p.rules_open) {
      findings.push({
        check: "collection_rules_open",
        severity: "critical",
        title: `Collection \`${col}\` is readable anonymously`,
        explain: `GET firestore.googleapis.com/v1/projects/${pid}/databases/(default)/documents/${col} returned documents without auth. Your firestore.rules \`match /${col}/{doc}\` allows read for anyone, or your top-level wildcard rule is open.`,
        target: col,
        details: { http_status: p.status, doc_count_sample: p.doc_count_sample, body_preview: p.body_preview },
        fix: `// Edit firestore.rules:
match /${col}/{document=**} {
  allow read: if request.auth != null && resource.data.ownerId == request.auth.uid;
  allow write: if request.auth != null && request.resource.data.ownerId == request.auth.uid;
}
// Then: firebase deploy --only firestore:rules`,
        probe: { confirmed: true },
      });
    } else if (p.status === 200 && p.doc_count_sample === 0) {
      findings.push({
        check: "collection_reachable_no_data",
        severity: "info",
        title: `Collection \`${col}\` reachable anon but empty (or doesn't exist)`,
        explain: "GET 200 with 0 documents. Could mean open rules + empty collection, or collection name typo. Re-run after seeding.",
        target: col,
      });
    }
  }

  findings.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);

  const summary = findings.reduce(
    (acc, f) => ({ ...acc, [f.severity]: (acc[f.severity] || 0) + 1 }),
    { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  );

  return {
    mode: "discover",
    scanned_at: new Date().toISOString(),
    scanned_by: "firebase-security v0.2 (discover)",
    root_dir: root,
    project_id: pid,
    files_scanned: { source: scan.sourceFiles, env: scan.envFiles },
    collections_found: scan.collections,
    probes,
    summary,
    findings,
  };
}
