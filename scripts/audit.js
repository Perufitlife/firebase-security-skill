#!/usr/bin/env node
// Firebase / Firestore Rules Security Auditor — pure Node.js, no deps.
//
// Usage:
//   firebase-security firestore.rules
//   firebase-security --rules path/to/firestore.rules [--html report.html]
//   firebase-security --project-id PID [--html report.html]   (also probes default DB if URL accessible)
//
// Static analyzer for firestore.rules + optional active probe against a deployed Firestore instance.

import { readFileSync, writeFileSync, existsSync } from "node:fs";

const UA = "firebase-security/0.1";
const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

const CHECKS = {
  open_match_all: {
    severity: "critical",
    title: "Wildcard match `/{document=**}` with `if true` — ALL documents publicly readable/writable",
    explain: "The infamous Firebase data leak pattern. `match /{document=**} { allow read, write: if true; }` opens every collection in the database to anyone with the project ID. Common in dev rules left in production.",
  },
  if_true_literal: {
    severity: "critical",
    title: "Rule contains `if true` literal — bypasses all security checks",
    explain: "`allow read, write: if true;` always evaluates to true. Anyone with the project ID can read or write this path without auth. Almost always a leftover from local development.",
  },
  auth_only_no_ownership: {
    severity: "high",
    title: "Rule allows any signed-in user (`if request.auth != null`) without ownership check",
    explain: "`if request.auth != null` lets any signed-up user read/write the document, including anonymous-auth users. Identical to the PocketBase `@request.auth.id != \"\"` anti-pattern. Tighten with `request.auth.uid == resource.data.ownerId` or similar ownership check.",
  },
  test_mode_30_days: {
    severity: "high",
    title: "Test mode rules: timestamp-based expiry already passed or about to expire",
    explain: "`request.time < timestamp.date(YYYY, MM, DD)` is the default test-mode rule Firebase generates. After the date passes, it becomes effectively `if false` (denies everything) — but BEFORE it passes, it's `if true` (open to all). If the date is in the future, this is wide open right now.",
  },
  read_open_write_protected: {
    severity: "medium",
    title: "Read open (`if true`) but write protected — readable database",
    explain: "Splitting allow read/write means write may be locked but read is not. Anyone can dump every document. Often happens with public collections that should be query-restricted (e.g. only certain fields exposed).",
  },
  storage_rule_open_read: {
    severity: "high",
    title: "Storage rules: open read on user uploads",
    explain: "Storage rules with `match /{userId}/{file} { allow read: if true; }` make every user-uploaded file public. Often used for avatars but inadvertently exposes private uploads (PII docs, payment proofs, etc).",
  },
  default_deny_missing: {
    severity: "info",
    title: "No explicit default-deny rule — relying on Firebase implicit deny",
    explain: "Firebase denies by default if no rule matches, but having an explicit `match /{document=**} { allow read, write: if false; }` at the bottom is a defensive habit that prevents accidents from rule reorders.",
  },
};

function parseRules(content) {
  // Lightweight tokenizer: extract match-block paths + their allow statements.
  // We don't build a full AST; we look for line-level patterns inside match blocks.
  const blocks = [];
  const lines = content.split(/\r?\n/);
  const stack = [];
  let currentBlock = null;

  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    const line = raw.trim();
    if (!line || line.startsWith("//")) continue;

    // Match block opening: `match /path/{var}`
    const matchOpen = line.match(/^match\s+(\/\S+)\s*\{?/);
    if (matchOpen) {
      const block = { path: matchOpen[1], allows: [], line: i + 1, raw: [] };
      stack.push(block);
      blocks.push(block);
      currentBlock = block;
      continue;
    }

    // Allow statement
    const allowMatch = line.match(/^allow\s+([\w,\s]+):\s*if\s+(.+?);?$/);
    if (allowMatch && currentBlock) {
      const ops = allowMatch[1].split(",").map(s => s.trim());
      const condition = allowMatch[2].trim().replace(/;$/, "");
      currentBlock.allows.push({ ops, condition, line: i + 1 });
    }

    // Crude scope tracking
    if (line.includes("{") && !matchOpen) {
      // Inline brace open after non-match (function definitions etc.) — track for balance
    }
    if (line.includes("}")) {
      // pop top
      if (stack.length) {
        stack.pop();
        currentBlock = stack[stack.length - 1] || null;
      }
    }
  }

  return blocks;
}

function detectFindings(rules, blocks) {
  const findings = [];
  const today = new Date();

  // Check 1: open_match_all
  for (const b of blocks) {
    const isCatchAll = /\/\{[^}]*=\*\*\}$/.test(b.path) || b.path === "/{document=**}";
    for (const a of b.allows) {
      const cond = a.condition.replace(/\s+/g, "");
      if (isCatchAll && (cond === "true" || cond === "1==1")) {
        findings.push({
          check: "open_match_all",
          ...CHECKS.open_match_all,
          target: `${b.path} (${a.ops.join(",")})`,
          details: { path: b.path, ops: a.ops, condition: a.condition, line: a.line },
          fix_snippet: `// firestore.rules — replace catch-all "if true" with explicit deny + per-collection rules:
match /{document=**} {
  allow read, write: if false;        // explicit default-deny
}
match /users/{uid} {
  allow read, write: if request.auth != null && request.auth.uid == uid;
}
match /publicConfig/{doc} {
  allow read: if true;                 // ONLY read, ONLY this collection
  allow write: if false;
}`,
        });
        continue;
      }

      // Check 2: bare `if true`
      if (cond === "true" && !isCatchAll) {
        findings.push({
          check: "if_true_literal",
          ...CHECKS.if_true_literal,
          target: `${b.path} (${a.ops.join(",")})`,
          details: { path: b.path, ops: a.ops, condition: a.condition, line: a.line },
          fix_snippet: `// firestore.rules line ${a.line}:
// Replace 'if true' with an explicit ownership check.
match ${b.path} {
  allow ${a.ops.join(", ")}: if request.auth != null && request.auth.uid == resource.data.ownerId;
}`,
        });
        continue;
      }

      // Check 3: auth-only, no ownership
      const authOnlyPatterns = [
        /^request\.auth!=null$/,
        /^request\.auth\.uid!=null$/,
        /^request\.auth!=null&&request\.auth\.uid!=null$/,
      ];
      if (authOnlyPatterns.some(p => p.test(cond))) {
        // Confirm there's no further ownership check
        const hasOwnership = /resource\.data\.|request\.auth\.uid==/i.test(a.condition);
        if (!hasOwnership) {
          findings.push({
            check: "auth_only_no_ownership",
            ...CHECKS.auth_only_no_ownership,
            target: `${b.path} (${a.ops.join(",")})`,
            details: { path: b.path, ops: a.ops, condition: a.condition, line: a.line },
            fix_snippet: `// firestore.rules line ${a.line}:
// 'request.auth != null' lets ANY signed-up user (including anonymous-auth) read/write.
// Add ownership scoping:
match ${b.path} {
  allow ${a.ops.join(", ")}: if request.auth != null && request.auth.uid == resource.data.ownerId;
}`,
          });
        }
      }

      // Check 4: test mode timestamp-based rule
      const tsMatch = a.condition.match(/request\.time\s*<\s*timestamp\.date\((\d{4}),\s*(\d{1,2}),\s*(\d{1,2})\)/);
      if (tsMatch) {
        const expiry = new Date(parseInt(tsMatch[1]), parseInt(tsMatch[2]) - 1, parseInt(tsMatch[3]));
        const stillOpen = expiry > today;
        findings.push({
          check: "test_mode_30_days",
          ...CHECKS.test_mode_30_days,
          target: `${b.path} (${a.ops.join(",")})`,
          details: { path: b.path, ops: a.ops, condition: a.condition, line: a.line, expiry_date: expiry.toISOString().slice(0,10), currently_open: stillOpen },
          fix_snippet: `// firestore.rules line ${a.line}:
// Test-mode timestamp rule. ${stillOpen ? `EXPIRES ${expiry.toISOString().slice(0,10)} — currently OPEN.` : `Expired ${expiry.toISOString().slice(0,10)} — denying everything (your app may be broken).`}
// Replace with proper auth rules:
match ${b.path} {
  allow ${a.ops.join(", ")}: if request.auth != null;  // tighten further per-collection
}`,
        });
      }
    }
  }

  // Check 5: catch-all with read open + write closed
  for (const b of blocks) {
    const isCatchAll = /\/\{[^}]*=\*\*\}$/.test(b.path);
    if (!isCatchAll) continue;
    const readAllow = b.allows.find(a => a.ops.includes("read") && !a.ops.includes("write"));
    const writeAllow = b.allows.find(a => a.ops.includes("write") && !a.ops.includes("read"));
    if (readAllow && readAllow.condition.replace(/\s+/g,"") === "true" && writeAllow) {
      findings.push({
        check: "read_open_write_protected",
        ...CHECKS.read_open_write_protected,
        target: `${b.path} (read public, write protected)`,
        details: { path: b.path, read_condition: readAllow.condition, write_condition: writeAllow.condition },
        fix_snippet: `// firestore.rules:
// Catch-all read 'if true' = anyone can dump every document. Move public-read to specific collections only.
match /publicConfig/{doc} { allow read: if true; allow write: if false; }
match /{document=**} { allow read, write: if false; }`,
      });
    }
  }

  // Check 6: storage rules open read (only fires if storage block detected)
  const hasStorage = /service\s+firebase\.storage/.test(rules);
  if (hasStorage) {
    for (const b of blocks) {
      for (const a of b.allows) {
        if (a.ops.includes("read") && a.condition.replace(/\s+/g,"") === "true") {
          findings.push({
            check: "storage_rule_open_read",
            ...CHECKS.storage_rule_open_read,
            target: `${b.path} (storage read)`,
            details: { path: b.path, ops: a.ops, condition: a.condition, line: a.line },
            fix_snippet: `// storage.rules line ${a.line}:
// Open read on user uploads exposes private files. Restrict per owner:
match /users/{userId}/{file} {
  allow read: if request.auth != null && request.auth.uid == userId;
}`,
          });
        }
      }
    }
  }

  // Check 7: default-deny missing
  const hasExplicitDefaultDeny = blocks.some(b => {
    const isCatchAll = b.path === "/{document=**}" || /\/\{[^}]*=\*\*\}$/.test(b.path);
    if (!isCatchAll) return false;
    return b.allows.some(a => a.condition.replace(/\s+/g,"") === "false");
  });
  if (!hasExplicitDefaultDeny) {
    findings.push({
      check: "default_deny_missing",
      ...CHECKS.default_deny_missing,
      target: "(end of file)",
      details: { recommendation: "add `match /{document=**} { allow read, write: if false; }` at end" },
      fix_snippet: `// firestore.rules — add at end of service block:
match /{document=**} {
  allow read, write: if false;
}`,
    });
  }

  return findings;
}

async function probeProject(projectId) {
  // Public REST endpoint. Anonymous read attempt against the default database.
  // GET https://firestore.googleapis.com/v1/projects/{pid}/databases/(default)/documents
  const url = `https://firestore.googleapis.com/v1/projects/${encodeURIComponent(projectId)}/databases/(default)/documents`;
  try {
    const r = await fetch(url, { headers: { "User-Agent": UA } });
    const status = r.status;
    const body = await r.text();
    if (!r.ok) {
      return { confirmed: false, status, reason: `http ${status} (${body.slice(0, 80)})` };
    }
    let docs = [];
    try {
      const parsed = JSON.parse(body);
      docs = parsed.documents || [];
    } catch { /* */ }
    return {
      confirmed: docs.length > 0,
      status,
      sample: { document_count: docs.length, bytes_returned: body.length, first_paths: docs.slice(0, 3).map(d => d.name?.split("/").slice(-2).join("/")) },
    };
  } catch (e) {
    return { confirmed: false, status: 0, reason: `network: ${e.message}` };
  }
}

export async function audit(opts) {
  const { rulesPath, projectId, activeProbe = true } = opts;

  let rules = "";
  if (rulesPath) {
    if (!existsSync(rulesPath)) throw new Error(`rules file not found: ${rulesPath}`);
    rules = readFileSync(rulesPath, "utf8");
  }

  const blocks = rules ? parseRules(rules) : [];
  const findings = rules ? detectFindings(rules, blocks) : [];

  let probed = 0;
  let confirmed = 0;
  if (activeProbe && projectId) {
    const probe = await probeProject(projectId);
    probed = 1;
    if (probe.confirmed) {
      confirmed = 1;
      findings.unshift({
        check: "anon_read_default_db",
        severity: "critical",
        title: `Anonymous read of project ${projectId} default database returned ${probe.sample.document_count} documents`,
        explain: "The Firestore REST endpoint accepts anonymous GET against /v1/projects/{pid}/databases/(default)/documents. Documents came back, confirming live data leak.",
        target: `firestore://${projectId}/(default)`,
        details: { project_id: projectId, sample: probe.sample },
        probe,
        fix_snippet: `// Tighten firestore.rules — at minimum add explicit default-deny:
match /{document=**} {
  allow read, write: if false;
}
// Then re-deploy: firebase deploy --only firestore:rules`,
      });
    }
  }

  findings.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);

  const summary = findings.reduce(
    (acc, f) => ({ ...acc, [f.severity]: (acc[f.severity] || 0) + 1 }),
    { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  );

  return {
    rules_path: rulesPath,
    project_id: projectId,
    scanned_at: new Date().toISOString(),
    scanned_by: "firebase-security v0.1",
    active_probe: { enabled: activeProbe && !!projectId, probed, confirmed },
    summary,
    n_match_blocks: blocks.length,
    n_allow_statements: blocks.reduce((s, b) => s + b.allows.length, 0),
    findings,
  };
}

async function main() {
  const args = process.argv.slice(2);
  if (args.includes("--help") || args.includes("-h")) {
    console.error(`Usage:
  firebase-security firestore.rules [--project-id PID] [--no-probe] [--html report.html]
  firebase-security --rules PATH [--project-id PID] [--no-probe] [--html report.html]

  Keyless discover (parses local repo + probes Firestore REST anon):
    firebase-security --discover [path] [--project-id PID]

If --project-id is provided, the active probe sends an anonymous GET against
https://firestore.googleapis.com/v1/projects/<pid>/databases/(default)/documents
and reports CONFIRMED if documents are returned.

Detects: open match-all wildcards, 'if true' literals, auth-only-no-ownership patterns,
test-mode timestamp expiry, public-read storage uploads, missing explicit default-deny.
--discover: no rules file needed; parses collection(db, '...') call sites + probes.`);
    process.exit(1);
  }

  // --discover mode (v0.2): no rules file needed.
  if (args.includes("--discover")) {
    const { discover } = await import("./discover.js");
    const idx = args.indexOf("--discover");
    const path = args[idx + 1] && !args[idx + 1].startsWith("--") ? args[idx + 1] : process.cwd();
    const pidOverride = args.includes("--project-id") ? args[args.indexOf("--project-id") + 1] : null;
    const result = await discover({ root: path, projectId: pidOverride });

    const htmlIdx = args.indexOf("--html");
    if (htmlIdx !== -1) {
      const out = args[htmlIdx + 1] || "discover-report.html";
      const { renderHtml } = await import("./report.js");
      writeFileSync(out, renderHtml(result));
      console.error(`Discover report written to ${out}`);
    }
    console.log(JSON.stringify(result, null, 2));
    return;
  }

  const flag = (k) => args.includes(k) ? args[args.indexOf(k) + 1] : null;
  let rulesPath = flag("--rules") || args.find(a => a.endsWith(".rules") || a.endsWith("firestore.rules"));
  const projectId = flag("--project-id") || process.env.FIREBASE_PROJECT_ID;
  const activeProbe = !args.includes("--no-probe");

  if (!rulesPath && !projectId) {
    console.error("Error: provide a rules file path or --project-id (or FIREBASE_PROJECT_ID env var)");
    console.error("\nTip: try --discover for a keyless scan of your local repo:");
    console.error("  firebase-security --discover .");
    process.exit(1);
  }

  const result = await audit({ rulesPath, projectId, activeProbe });

  const htmlIdx = args.indexOf("--html");
  if (htmlIdx !== -1) {
    const out = args[htmlIdx + 1] || "report.html";
    const { renderHtml } = await import("./report.js");
    writeFileSync(out, renderHtml(result));
    console.error(`HTML report written to ${out}`);
    console.error(`Findings: ${result.summary.critical} critical, ${result.summary.high} high, ${result.summary.medium} medium${result.active_probe.enabled ? ` (${result.active_probe.confirmed} CONFIRMED via active probe)` : ""}`);
  } else {
    console.log(JSON.stringify(result, null, 2));
  }
}

const isMain = process.argv[1] && (
  import.meta.url === `file://${process.argv[1].replace(/\\/g, "/")}` ||
  import.meta.url.endsWith(process.argv[1].replace(/\\/g, "/"))
);
if (isMain) {
  main().catch((e) => {
    console.error(e.message);
    process.exit(1);
  });
}
