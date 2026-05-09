// HTML report generator for firebase-security — Tailwind CDN + Chart.js, self-contained.

const SEVERITY_STYLE = {
  critical: { bg: "bg-red-100", border: "border-red-500", text: "text-red-900", badge: "bg-red-600" },
  high:     { bg: "bg-orange-100", border: "border-orange-500", text: "text-orange-900", badge: "bg-orange-500" },
  medium:   { bg: "bg-yellow-100", border: "border-yellow-500", text: "text-yellow-900", badge: "bg-yellow-500" },
  low:      { bg: "bg-blue-100", border: "border-blue-500", text: "text-blue-900", badge: "bg-blue-500" },
  info:     { bg: "bg-gray-100", border: "border-gray-400", text: "text-gray-900", badge: "bg-gray-500" },
};

const SEVERITY_ICON = { critical: "[CRITICAL]", high: "[HIGH]", medium: "[MEDIUM]", low: "[LOW]", info: "[INFO]" };

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function probeBlock(probe) {
  if (!probe) return "";
  if (probe.confirmed) {
    const s = probe.sample || {};
    return `
    <div class="bg-red-900 text-white p-3 rounded mb-2 text-sm">
      <div class="font-bold mb-1">★ CONFIRMED LEAK — anonymous Firestore REST returned data</div>
      <div class="text-xs">HTTP ${probe.status} &middot; ${s.document_count ?? 0} document(s) &middot; ${s.bytes_returned ?? 0} bytes</div>
      ${s.first_paths?.length ? `<div class="text-xs mt-1 opacity-90">Paths visible: <code>${escapeHtml(s.first_paths.join(", "))}</code></div>` : ""}
    </div>`;
  }
  return `
    <div class="bg-gray-200 text-gray-700 p-2 rounded mb-2 text-xs">
      ▸ Active probe: HTTP ${probe.status} (${escapeHtml(probe.reason || "blocked")}) — finding inferred from rules text only
    </div>`;
}

function findingCard(f, idx) {
  const style = SEVERITY_STYLE[f.severity] || SEVERITY_STYLE.info;
  const icon = SEVERITY_ICON[f.severity] || "[INFO]";
  return `
  <div class="${style.bg} ${style.text} border-l-4 ${style.border} p-5 rounded shadow-sm mb-3">
    <div class="flex items-center justify-between mb-2">
      <h3 class="font-bold text-lg">${escapeHtml(icon)} ${escapeHtml(f.title)}</h3>
      <span class="${style.badge} text-white text-xs font-bold px-2 py-1 rounded uppercase">${escapeHtml(f.severity)}</span>
    </div>
    <p class="text-sm mb-2"><strong>Target:</strong> <code class="bg-white px-2 py-1 rounded text-xs">${escapeHtml(f.target)}</code></p>
    ${probeBlock(f.probe)}
    <p class="text-sm mb-3">${escapeHtml(f.explain)}</p>
    ${f.details ? `<details class="text-xs mb-2"><summary class="cursor-pointer font-semibold">Details</summary><pre class="bg-white p-2 rounded mt-1 overflow-x-auto">${escapeHtml(JSON.stringify(f.details, null, 2))}</pre></details>` : ""}
    <details class="text-xs">
      <summary class="cursor-pointer font-semibold text-green-800">Fix snippet (paste into firestore.rules)</summary>
      <pre class="bg-gray-900 text-green-300 p-3 rounded mt-1 overflow-x-auto"><code id="fix-${idx}">${escapeHtml(f.fix_snippet || "")}</code></pre>
      <button onclick="navigator.clipboard.writeText(document.getElementById('fix-${idx}').textContent)" class="mt-2 bg-green-700 hover:bg-green-800 text-white text-xs px-3 py-1 rounded">Copy snippet</button>
    </details>
  </div>`;
}

export function renderHtml(result) {
  const { rules_path, project_id, scanned_at, summary, findings, n_match_blocks, n_allow_statements, active_probe } = result;
  const total = findings.length;
  const probeBanner = active_probe?.enabled
    ? (active_probe.confirmed > 0
        ? `<div class="bg-red-700 text-white p-3 rounded mb-4 text-center font-semibold">★ Active anon probe ran on project ${escapeHtml(project_id || "")}. ${active_probe.confirmed} of ${active_probe.probed} suspected leaks confirmed live.</div>`
        : `<div class="bg-emerald-100 text-emerald-900 border border-emerald-300 p-3 rounded mb-4 text-center text-sm">▸ Active probe ran on ${active_probe.probed} target(s). ${active_probe.confirmed} confirmed.</div>`)
    : `<div class="bg-gray-100 text-gray-700 border border-gray-300 p-3 rounded mb-4 text-center text-sm">▸ Active probe disabled. Findings inferred from rules file only. Add --project-id to probe live.</div>`;
  const score = Math.max(0, 100 - (summary.critical * 20 + summary.high * 10 + summary.medium * 4 + summary.low * 1));
  const grade = score >= 95 ? "A+" : score >= 85 ? "A" : score >= 70 ? "B" : score >= 50 ? "C" : score >= 30 ? "D" : "F";
  const gradeColor = score >= 85 ? "text-green-600" : score >= 50 ? "text-yellow-600" : "text-red-600";
  const allFixes = findings.map((f) => `// ${f.title} (${f.target})\n${f.fix_snippet || ""}`).join("\n\n");

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Firebase Security Report${rules_path ? ` — ${escapeHtml(rules_path)}` : ""}</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <script src="https://cdn.tailwindcss.com"></script>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
</head>
<body class="bg-gray-50 text-gray-900 font-sans">
  <div class="max-w-5xl mx-auto p-6">

    <div class="bg-gradient-to-r from-yellow-600 to-orange-500 text-white p-8 rounded-lg shadow-lg mb-6">
      <h1 class="text-3xl font-bold mb-2">Firebase Security Report</h1>
      <p class="text-yellow-100"><strong>Rules file:</strong> ${escapeHtml(rules_path || "(none — probe-only mode)")}</p>
      ${project_id ? `<p class="text-yellow-100"><strong>Project ID:</strong> ${escapeHtml(project_id)}</p>` : ""}
      <p class="text-yellow-100"><strong>Scanned:</strong> ${escapeHtml(new Date(scanned_at).toLocaleString())}</p>
    </div>

    <div class="grid grid-cols-2 md:grid-cols-5 gap-4 mb-6">
      <div class="bg-white p-5 rounded-lg shadow text-center col-span-2 md:col-span-1">
        <div class="text-6xl font-bold ${gradeColor}">${grade}</div>
        <div class="text-sm text-gray-500 mt-1">Score: ${score}/100</div>
      </div>
      <div class="bg-red-600 text-white p-5 rounded-lg shadow text-center"><div class="text-3xl font-bold">${summary.critical}</div><div class="text-xs uppercase">Critical</div></div>
      <div class="bg-orange-500 text-white p-5 rounded-lg shadow text-center"><div class="text-3xl font-bold">${summary.high}</div><div class="text-xs uppercase">High</div></div>
      <div class="bg-yellow-500 text-white p-5 rounded-lg shadow text-center"><div class="text-3xl font-bold">${summary.medium}</div><div class="text-xs uppercase">Medium</div></div>
      <div class="bg-blue-500 text-white p-5 rounded-lg shadow text-center"><div class="text-3xl font-bold">${summary.low + summary.info}</div><div class="text-xs uppercase">Low/Info</div></div>
    </div>

    ${probeBanner}

    <div class="bg-white p-5 rounded-lg shadow mb-6">
      <h2 class="text-lg font-bold mb-3">Coverage</h2>
      <div class="grid grid-cols-3 gap-4 text-center">
        <div><div class="text-2xl font-bold text-gray-700">${n_match_blocks}</div><div class="text-xs text-gray-500">match blocks</div></div>
        <div><div class="text-2xl font-bold text-gray-700">${n_allow_statements}</div><div class="text-xs text-gray-500">allow statements</div></div>
        <div><div class="text-2xl font-bold text-gray-700">7</div><div class="text-xs text-gray-500">checks run</div></div>
      </div>
    </div>

    ${total > 0 ? `
    <div class="bg-white p-5 rounded-lg shadow mb-6">
      <h2 class="text-lg font-bold mb-3">Findings by severity</h2>
      <canvas id="severityChart" height="80"></canvas>
    </div>
    ` : `
    <div class="bg-green-50 border-l-4 border-green-500 text-green-900 p-6 rounded-lg shadow mb-6 text-center">
      <h2 class="text-2xl font-bold">No security issues found.</h2>
      <p class="mt-2">Your firestore.rules file passes all checks.</p>
    </div>
    `}

    ${total > 0 ? `
    <div class="mb-6">
      <h2 class="text-2xl font-bold mb-4">Findings (${total})</h2>
      ${findings.map((f, i) => findingCard(f, i)).join("")}
    </div>

    <div class="bg-white p-5 rounded-lg shadow mb-6">
      <h2 class="text-lg font-bold mb-3">Apply all fixes (paste into firestore.rules)</h2>
      <p class="text-sm text-gray-600 mb-3">Review each block before deploying. Then: <code>firebase deploy --only firestore:rules</code></p>
      <pre class="bg-gray-900 text-green-300 p-4 rounded overflow-x-auto text-xs"><code id="all-fixes">${escapeHtml(allFixes)}</code></pre>
      <button onclick="navigator.clipboard.writeText(document.getElementById('all-fixes').textContent)" class="mt-3 bg-orange-600 hover:bg-orange-700 text-white text-sm px-4 py-2 rounded">Copy all snippets</button>
    </div>
    ` : ""}

    <div class="text-center text-xs text-gray-500 mt-8 pb-4">
      Generated by <a href="https://github.com/Perufitlife/firebase-security-skill" class="text-orange-700 underline">firebase-security</a>
      &middot; Open source (MIT) &middot; Static analysis runs locally; project-id probe sends only an unauthenticated GET.
    </div>
  </div>

  ${total > 0 ? `
  <script>
    new Chart(document.getElementById("severityChart"), {
      type: "bar",
      data: {
        labels: ["Critical", "High", "Medium", "Low", "Info"],
        datasets: [{
          data: [${summary.critical}, ${summary.high}, ${summary.medium}, ${summary.low}, ${summary.info}],
          backgroundColor: ["#dc2626", "#f97316", "#eab308", "#3b82f6", "#6b7280"]
        }]
      },
      options: {
        indexAxis: "y",
        plugins: { legend: { display: false } },
        scales: { x: { beginAtZero: true, ticks: { stepSize: 1 } } }
      }
    });
  </script>` : ""}
</body>
</html>`;
}
