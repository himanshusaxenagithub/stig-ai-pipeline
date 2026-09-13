/* Public site: pick an OS, read the filed explanations, select rules,
   download a local scanner. This page never runs a host check. */

const $ = s => document.querySelector(s);
const $$ = s => [...document.querySelectorAll(s)];
const esc = s => String(s ?? "").replace(/[&<>"]/g, c => ({
  "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"
}[c]));

const OS = {
  macos: {key: "macos-26", label: "MacBook", zip: "STIG-Scanner-macOS.zip",
          folder: "STIG-Scanner-macOS/", launch: "STIG Checker.command"},
  windows: {key: "windows-11", label: "Windows PC", zip: "STIG-Scanner-Windows.zip",
            folder: "STIG-Scanner-Windows/", launch: "STIG Checker.bat"},
};

let catalog = null;
let guide = null;
let pack = null;
let platform = null;
let selected = new Set();

async function loadJSON(url) {
  const r = await fetch(url);
  if (!r.ok) throw new Error("could not load " + url + " (" + r.status + ")");
  return r.json();
}

function show(step) {
  for (const id of ["landing", "rules", "download"]) {
    $("#s-" + id).hidden = (id !== step);
    const tab = $("#tab-" + id);
    if (tab) tab.setAttribute("aria-selected", String(id === step));
  }
}

function setStatus(id, text, isErr) {
  const el = $(id);
  if (!el) return;
  el.textContent = text || "";
  el.classList.toggle("err-inline", !!isErr);
}

(async () => {
  try {
    catalog = await loadJSON("data/catalog.json");
    $("#fetch-note").textContent = catalog.note;
  } catch (e) {
    $("#fetch-note").innerHTML = `<span class="err" style="display:block">${esc(e.message)}</span>`;
  }
})();

$$(".pick").forEach(btn => {
  btn.onclick = () => chooseOS(btn.dataset.os);
});

async function chooseOS(os) {
  platform = os;
  const meta = OS[os];
  $$(".pick").forEach(b => b.setAttribute("data-mine", String(b.dataset.os === os)));
  $("#rules-status").textContent = "loading the filed " + meta.label + " guide…";
  show("rules");
  try {
    guide = await loadJSON("data/guides/" + meta.key + ".json");
    const cat = (catalog && catalog.guides || []).find(g => g.key === meta.key);
    const checks = guide.checkpack
      ? await loadJSON("data/checkpacks/" + guide.checkpack + ".json")
      : null;
    pack = checks;
    selected = new Set(guide.items.filter(r => r.mode === "shell").map(r => r.stig_id));
    renderGuideMeta(cat);
    renderRules();
    $("#tab-rules").disabled = false;
    $("#tab-download").disabled = false;
    $("#rules-status").textContent = "";
  } catch (e) {
    $("#rules-status").innerHTML = `<span class="err" style="display:block">${esc(e.message)}</span>`;
  }
}

function renderGuideMeta(cat) {
  const g = guide;
  const tri = {};
  for (const r of g.items) {
    const k = r.triage || "unexplained";
    tri[k] = (tri[k] || 0) + 1;
  }
  const chips = Object.entries(tri).sort((a,b) => b[1]-a[1])
    .map(([k,v]) => `<span class="chip t-${esc(k)}">${esc(k.replace(/-/g," "))} ${v}</span>`)
    .join(" ");
  const sha = (cat && cat.sha256)
    ? `Pinned SHA-256: <code>${esc(cat.sha256)}</code>`
    : `No pinned SHA-256 is recorded for this release; the local scanner still checks the rule count (${g.expected_rules || g.rules}).`;
  $("#guide-out").innerHTML = `
    <div class="stats">
      <div class="stat"><b>${g.rules}</b><span>rules in the validated guide</span></div>
      <div class="stat"><b>${g.items.filter(r => r.severity==="high").length}</b><span>CAT I — most serious</span></div>
      <div class="stat"><b>${g.annotated}</b><span>explained in plain English</span></div>
      <div class="stat"><b>${g.items.filter(r => r.mode==="shell").length}</b><span>have a machine check</span></div>
    </div>
    <p><b>${esc(g.title)}</b><br>
      <span class="muted">${esc(g.version || "")} · validated release ${esc(String(g.release))} ·
      ${esc(g.filename)}</span></p>
    <p>${chips}</p>
    <div class="note">
      This page loaded the filed explanations this project ships — the same
      set <code>stigprep parse --explain</code> attaches. It did not download
      the official zip from <code>dl.dod.cyber.mil</code> (browsers are
      blocked from that host). The local scanner still fetches
      <a href="${esc(g.official_url)}">${esc(g.filename)}</a> when you ask it
      to, verifies the rule count${cat && cat.sha256 ? " and the pinned digest" : ""},
      and refuses a file that does not match.
      If that host is blocked on your network, use
      <a href="${esc(g.download_page)}">${esc(g.download_page)}</a>.
      ${sha}
    </div>`;
}

["rules-find","rules-cat","rules-triage","rules-mode"].forEach(id => {
  const el = $("#" + id);
  if (el) el.oninput = renderRules;
});
$("#sel-all").onclick = () => {
  visibleRules().forEach(r => selected.add(r.stig_id));
  renderRules();
};
$("#sel-none").onclick = () => {
  visibleRules().forEach(r => selected.delete(r.stig_id));
  renderRules();
};
$("#sel-shell").onclick = () => {
  visibleRules().forEach(r => {
    if (r.mode === "shell") selected.add(r.stig_id);
    else selected.delete(r.stig_id);
  });
  renderRules();
};
$("#sel-cati").onclick = () => {
  visibleRules().forEach(r => {
    if (r.severity === "high") selected.add(r.stig_id);
    else selected.delete(r.stig_id);
  });
  renderRules();
};

function visibleRules() {
  if (!guide) return [];
  const q = $("#rules-find").value.toLowerCase();
  const cat = $("#rules-cat").value;
  const tri = $("#rules-triage").value;
  const mode = $("#rules-mode").value;
  return guide.items.filter(r =>
    (!cat || r.severity === cat) &&
    (!tri || r.triage === tri) &&
    (!mode || r.mode === mode) &&
    (!q || (r.stig_id + " " + r.title + " " + r.summary).toLowerCase().includes(q)));
}

function renderRules() {
  if (!guide) return;
  const rows = visibleRules();
  $("#rules-count").textContent = rows.length + " of " + guide.items.length + " shown · "
    + selected.size + " selected for the scan";
  $("#rules-title").textContent = guide.title;
  $("#rules-sub").textContent =
    `${guide.annotated} of ${guide.rules} rules carry a plain-English explanation. `
    + `Tick the ones to put in the ${OS[platform].label} scanner.`;
  $("#rules-table tbody").innerHTML = rows.slice(0, 500).map(r => `
    <tr>
      <td><input type="checkbox" class="pickme" value="${esc(r.stig_id)}"
           ${selected.has(r.stig_id) ? "checked" : ""}></td>
      <td><code>${esc(r.stig_id)}</code></td>
      <td><span class="chip c-${esc(r.severity)}">${esc(r.cat)}</span></td>
      <td><b>${esc(r.title)}</b>${r.summary ? "<br>" + esc(r.summary) : ""}
          ${r.caution ? `<div class="muted">${esc(r.caution)}</div>` : ""}</td>
      <td>${r.triage ? `<span class="chip t-${esc(r.triage)}">${esc(r.triage.replace(/-/g," "))}</span>` : ""}
          ${r.automation ? `<br><span class="muted">${esc(r.automation)}</span>` : ""}
          <br><span class="muted">${r.mode === "shell" ? "machine check" : "needs a person"}</span></td>
    </tr>`).join("");
  $$(".pickme").forEach(box => {
    box.onchange = () => {
      if (box.checked) selected.add(box.value);
      else selected.delete(box.value);
      $("#rules-count").textContent = rows.length + " of " + guide.items.length + " shown · "
        + selected.size + " selected for the scan";
    };
  });
}

$("#go-download").onclick = () => {
  if (!selected.size) {
    alert("Select at least one rule to put in the scanner.");
    return;
  }
  const meta = OS[platform];
  $("#dl-summary").innerHTML = `
    <p>You are about to download <b>${esc(meta.zip)}</b> for a ${esc(meta.label)},
    preconfigured with <b>${selected.size}</b> of ${guide.rules} rules from
    <b>${esc(guide.title)}</b>.</p>
    <div class="note">
      This zip is a local program — the same Python files as this repository,
      plus your selection. It does <b>not</b> run any check until you open it
      on your own ${esc(meta.label)}, read each command, and approve it under
      your own name. Every shipped check is unreviewed. After the scan, a PDF
      report is written next to the JSON and Markdown reports.
    </div>`;
  show("download");
};

$("#go-build").onclick = async () => {
  const btn = $("#go-build");
  btn.disabled = true;
  setStatus("#dl-status", "building the " + OS[platform].label + " scanner…");
  try {
    await downloadScanner();
    setStatus("#dl-status", "saved " + OS[platform].zip + " — unzip it and double-click "
      + OS[platform].launch + ".");
  } catch (e) {
    setStatus("#dl-status", e.message, true);
  }
  btn.disabled = false;
};

function encoder() { return new TextEncoder(); }

function filterPack(raw, ids, packId) {
  const want = new Set(ids);
  const checks = (raw.checks || []).filter(c => want.has(c.stig_id));
  if (checks.length !== ids.length) {
    const have = new Set(checks.map(c => c.stig_id));
    const missing = ids.filter(id => !have.has(id));
    throw new Error("not in this pack: " + missing.slice(0, 6).join(", "));
  }
  const note = ((raw.notes || "") + "\nSelected subset for a local scan. "
    + "Every check remains unreviewed until a named person approves it.").trim();
  return {
    ...raw,
    pack_id: packId,
    notes: note,
    checks,
  };
}

async function downloadScanner() {
  const meta = OS[platform];
  const srcResp = await fetch("packages/scanner-src.zip");
  if (!srcResp.ok) {
    throw new Error(
      "could not load the scanner payload (" + srcResp.status + "). "
      + "If you opened this file directly, serve the docs/ folder over HTTP, "
      + "or enable GitHub Pages so packages/scanner-src.zip is available.");
  }
  const files = unzipStore(await srcResp.arrayBuffer());
  const ids = (pack.checks || []).filter(c => selected.has(c.stig_id)).map(c => c.stig_id);
  if (!ids.length) throw new Error("select at least one rule that is in the shipped pack");
  const packId = (guide.checkpack || "pack") + "-selected";
  const filtered = filterPack(pack, ids, packId);
  const selection = {
    selection_format: 1,
    created: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
    platform,
    os_label: meta.label,
    guide_key: guide.key,
    source_pack: guide.checkpack,
    pack_id: packId,
    pack_path: "checkpacks/" + packId + ".json",
    rule_ids: ids,
    unreviewed: true,
    note: "Every check in this pack is unreviewed. A named person must read "
      + "and approve each command on the machine being scanned before it runs.",
  };
  const enc = encoder();
  files["selection.json"] = enc.encode(JSON.stringify(selection, null, 2) + "\n");
  files["checkpacks/" + packId + ".json"] = enc.encode(JSON.stringify(filtered, null, 2) + "\n");
  files["Read me.txt"] = enc.encode(
    "STIG Checker — configured scan pack\n"
    + "===================================\n\n"
    + "This folder is for a " + meta.label + ", with " + ids.length
    + " selected rule(s) from " + (guide.checkpack || guide.key) + ".\n\n"
    + "Unzip it. Keep the files together.\n"
    + "Windows: double-click STIG Checker.bat.\n"
    + "Mac: right-click STIG Checker.command, choose Open, then Open.\n\n"
    + "The page opens on this computer. Your selection is already loaded.\n"
    + "Read each command, type your name, approve, then scan.\n"
    + "A PDF report is saved with the other reports (Show files).\n\n"
    + "Nothing leaves this machine. Checks stay unreviewed until you approve them.\n"
    + "MIT licence. https://github.com/himanshusaxenagithub/stig-ai-pipeline\n"
  );
  const blob = zipStore(files, meta.folder);
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = meta.zip;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 4000);
}

$("#tab-landing").onclick = () => show("landing");
$("#tab-rules").onclick = () => { if (guide) show("rules"); };
$("#tab-download").onclick = () => { if (selected.size) $("#go-download").click(); };
