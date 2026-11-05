const $ = id => document.getElementById(id);
const demoMode = new URLSearchParams(window.location.search).get("demo") === "1" ||
  document.documentElement.dataset.demo === "true";
let masterPassword = "";
let vaultUsername = "";
let entries = [];
let toastTimer;

async function api(path, data = {}) {
  const response = await fetch(path, {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify(data)
  });
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || "Something went wrong.");
  return result;
}
function toast(message) {
  const el = $("toast"); el.textContent = message; el.classList.add("show");
  clearTimeout(toastTimer); toastTimer = setTimeout(() => el.classList.remove("show"), 2400);
}
function showAuth(initialized) {
  $("authView").classList.remove("hidden"); $("appView").classList.add("hidden");
  $("generatorView").classList.add("hidden");
  $("authEyebrow").textContent = initialized ? "WELCOME BACK" : "GET STARTED";
  $("authTitle").innerHTML = initialized ? "Unlock your vault<span>.</span>" : "Create your vault<span>.</span>";
  $("authCopy").textContent = initialized ? "Enter your login name and master password to access your credentials." : "Create a login name and master password for your vault.";
  $("authSubmit").innerHTML = initialized ? 'Unlock vault <span>→</span>' : 'Create secure vault <span>→</span>';
  $("masterHint").textContent = initialized
    ? "Use the login name and master password set for this vault. The default is admin / 0000 only until changed."
    : "Use at least 10 characters for your new master password.";
  $("loginName").value = initialized ? "admin" : "";
  $("master").value = "";
  $("authForm").dataset.mode = initialized ? "login" : "setup";
}
async function refreshEntries() {
  const result = await api("/api/list", {login: vaultUsername, master: masterPassword});
  entries = result.entries || [];
  renderEntries();
}
function renderEntries() {
  $("totalCount").textContent = entries.length;
  const term = $("search").value.toLowerCase();
  const filtered = entries.filter(e => e.site.toLowerCase().includes(term) || e.username.toLowerCase().includes(term));
  if (!filtered.length) {
    $("entries").innerHTML = `<div class="empty-state"><div class="empty-icon">▤</div><strong>${entries.length ? "No matching accounts" : "Your vault is empty"}</strong><p>${entries.length ? "Try a different search." : "Add your first login to get started."}</p>${entries.length ? "" : '<button class="text-btn" id="emptyAdd">＋ Add your first password</button>'}</div>`;
    $("emptyAdd")?.addEventListener("click", openModal);
    return;
  }
  $("entries").innerHTML = filtered.map(e => `
    <div class="entry-row">
      <div class="site-cell"><span class="site-icon">${escapeHtml(e.site.charAt(0).toUpperCase())}</span>${escapeHtml(e.site)}</div>
      <div class="muted-cell">${escapeHtml(e.username)}</div>
      <div class="muted-cell"><span class="dots" data-id="${e.id}">••••••••••</span></div>
      <div class="row-actions"><button class="icon-btn reveal-entry" data-id="${e.id}" title="Show password">◉</button><button class="icon-btn copy-entry" data-id="${e.id}" title="Copy password">▢</button><button class="icon-btn delete-entry" data-id="${e.id}" title="Delete">×</button></div>
    </div>`).join("");
  document.querySelectorAll(".reveal-entry").forEach(btn => btn.addEventListener("click", () => {
    const e = entries.find(x => x.id == btn.dataset.id), el = document.querySelector(`.dots[data-id="${btn.dataset.id}"]`);
    const shown = el.textContent !== "••••••••••"; el.textContent = shown ? "••••••••••" : e.password;
    btn.textContent = shown ? "◉" : "⊘";
  }));
  document.querySelectorAll(".copy-entry").forEach(btn => btn.addEventListener("click", async () => {
    const e = entries.find(x => x.id == btn.dataset.id);
    try { await navigator.clipboard.writeText(e.password); toast("Password copied to clipboard."); }
    catch { toast("Clipboard access was blocked by the browser."); }
  }));
  document.querySelectorAll(".delete-entry").forEach(btn => btn.addEventListener("click", async () => {
    if (!confirm(demoMode ? "Remove this sample entry?" : "Delete this saved credential permanently?")) return;
    if (demoMode) {
      entries = entries.filter(x => String(x.id) !== btn.dataset.id);
      renderEntries();
      toast("Sample entry removed.");
      return;
    }
    try { await api("/api/delete", {login: vaultUsername, master: masterPassword, id: String(btn.dataset.id)}); await refreshEntries(); toast("Credential deleted."); }
    catch (err) { toast(err.message); }
  }));
}
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
}
function openApp() {
  $("authView").classList.add("hidden"); $("generatorView").classList.add("hidden"); $("appView").classList.remove("hidden");
}
function openModal() { $("addModal").classList.remove("hidden"); $("site").focus(); }
function closeModal() { $("addModal").classList.add("hidden"); $("addForm").reset(); $("addError").textContent = ""; }
function closeChangeMasterModal() {
  $("changeMasterModal").classList.add("hidden");
  $("changeMasterForm").reset();
  $("changeMasterError").textContent = "";
}

$("authForm").addEventListener("submit", async e => {
  e.preventDefault(); $("authError").textContent = "";
  const username = $("loginName").value.trim();
  const master = $("master").value;
  try {
    if ($("authForm").dataset.mode === "setup") await api("/api/setup", {login: username, master});
    else await api("/api/login", {login: username, master});
    vaultUsername = username;
    masterPassword = master;
    await refreshEntries(); openApp(); toast("Vault unlocked securely.");
  } catch (err) { $("authError").textContent = err.message; }
});
$("addOpen").addEventListener("click", openModal);
$("changeMasterOpen").addEventListener("click", () => {
  $("changeMasterModal").classList.remove("hidden");
  $("currentMaster").focus();
});
$("changeMasterClose").addEventListener("click", closeChangeMasterModal);
$("changeMasterCancel").addEventListener("click", closeChangeMasterModal);
$("changeMasterModal").addEventListener("click", e => {
  if (e.target === $("changeMasterModal")) closeChangeMasterModal();
});
$("changeMasterForm").addEventListener("submit", async e => {
  e.preventDefault();
  $("changeMasterError").textContent = "";
  const currentMaster = $("currentMaster").value;
  const newMaster = $("newMaster").value;
  if (newMaster !== $("confirmMaster").value) {
    $("changeMasterError").textContent = "The new passwords do not match.";
    return;
  }
  try {
    await api("/api/change-master", {login: vaultUsername, master: currentMaster, newMaster});
    masterPassword = newMaster;
    closeChangeMasterModal();
    toast("Master password changed. Vault credentials were re-encrypted.");
  } catch (err) {
    $("changeMasterError").textContent = err.message;
  }
});
$("emptyAdd")?.addEventListener("click", openModal);
$("modalClose").addEventListener("click", closeModal);
$("cancelAdd").addEventListener("click", closeModal);
$("addModal").addEventListener("click", e => { if (e.target === $("addModal")) closeModal(); });
$("addForm").addEventListener("submit", async e => {
  e.preventDefault(); $("addError").textContent = "";
  if (demoMode) {
    entries.unshift({
      id: Date.now(),
      site: $("site").value.trim(),
      username: $("username").value.trim(),
      password: $("password").value
    });
    closeModal();
    renderEntries();
    toast("Added to this demo only; nothing was saved.");
    return;
  }
  try {
    await api("/api/add", {login: vaultUsername, master: masterPassword, site: $("site").value.trim(), username: $("username").value.trim(), password: $("password").value});
    closeModal(); await refreshEntries(); toast("Password encrypted and saved.");
  } catch (err) { $("addError").textContent = err.message; }
});
$("search").addEventListener("input", renderEntries);
document.querySelectorAll(".reveal").forEach(btn => btn.addEventListener("click", () => {
  const input = $(btn.dataset.target); input.type = input.type === "password" ? "text" : "password";
}));
$("generatorNav").addEventListener("click", () => { $("appView").classList.add("hidden"); $("authView").classList.add("hidden"); $("generatorView").classList.remove("hidden"); makePassword(); });
$("backVault").addEventListener("click", () => { $("generatorView").classList.add("hidden"); $("appView").classList.remove("hidden"); });
function makePassword() {
  const groups = [];
  if ($("upper").checked) groups.push("ABCDEFGHJKLMNPQRSTUVWXYZ");
  if ($("lower").checked) groups.push("abcdefghijkmnopqrstuvwxyz");
  if ($("numbers").checked) groups.push("23456789");
  if ($("symbols").checked) groups.push("!@#$%^&*()-_=+[]{}?");
  if (!groups.length) { toast("Select at least one character type."); return; }

  const alphabet = groups.join("");
  const length = Number($("length").value);
  const random = new Uint32Array(Math.max(length, 1));
  crypto.getRandomValues(random);

  const result = Array.from({ length }, (_, i) => {
    const source = groups[i % groups.length];
    return source[random[i] % source.length];
  });

  for (let i = result.length - 1; i > 0; i--) {
    const j = random[i] % (i + 1);
    [result[i], result[j]] = [result[j], result[i]];
  }

  $("generatedPassword").value = result.join("");
  $("strengthLabel").textContent = length >= 20 && groups.length >= 3 ? "Very strong" : length >= 14 ? "Strong" : "Moderate";
  $("strengthBar").style.width = Math.min(100, length * groups.length / 1.6) + "%";
}
$("generate").addEventListener("click", makePassword);
["length","upper","lower","numbers","symbols"].forEach(id => $(id).addEventListener("input", () => {
  $("lengthValue").textContent = $("length").value; makePassword();
}));
$("copyGenerated").addEventListener("click", async () => {
  try { await navigator.clipboard.writeText($("generatedPassword").value); toast("Generated password copied."); }
  catch { toast("Clipboard access was blocked."); }
});
(async function init() {
  if (demoMode) {
    document.title = "ENCRYPT — Public Demo";
    const notice = document.createElement("div");
    notice.className = "demo-notice";
    notice.setAttribute("role", "alert");
    notice.textContent = "PUBLIC DEMO — Sample data only. Do not enter real passwords; your entries are not sent to or saved on the server.";
    notice.style.cssText = "position:sticky;top:0;z-index:10;padding:12px 20px;background:#713b16;color:#fff4d6;text-align:center;font:700 12px 'DM Sans',sans-serif;letter-spacing:.3px";
    document.body.prepend(notice);
    document.querySelector(".secure-card strong").textContent = "Public demo only";
    document.querySelector(".secure-card p").textContent = "Sample data only. This demo does not securely store or encrypt credentials.";
    document.querySelector(".secure-status").innerHTML = "<i></i> NO SERVER STORAGE";
    document.querySelector(".local-pill").textContent = "DEMO · NO STORAGE";
    document.querySelector("#authView").classList.add("hidden");
    document.querySelector("#appView").classList.remove("hidden");
    document.querySelector(".welcome-row .subheading").textContent = "Explore the password-vault interface with fake sample data.";
    document.querySelector(".stat-card:first-child small").textContent = "Fake sample entries";
    document.querySelector(".stat-card:nth-child(2) strong").textContent = "DEMO";
    document.querySelector(".stat-card:nth-child(2) small").textContent = "Encryption is not active";
    document.querySelector(".status-text").textContent = "Demo only";
    document.querySelector(".stat-card:nth-child(3) small").innerHTML = "<i class=\"green-dot\"></i> No server or database";
    document.querySelector(".modal-copy").textContent = "Demo only. Do not enter real information; entries stay in this browser session and are discarded on refresh.";
    document.querySelector(".modal-actions .primary-btn").textContent = "Add demo entry";
    $("changeMasterOpen").classList.add("hidden");
    document.querySelector(".footer-note span:first-child").textContent = "PUBLIC SAMPLE ONLY";
    document.querySelector(".footer-note span:last-child").textContent = "Static demo · No vault backend";
    entries = [
      {id: 1, site: "Example Mail", username: "alex@example.test", password: "SampleOnly!123"},
      {id: 2, site: "Demo Store", username: "shopper@example.test", password: "NotARealPassword!"},
      {id: 3, site: "Sample Cloud", username: "cloud-user@example.test", password: "FakeCredential#456"}
    ];
    renderEntries();
    openApp();
    makePassword();
    return;
  }
  try { const state = await (await fetch("/api/status")).json(); showAuth(state.initialized); }
  catch { $("authError").textContent = "Cannot reach the C server. Start encrypt_server from the project root folder."; }
})();
