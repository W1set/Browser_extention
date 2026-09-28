const api = globalThis.browser || globalThis.chrome;
// popup.js

const el = (id) => document.getElementById(id);

function show(id) { el(id).classList.remove("hidden"); }
function hide(id) { el(id).classList.add("hidden"); }

function formatDate(dateStr) {
  if (!dateStr) return "unknown";
  const d = new Date(dateStr);
  if (Number.isNaN(d.getTime())) return dateStr;
  return d.toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" });
}

function renderResult(result) {
  hide("loading"); hide("empty"); hide("error");

  if (!result) {
    show("empty");
    hide("content");
    return;
  }
  if (result.error) {
    el("error").textContent = "Analysis error: " + result.error;
    show("error");
    hide("content");
    return;
  }

  show("content");

  el("domainName").textContent = result.hostname;
  const httpsBadge = el("httpsBadge");
  httpsBadge.textContent = result.isHttps ? "HTTPS" : "no HTTPS";
  httpsBadge.className = "badge " + (result.isHttps ? "https" : "nohttps");

  const box = el("verdictBox");
  box.className = "verdict-box " + result.verdict.level;
  el("verdictLabel").textContent = result.verdict.label;
  el("scoreFill").style.width = result.verdict.score + "%";
  el("scoreText").textContent = `Trust score: ${result.verdict.score} / 100`;

  const reasonsList = el("reasonsList");
  reasonsList.innerHTML = "";
  for (const reason of result.verdict.reasons) {
    const li = document.createElement("li");
    li.textContent = reason;
    reasonsList.appendChild(li);
  }

  // Domain registration
  if (result.rdap && result.rdap.ok) {
    el("regDate").textContent = formatDate(result.rdap.registrationDate);
    el("ageText").textContent = result.ageDays !== null ? `${result.ageDays} days` : "unknown";
    el("registrar").textContent = (result.rdap.registrar || "unknown") + (result.registrarTrusted ? " ✓ brand-protection registrar" : "");
    el("expDate").textContent = formatDate(result.rdap.expirationDate);
  } else {
    el("regDate").textContent = "data unavailable (RDAP did not respond)";
    el("ageText").textContent = "—";
    el("registrar").textContent = "—";
    el("expDate").textContent = "—";
  }

  // VirusTotal
  const vtBlock = el("vtBlock");
  if (!result.vt) {
    vtBlock.textContent = "No VirusTotal API key set. Add one in Settings to check reputation.";
  } else if (!result.vt.ok) {
    vtBlock.textContent = "Could not fetch VirusTotal data.";
  } else {
    const s = result.vt.stats || {};
    vtBlock.innerHTML = `
      Malicious: <b>${s.malicious ?? 0}</b> ·
      Suspicious: <b>${s.suspicious ?? 0}</b> ·
      Harmless: <b>${s.harmless ?? 0}</b> ·
      Undetected: <b>${s.undetected ?? 0}</b>
    `;
  }

  // Google Safe Browsing
  const gsbBlock = el("gsbBlock");
  if (!result.gsb) {
    gsbBlock.textContent = "No Google Safe Browsing API key set. Add one in Settings for a second reputation check.";
  } else if (!result.gsb.ok) {
    gsbBlock.textContent = "Could not fetch Google Safe Browsing data.";
  } else if (result.gsb.threatsFound > 0) {
    gsbBlock.innerHTML = `⚠ Flagged as: <b>${result.gsb.threatTypes.join(", ")}</b>`;
  } else {
    gsbBlock.textContent = "No known threats found.";
  }

  // Brand similarity
  const brandBlock = el("brandBlock");
  const bm = result.brandMatch;
  if (bm.type === "exact") {
    brandBlock.textContent = `Matches known domain "${bm.brand}".`;
  } else if (bm.type === "typosquat") {
    brandBlock.textContent = `⚠ Looks similar to "${bm.brand}" (distance ${bm.distance}). Possible spoof.`;
  } else if (bm.type === "impersonation") {
    brandBlock.textContent = `⚠ Contains "${bm.brand.split(".")[0]}" but is NOT ${bm.brand}.` +
      (bm.suspiciousKeyword ? " Combined with a login/security-style word — classic phishing pattern." : "");
  } else if (bm.type === "punycode") {
    brandBlock.textContent = "⚠ Domain uses punycode (xn--) encoding — check carefully for look-alike characters.";
  } else {
    brandBlock.textContent = "No match with known brands found.";
  }
}

async function main() {
  show("loading");
  const [tab] = await api.tabs.query({ active: true, currentWindow: true });
  if (!tab || !tab.url || !/^https?:\/\//.test(tab.url)) {
    hide("loading");
    renderResult(null);
    return;
  }

  const resp = await api.runtime.sendMessage({ type: "GET_RESULT_FOR_TAB", tabId: tab.id });
  hide("loading");
  renderResult(resp && resp.result);

  el("refreshBtn").addEventListener("click", async () => {
    show("loading");
    hide("content"); hide("error"); hide("empty");
    const r = await api.runtime.sendMessage({ type: "REANALYZE_TAB", tabId: tab.id, url: tab.url });
    hide("loading");
    renderResult(r && r.result);
  });
}

main();
