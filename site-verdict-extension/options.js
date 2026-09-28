const api = globalThis.browser || globalThis.chrome;
// options.js

async function load() {
  const stored = await api.storage.local.get(["vtApiKey", "gsbApiKey", "customBrands"]);
  document.getElementById("vtApiKey").value = stored.vtApiKey || "";
  document.getElementById("gsbApiKey").value = stored.gsbApiKey || "";
  document.getElementById("customBrands").value = (stored.customBrands || []).join("\n");
}

async function save() {
  const vtApiKey = document.getElementById("vtApiKey").value.trim();
  const gsbApiKey = document.getElementById("gsbApiKey").value.trim();
  const customBrands = document.getElementById("customBrands").value
    .split("\n")
    .map(s => s.trim().toLowerCase())
    .filter(Boolean);

  await api.storage.local.set({ vtApiKey, gsbApiKey, customBrands });

  const status = document.getElementById("status");
  status.textContent = "Saved ✓";
  setTimeout(() => (status.textContent = ""), 2000);
}

document.getElementById("saveBtn").addEventListener("click", save);
load();


async function testApiKeys() {
  const testStatus = document.getElementById("testStatus");
  testStatus.textContent = "Testing…";
  testStatus.style.color = "#555";

  const result = await api.runtime.sendMessage({ type: "TEST_API_KEYS" });
  const parts = [];

  if (result?.vt?.ok) {
    parts.push("VirusTotal ✓");
  } else if (result?.vt?.status) {
    parts.push(`VirusTotal ✕ (${result.vt.status})`);
  } else {
    parts.push("VirusTotal ✕");
  }

  if (result?.gsb?.ok) {
    parts.push("Google Safe Browsing ✓");
  } else if (result?.gsb?.status) {
    parts.push(`Google Safe Browsing ✕ (${result.gsb.status})`);
  } else {
    parts.push("Google Safe Browsing ✕");
  }

  testStatus.textContent = parts.join(" · ");
  testStatus.style.color = parts.every(p => p.includes("✓")) ? "#1e7e34" : "#b02a37";
}

document.getElementById("testBtn").addEventListener("click", testApiKeys);
