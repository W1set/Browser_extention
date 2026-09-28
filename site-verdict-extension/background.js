const api = globalThis.browser || globalThis.chrome;

// background.js
// Single merged file: domain analysis logic (RDAP, VirusTotal, typosquatting, verdict)
// plus tab tracking and message handling from popup.js.
// Kept in one file on purpose — this guarantees global functions/constants are
// visible to each other, with no risk of multi-<script> load-order issues.

// Small list of well-known brand domains — used for the "looks like the official
// site of X" heuristic and for typosquatting/impersonation detection.
// Not exhaustive; extend it for your own needs via options.html.
const DEFAULT_KNOWN_BRANDS = [
  // Big tech / search / social
  "google.com", "youtube.com", "facebook.com", "instagram.com", "whatsapp.com",
  "apple.com", "microsoft.com", "amazon.com", "netflix.com", "twitter.com", "x.com",
  "linkedin.com", "telegram.org", "wikipedia.org", "reddit.com", "tiktok.com",
  "discord.com", "snapchat.com", "pinterest.com", "twitch.tv", "signal.org", "viber.com",
  "gmail.com", "outlook.com", "yahoo.com", "protonmail.com", "icloud.com",
  // Dev / cloud
  "github.com", "gitlab.com", "dropbox.com", "adobe.com", "cloudflare.com",
  "digitalocean.com", "heroku.com", "vercel.com", "netlify.com", "zoom.us",
  "slack.com", "notion.so", "figma.com", "oracle.com", "ibm.com", "salesforce.com",
  // Payments / finance
  "paypal.com", "visa.com", "mastercard.com", "americanexpress.com", "stripe.com",
  "square.com", "venmo.com", "wise.com", "revolut.com", "chase.com", "wellsfargo.com",
  "bankofamerica.com", "hsbc.com",
  // Crypto
  "binance.com", "coinbase.com", "kraken.com", "crypto.com", "kucoin.com",
  "bybit.com", "okx.com", "bitfinex.com", "gemini.com", "metamask.io",
  "trustwallet.com", "ledger.com", "blockchain.com",
  // Shopping / delivery
  "ebay.com", "aliexpress.com", "alibaba.com", "etsy.com", "walmart.com",
  "target.com", "bestbuy.com", "ikea.com", "rozetka.ua", "dhl.com", "fedex.com",
  "ups.com", "usps.com", "novaposhta.ua", "ukrposhta.ua",
  // Gaming
  "steampowered.com", "epicgames.com", "playstation.com", "xbox.com", "ea.com",
  "blizzard.com", "riotgames.com", "roblox.com", "minecraft.net", "spotify.com",
  // Security software
  "kaspersky.com", "avast.com", "norton.com", "mcafee.com", "bitdefender.com",
  // Ukraine-specific banks / gov / services
  "bank.gov.ua", "privatbank.ua", "monobank.ua", "oschadbank.ua", "ukrsibbank.com",
  "raiffeisen.ua", "pumb.ua", "diia.gov.ua"
];

// Keywords that often appear alongside a brand name in phishing domains
// (e.g. "paypal-secure-login.com"). Used only to adjust confidence, not to
// block anything outright.
const SUSPICIOUS_KEYWORDS = [
  "login", "signin", "log-in", "sign-in", "secure", "security", "verify",
  "verification", "update", "confirm", "account", "password", "wallet",
  "support", "service", "recover", "unlock", "billing", "auth"
];

// Registrars used almost exclusively for corporate brand protection by large
// companies. Seeing one of these is a positive signal; NOT seeing one is not
// a negative signal (small legitimate sites use ordinary registrars too).
const TRUSTED_REGISTRARS = [
  "markmonitor", "csc corporate domains", "csc global", "safenames",
  "com laude", "amazon registrar"
];

function getRegistrableDomain(hostname) {
  // Simple extraction of the "registrable domain" (without subdomains).
  // An approximation for tricky cases (co.uk etc.), but good enough for this heuristic.
  const parts = hostname.toLowerCase().split(".").filter(Boolean);
  if (parts.length <= 2) return parts.join(".");
  const twoPartTlds = new Set(["co.uk", "com.ua", "co.jp", "com.br", "com.au", "org.uk", "gov.ua"]);
  const lastTwo = parts.slice(-2).join(".");
  if (twoPartTlds.has(lastTwo) && parts.length >= 3) {
    return parts.slice(-3).join(".");
  }
  return parts.slice(-2).join(".");
}

function levenshtein(a, b) {
  const m = a.length, n = b.length;
  const dp = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(
        dp[i - 1][j] + 1,
        dp[i][j - 1] + 1,
        dp[i - 1][j - 1] + cost
      );
    }
  }
  return dp[m][n];
}

function brandNameFromDomain(brandDomain) {
  // "paypal.com" -> "paypal"
  return brandDomain.split(".")[0];
}

function hasSuspiciousKeyword(hostname) {
  const h = hostname.toLowerCase();
  return SUSPICIOUS_KEYWORDS.some(k => h.includes(k));
}

function isPunycode(hostname) {
  return hostname.toLowerCase().split(".").some(label => label.startsWith("xn--"));
}

function checkBrandMatch(hostname, registrableDomain, brands) {
  const host = registrableDomain.toLowerCase();
  const fullHost = hostname.toLowerCase();

  // 1. Exact match on the registrable domain — e.g. "accounts.google.com"
  //    registers as "google.com" and matches here.
  for (const brand of brands) {
    if (host === brand) {
      return { type: "exact", brand };
    }
  }

  // 2. Edit-distance typosquatting on the registrable domain, e.g. "gogle.com".
  for (const brand of brands) {
    const dist = levenshtein(host, brand);
    // Threshold depends on name length to avoid false positives on short domains.
    const threshold = brand.length <= 6 ? 1 : 2;
    if (dist > 0 && dist <= threshold) {
      return { type: "typosquat", brand, distance: dist };
    }
  }

  // 3. Brand name used as a whole label somewhere in the full hostname, but the
  //    registrable domain is something else entirely — e.g. "paypal-secure-login.com"
  //    or "paypal.attacker-domain.com". Matching whole dot/hyphen-separated
  //    tokens (rather than a raw substring) avoids false positives like
  //    "pineapple.com" for the brand "apple".
  const tokens = fullHost.split(/[.-]+/).filter(Boolean);
  for (const brand of brands) {
    const name = brandNameFromDomain(brand);
    if (name.length >= 4 && host !== brand && tokens.includes(name)) {
      return {
        type: "impersonation",
        brand,
        suspiciousKeyword: hasSuspiciousKeyword(fullHost)
      };
    }
  }

  // 4. Punycode (xn--) labels are sometimes used for homograph/look-alike
  //    character attacks. Not proof of anything by itself, so it's only
  //    flagged when nothing else matched.
  if (isPunycode(fullHost)) {
    return { type: "punycode" };
  }

  return { type: "unknown" };
}

function checkRegistrarTrust(registrar) {
  if (!registrar) return false;
  const r = registrar.toLowerCase();
  return TRUSTED_REGISTRARS.some(t => r.includes(t));
}

async function fetchRdap(domain) {
  try {
    const resp = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
      headers: { "Accept": "application/rdap+json" }
    });
    if (!resp.ok) {
      return { ok: false, status: resp.status };
    }
    const data = await resp.json();
    const events = data.events || [];
    const regEvent = events.find(e => e.eventAction === "registration");
    const updEvent = events.find(e =>
      e.eventAction === "last changed" || e.eventAction === "last update of RDAP database"
    );
    const expEvent = events.find(e => e.eventAction === "expiration");
    return {
      ok: true,
      registrationDate: regEvent ? regEvent.eventDate : null,
      lastChanged: updEvent ? updEvent.eventDate : null,
      expirationDate: expEvent ? expEvent.eventDate : null,
      registrar: (data.entities || [])
        .find(e => (e.roles || []).includes("registrar"))?.vcardArray?.[1]
        ?.find(f => f[0] === "fn")?.[3] || null
    };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
}

async function fetchVirusTotal(domain, apiKey) {
  if (!apiKey) return null;
  try {
    const resp = await fetch(`https://www.virustotal.com/api/v3/domains/${encodeURIComponent(domain)}`, {
      headers: { "x-apikey": apiKey }
    });
    if (!resp.ok) {
      return { ok: false, status: resp.status };
    }
    const data = await resp.json();
    const stats = data?.data?.attributes?.last_analysis_stats || null;
    const reputation = data?.data?.attributes?.reputation ?? null;
    return { ok: true, stats, reputation };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
}

async function fetchSafeBrowsing(urlString, apiKey) {
  if (!apiKey) return null;
  try {
    const body = {
      client: { clientId: "site-verdict-extension", clientVersion: "1.0.0" },
      threatInfo: {
        threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
        platformTypes: ["ANY_PLATFORM"],
        threatEntryTypes: ["URL"],
        threatEntries: [{ url: urlString }]
      }
    };
    const resp = await fetch(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(apiKey)}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body)
      }
    );
    if (!resp.ok) {
      return { ok: false, status: resp.status };
    }
    const data = await resp.json();
    const matches = data.matches || [];
    return { ok: true, threatsFound: matches.length, threatTypes: matches.map(m => m.threatType) };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
}

function daysSince(dateStr) {
  if (!dateStr) return null;
  const then = new Date(dateStr).getTime();
  if (Number.isNaN(then)) return null;
  return Math.floor((Date.now() - then) / (1000 * 60 * 60 * 24));
}

function buildVerdict({ isHttps, brandMatch, ageDays, vt, gsb, registrarTrusted, registrar }) {
  const reasons = [];
  let score = 50; // 0 = very suspicious, 100 = looks trustworthy

  if (!isHttps) {
    score -= 25;
    reasons.push("Connection does not use HTTPS");
  }

  if (brandMatch.type === "exact") {
    score += 20;
    reasons.push(`Domain exactly matches known site "${brandMatch.brand}"`);
  } else if (brandMatch.type === "typosquat") {
    score -= 40;
    reasons.push(`Domain looks suspiciously similar to "${brandMatch.brand}" (possible phishing/typosquatting)`);
  } else if (brandMatch.type === "impersonation") {
    const brandName = brandNameFromDomain(brandMatch.brand);
    if (brandMatch.suspiciousKeyword) {
      score -= 45;
      reasons.push(`Domain contains "${brandName}" alongside a login/security-style word — a classic phishing pattern, and this is NOT ${brandMatch.brand}`);
    } else {
      score -= 30;
      reasons.push(`Domain contains "${brandName}" but is not the official ${brandMatch.brand}`);
    }
  } else if (brandMatch.type === "punycode") {
    score -= 15;
    reasons.push("Domain uses punycode (xn--) encoding, sometimes used to disguise look-alike characters");
  }

  if (ageDays === null) {
    reasons.push("Could not determine domain registration date");
  } else if (ageDays < 30) {
    score -= 25;
    reasons.push(`Domain was registered very recently (${ageDays} days ago)`);
  } else if (ageDays < 180) {
    score -= 10;
    reasons.push(`Domain is less than 6 months old (${ageDays} days)`);
  } else if (ageDays > 365 * 2) {
    score += 15;
    reasons.push(`Domain has existed for a long time (>${Math.floor(ageDays / 365)} years)`);
  } else {
    reasons.push(`Domain age: ~${ageDays} days`);
  }

  if (registrarTrusted) {
    score += 10;
    reasons.push(`Registered via ${registrar} — a registrar mainly used for corporate brand protection`);
  }

  if (vt && vt.ok && vt.stats) {
    const { malicious = 0, suspicious = 0, harmless = 0 } = vt.stats;
    if (malicious > 0) {
      score -= Math.min(40, malicious * 8);
      reasons.push(`VirusTotal: ${malicious} engines flag this site as malicious`);
    } else if (suspicious > 0) {
      score -= Math.min(20, suspicious * 5);
      reasons.push(`VirusTotal: ${suspicious} engines flag this site as suspicious`);
    } else if (harmless > 0) {
      score += 10;
      reasons.push(`VirusTotal: ${harmless} engines consider this site safe`);
    }
  }

  if (gsb && gsb.ok) {
    if (gsb.threatsFound > 0) {
      score -= 50;
      reasons.push(`Google Safe Browsing: this URL is flagged as a known threat (${gsb.threatTypes.join(", ")})`);
    } else {
      score += 5;
      reasons.push("Google Safe Browsing: no known threats found");
    }
  }

  score = Math.max(0, Math.min(100, score));

  let label, level;
  if (score >= 70) {
    label = "Likely a trustworthy site";
    level = "good";
  } else if (score >= 45) {
    label = "Not enough data / moderate risk";
    level = "warn";
  } else {
    label = "High risk — be careful";
    level = "danger";
  }

  return { score, label, level, reasons };
}

async function analyzeUrl(urlString, options = {}) {
  const url = new URL(urlString);
  const hostname = url.hostname;
  const domain = getRegistrableDomain(hostname);
  const isHttps = url.protocol === "https:";
  const brands = options.brands || DEFAULT_KNOWN_BRANDS;
  const vtApiKey = options.vtApiKey || null;
  const gsbApiKey = options.gsbApiKey || null;

  const [rdap, vt, gsb] = await Promise.all([
    fetchRdap(domain),
    fetchVirusTotal(domain, vtApiKey),
    fetchSafeBrowsing(urlString, gsbApiKey)
  ]);

  const brandMatch = checkBrandMatch(hostname, domain, brands);
  const ageDays = rdap.ok ? daysSince(rdap.registrationDate) : null;
  const registrarTrusted = rdap.ok ? checkRegistrarTrust(rdap.registrar) : false;

  const verdict = buildVerdict({
    isHttps, brandMatch, ageDays, vt, gsb,
    registrarTrusted, registrar: rdap.ok ? rdap.registrar : null
  });

  return {
    hostname,
    domain,
    isHttps,
    rdap,
    vt,
    gsb,
    brandMatch,
    registrarTrusted,
    ageDays,
    verdict,
    analyzedAt: new Date().toISOString()
  };
}

const resultsByTab = new Map();

function domainKeyFromUrl(urlString) {
  try {
    return new URL(urlString).hostname;
  } catch (e) {
    return null;
  }
}

async function getOptions() {
  const stored = await api.storage.local.get(["vtApiKey", "gsbApiKey", "customBrands"]);
  const brands = DEFAULT_KNOWN_BRANDS.concat(stored.customBrands || []);
  return { vtApiKey: stored.vtApiKey || null, gsbApiKey: stored.gsbApiKey || null, brands };
}

function setBadge(tabId, verdict) {
  const colors = { good: "#2ecc71", warn: "#f1c40f", danger: "#e74c3c" };
  const text = { good: "OK", warn: "?", danger: "!" };
  api.action.setBadgeText({ tabId, text: text[verdict.level] || "" });
  api.action.setBadgeBackgroundColor({ tabId, color: colors[verdict.level] || "#999" });
}

async function analyzeAndStore(tabId, url) {
  if (!url || !/^https?:\/\//.test(url)) {
    resultsByTab.delete(tabId);
    api.action.setBadgeText({ tabId, text: "" });
    return;
  }
  api.action.setBadgeText({ tabId, text: "…" });
  api.action.setBadgeBackgroundColor({ tabId, color: "#3498db" });
  try {
    const options = await getOptions();
    const result = await analyzeUrl(url, options);
    resultsByTab.set(tabId, result);
    setBadge(tabId, result.verdict);
  } catch (e) {
    resultsByTab.set(tabId, { error: String(e) });
    api.action.setBadgeText({ tabId, text: "×" });
    api.action.setBadgeBackgroundColor({ tabId, color: "#999" });
  }
}

api.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url) {
    analyzeAndStore(tabId, tab.url);
  }
});

api.tabs.onActivated.addListener(async ({ tabId }) => {
  if (!resultsByTab.has(tabId)) {
    try {
      const tab = await api.tabs.get(tabId);
      if (tab.url) analyzeAndStore(tabId, tab.url);
    } catch (e) {
      // tab may have been closed — ignore
    }
  }
});

api.tabs.onRemoved.addListener((tabId) => {
  resultsByTab.delete(tabId);
});

// API key connectivity test used by the Settings page.
api.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type !== "TEST_API_KEYS") return;

  getOptions().then(async (options) => {
    const vt = await fetchVirusTotal("example.com", options.vtApiKey);
    const gsb = await fetchSafeBrowsing("https://example.com/", options.gsbApiKey);
    sendResponse({ vt, gsb });
  }).catch((e) => {
    sendResponse({ error: String(e) });
  });

  return true;
});

// Messages from popup.js
api.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "GET_RESULT_FOR_TAB") {
    const result = resultsByTab.get(message.tabId) || null;
    sendResponse({ result });
    return true;
  }
  if (message.type === "REANALYZE_TAB") {
    analyzeAndStore(message.tabId, message.url).then(() => {
      sendResponse({ result: resultsByTab.get(message.tabId) || null });
    });
    return true; // async response
  }
});
