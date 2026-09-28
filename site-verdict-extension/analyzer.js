// analyzer.js;
// Вся логика анализа домена: WHOIS/RDAP, репутация, тайпсквоттинг, вердикт.
// Подключается и в background.js, и (при желании) в popup для отладки.

// Небольшой список известных доменов крупных сервисов — для эвристики
// "похоже на официальный сайт X" и обнаружения тайпсквоттинга.
// Список неполный и его стоит расширять под свои нужды через options.html.
const DEFAULT_KNOWN_BRANDS = [
  "google.com", "youtube.com", "facebook.com", "instagram.com", "whatsapp.com",
  "paypal.com", "apple.com", "microsoft.com", "amazon.com", "netflix.com",
  "binance.com", "github.com", "gitlab.com", "twitter.com", "x.com",
  "linkedin.com", "telegram.org", "steampowered.com", "wikipedia.org",
  "ebay.com", "dropbox.com", "adobe.com", "spotify.com", "reddit.com",
  "bank.gov.ua", "privatbank.ua", "monobank.ua"
];

function getRegistrableDomain(hostname) {
  // Простое извлечение "registrable domain" (без поддоменов).
  // Для сложных случаев (co.uk и т.п.) это приближение, но для эвристики достаточно.
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

function checkBrandMatch(domain, brands) {
  const host = domain.toLowerCase();
  for (const brand of brands) {
    if (host === brand) {
      return { type: "exact", brand };
    }
  }
  for (const brand of brands) {
    const dist = levenshtein(host, brand);
    // Похоже на бренд, но не совпадает точно — потенциальный тайпсквоттинг.
    // Порог зависит от длины имени, чтобы не ловить ложные срабатывания на коротких доменах.
    const threshold = brand.length <= 6 ? 1 : 2;
    if (dist > 0 && dist <= threshold) {
      return { type: "typosquat", brand, distance: dist };
    }
  }
  return { type: "unknown" };
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

function daysSince(dateStr) {
  if (!dateStr) return null;
  const then = new Date(dateStr).getTime();
  if (Number.isNaN(then)) return null;
  return Math.floor((Date.now() - then) / (1000 * 60 * 60 * 24));
}

function buildVerdict({ isHttps, brandMatch, ageDays, vt }) {
  const reasons = [];
  let score = 50; // 0 = очень подозрительно, 100 = похоже на надёжный сайт

  if (!isHttps) {
    score -= 25;
    reasons.push("Соединение не использует HTTPS");
  }

  if (brandMatch.type === "exact") {
    score += 20;
    reasons.push(`Домен точно совпадает с известным сайтом «${brandMatch.brand}»`);
  } else if (brandMatch.type === "typosquat") {
    score -= 40;
    reasons.push(`Домен подозрительно похож на «${brandMatch.brand}» (возможен фишинг/тайпсквоттинг)`);
  }

  if (ageDays === null) {
    reasons.push("Не удалось определить дату регистрации домена");
  } else if (ageDays < 30) {
    score -= 25;
    reasons.push(`Домен зарегистрирован совсем недавно (${ageDays} дн. назад)`);
  } else if (ageDays < 180) {
    score -= 10;
    reasons.push(`Домену меньше полугода (${ageDays} дн.)`);
  } else if (ageDays > 365 * 2) {
    score += 15;
    reasons.push(`Домен существует уже давно (>${Math.floor(ageDays / 365)} лет)`);
  } else {
    reasons.push(`Возраст домена: ~${ageDays} дн.`);
  }

  if (vt && vt.ok && vt.stats) {
    const { malicious = 0, suspicious = 0, harmless = 0 } = vt.stats;
    if (malicious > 0) {
      score -= Math.min(40, malicious * 8);
      reasons.push(`VirusTotal: ${malicious} движков считают сайт вредоносным`);
    } else if (suspicious > 0) {
      score -= Math.min(20, suspicious * 5);
      reasons.push(`VirusTotal: ${suspicious} движков считают сайт подозрительным`);
    } else if (harmless > 0) {
      score += 10;
      reasons.push(`VirusTotal: ${harmless} движков считают сайт безопасным`);
    }
  }

  score = Math.max(0, Math.min(100, score));

  let label, level;
  if (score >= 70) {
    label = "Вероятно надёжный сайт";
    level = "good";
  } else if (score >= 45) {
    label = "Недостаточно данных / умеренный риск";
    level = "warn";
  } else {
    label = "Высокий риск — будьте осторожны";
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

  const [rdap, vt] = await Promise.all([
    fetchRdap(domain),
    fetchVirusTotal(domain, vtApiKey)
  ]);

  const brandMatch = checkBrandMatch(domain, brands);
  const ageDays = rdap.ok ? daysSince(rdap.registrationDate) : null;

  const verdict = buildVerdict({ isHttps, brandMatch, ageDays, vt });

  return {
    hostname,
    domain,
    isHttps,
    rdap,
    vt,
    brandMatch,
    ageDays,
    verdict,
    analyzedAt: new Date().toISOString()
  };
}
