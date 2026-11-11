'use strict';

/**
 * Scam-link detector (pure logic, no Discord code — easy to test).
 *
 * analyze(text) -> { flagged, score, links: [{url, host, reasons}], reasons }
 *
 * Strategy: every link in the message is scored. A link is flagged when its
 * score reaches 2 or it shows a strong scam signal on its own (look-alike
 * domain, hidden / split-up link, raw IP, ...). No lists to maintain.
 */

// ---- lists -------------------------------------------------------------------

// Built in, nothing to configure: only used so the REAL sites below are not
// mistaken for fakes when we look for look-alike domains.
const OFFICIAL = new Set([
  'discord.com', 'discord.gg', 'discordapp.com', 'discordapp.net', 'discord.media',
  'discord.new', 'discord.gift', 'discord.gifts', 'discord.status', 'discordstatus.com',
  'steamcommunity.com', 'steampowered.com',
  'popdex.xyz', 'github.com', 'githubusercontent.com',
  'tenor.com', 'giphy.com', 'imgur.com',
  'google.com', 'youtube.com', 'youtu.be', 'twitter.com', 'x.com', 't.me', 'telegram.org',
  'wikipedia.org', 'metamask.io', 'opensea.io', 'binance.com', 'coinbase.com',
]);

// Brands scammers imitate. A host that contains/resembles one of these but is
// not on an official domain gets flagged.
const BRANDS = [
  'discord', 'discordapp', 'nitro', 'steam', 'metamask',
  'opensea', 'binance', 'coinbase', 'trustwallet', 'phantom', 'uniswap',
];

const SUSPICIOUS_TLDS = new Set([
  'gift', 'gifts', 'click', 'top', 'icu', 'cyou', 'cfd', 'sbs', 'rest', 'monster',
  'quest', 'buzz', 'zip', 'mov', 'work', 'support', 'live', 'cam', 'tk', 'ml', 'ga', 'cf', 'gq',
]);

const SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 'cutt.ly', 'is.gd', 'rb.gy', 'shorturl.at', 'tiny.cc',
  'ow.ly', 'goo.gl', 't.ly', 'v.gd', 'rebrand.ly', 'bl.ink', 'lnkd.in', 'shorte.st',
]);

const SCAM_PHRASES = [
  /free\s+nitro/i, /nitro\s+(gift|giveaway|for\s+free)/i, /steam\s+gift/i,
  /claim\s+(your|the|now)/i, /airdrop/i, /verify\s+(your\s+)?(wallet|account)/i,
  /connect\s+(your\s+)?wallet/i, /seed\s+phrase|recovery\s+phrase|private\s+key/i,
  /you\s+(have\s+)?(been\s+)?(won|selected|chosen)/i, /limited\s+time/i,
  /discord\s+(staff|moderator|admin)\s+(here|team)/i, /account\s+(will\s+be\s+)?(suspended|disabled|banned)/i,
];

const TLD_FOR_BARE = [
  'com', 'net', 'org', 'io', 'gg', 'xyz', 'co', 'me', 'app', 'dev', 'info', 'biz', 'ru', 'cn',
  ...SUSPICIOUS_TLDS,
].join('|');

// ---- helpers -----------------------------------------------------------------

function normalizeText(text) {
  return String(text || '')
    .replace(/hxxp(s?)/gi, 'http$1')
    .replace(/\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}/g, '.')
    .replace(/\[\s*:\s*\]/g, ':')
    .replace(/[\u200B-\u200D\u2060\uFEFF]/g, ''); // zero-width characters
}

// Undo the tricks scammers use to hide a link from filters:
//  - split over several lines / quoted with ">"   (">http" / "> ://di" / "> sco")
//  - full-width or ideographic dots "。" and full-width letters
//  - backslashes instead of slashes, zero-width characters, markdown noise
function squash(text) {
  return normalizeText(text)
    .replace(/[\u00AD\u061C\u180E\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFE00-\uFE0F\uFEFF]/g, '') // invisible characters
    .normalize('NFKC')
    .replace(/[\u3002\uFF61\u2024\uFE52\u00B7\u2219\u22C5\u2022\u2027]/g, '.') // dot look-alikes
    .replace(/[\\\u2044\u2215\u29F8\u2571]/g, '/') // backslash and slash look-alikes
    .replace(/[\uFE13\u2236\uA789]/g, ':') // colon look-alikes
    .replace(/[\s>*_~`|]+/g, '');
}

const OBF_RE =
  /(?:https?:\/\/|www\.)[A-Za-z0-9._~:/?#@!$&()*+,;=%-]{3,200}|discord(?:app)?\.(?:gg\/|com\/invite\/)[A-Za-z0-9_-]{2,40}/gi;

// Returns { urls, obfuscated } where `obfuscated` is the Set of urls that only
// appear once the text is stitched back together.
function scan(text) {
  const t = normalizeText(text);
  const found = new Set();
  const withScheme = t.match(/\b(?:https?:\/\/|www\.)[^\s<>"'`]+/gi) || [];
  for (const u of withScheme) found.add(u.replace(/[)\].,!?;:*_~|]+$/, ''));
  const bareRe = new RegExp(`\\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.)+(?:${TLD_FOR_BARE})\\b(?:\\/[^\\s<>"'\`]*)?`, 'gi');
  for (const u of t.match(bareRe) || []) {
    if (![...found].some((f) => f.toLowerCase().includes(u.toLowerCase()))) found.add(u);
  }

  const obfuscated = new Set();
  const normalHosts = new Set([...found].map((u) => (parseHost(u) || {}).host).filter(Boolean));
  for (let u of squash(text).match(OBF_RE) || []) {
    u = u.replace(/[)\].,!?;:]+$/, '');
    const h = (parseHost(u) || {}).host;
    if (!h || normalHosts.has(h)) continue;
    if (![...found].some((f) => f.toLowerCase() === u.toLowerCase())) {
      // drop partial fragments the plain scan picked up (e.g. "cord.gg/abc")
      for (const f of [...found]) if (f !== u && u.toLowerCase().endsWith(f.toLowerCase())) found.delete(f);
      found.add(u);
      obfuscated.add(u);
    }
  }
  return { urls: [...found], obfuscated };
}

function extractUrls(text) {
  return scan(text).urls;
}

function parseHost(raw) {
  try {
    const url = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : `http://${raw}`);
    return { url, host: url.hostname.toLowerCase().replace(/\.$/, '') };
  } catch {
    return null;
  }
}

// Approximate registrable domain (example.co.uk -> example.co.uk, a.b.example.com -> example.com).
function registrable(host) {
  const parts = host.split('.');
  if (parts.length <= 2) return host;
  const [sld, tld] = [parts[parts.length - 2], parts[parts.length - 1]];
  if (tld.length === 2 && ['co', 'com', 'org', 'net', 'gov', 'ac', 'edu'].includes(sld)) {
    return parts.slice(-3).join('.');
  }
  return parts.slice(-2).join('.');
}

const matchesDomain = (set, host) => {
  const parts = host.split('.');
  for (let i = 0; i < parts.length - 1; i++) {
    if (set.has(parts.slice(i).join('.'))) return true;
  }
  return false;
};

function deHomoglyph(s) {
  return s.replace(/rn/g, 'm').replace(/[1|!]/g, 'l').replace(/0/g, 'o').replace(/5/g, 's').replace(/vv/g, 'w');
}

function levenshtein(a, b) {
  const dp = Array.from({ length: a.length + 1 }, (_, i) => [i]);
  for (let j = 1; j <= b.length; j++) dp[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    }
  }
  return dp[a.length][b.length];
}

// ---- scoring -----------------------------------------------------------------

function scoreLink(raw) {
  const parsed = parseHost(raw);
  if (!parsed) return null;
  const { url, host } = parsed;
  const reasons = [];
  let score = 0;
  let strong = false;
  const add = (pts, why, isStrong = false) => {
    score += pts;
    reasons.push(why);
    if (isStrong) strong = true;
  };

  const official = matchesDomain(OFFICIAL, host);

  if (!official) {
    const reg = registrable(host);
    const labels = host.split('.').slice(0, -1);
    const flat = deHomoglyph(host.replace(/[-_.]/g, ''));

    // Brand keyword on a non-official domain (e.g. discord-nitro.gift, steamcommunlty.com)
    const brandHit = BRANDS.find((b) => flat.includes(b));
    if (brandHit) add(2, `Imitates "${brandHit}" on an unofficial domain (${reg})`, true);

    // Typo-squat: a label within 1-2 edits of a brand (dlscord, discorcl, d1scord)
    if (!brandHit) {
      for (const label of labels) {
        const l = deHomoglyph(label);
        const b = BRANDS.find((x) => x.length >= 5 && Math.abs(x.length - l.length) <= 2 && levenshtein(x, l) <= 2);
        if (b) {
          add(2, `Look-alike of "${b}" (${label})`, true);
          break;
        }
      }
    }

    if (host.startsWith('xn--') || host.includes('.xn--')) add(2, 'Punycode / look-alike (IDN) domain', true);
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) add(2, 'Raw IP address link', true);
    if (url.username || url.password) add(2, 'Credentials in URL (user@host trick)', true);

    const tld = host.split('.').pop();
    if (SUSPICIOUS_TLDS.has(tld)) add(1, `Suspicious TLD .${tld}`);
    if ((host.match(/-/g) || []).length >= 3) add(1, 'Many hyphens in domain');
    if (host.split('.').length >= 5) add(1, 'Excessive subdomains');
    if (SHORTENERS.has(reg)) add(1, 'URL shortener (hides real destination)');
  }

  return { url: raw, host, score, strong, reasons };
}

function analyze(text) {
  const { urls, obfuscated } = scan(text);
  const links = [];
  for (const u of urls) {
    const s = scoreLink(u);
    if (!s) continue;
    if (obfuscated.has(u)) {
      s.score += 3;
      s.strong = true;
      s.reasons.push('Obfuscated link (split across lines / look-alike characters)');
    }
    links.push(s);
  }

  const phraseHits = SCAM_PHRASES.filter((re) => re.test(text)).length;
  const massPing = /@everyone|@here/.test(text);
  const context = [];
  if (phraseHits) context.push(`Scam-style wording (${phraseHits} match${phraseHits > 1 ? 'es' : ''})`);
  if (massPing && links.length) context.push('@everyone/@here ping together with a link');

  const flaggedLinks = links
    .map((l) => {
      let score = l.score;
      const reasons = [...l.reasons];
      // Context only helps push a link over the line, it never flags on its own.
      if (l.score > 0 || l.strong) {
        score += context.length;
        reasons.push(...context);
      }
      return { ...l, score, reasons: [...new Set(reasons)] };
    })
    .filter((l) => l.strong || l.score >= 2);

  const all = [...new Set(flaggedLinks.flatMap((l) => l.reasons))];
  return { flagged: flaggedLinks.length > 0, links: flaggedLinks, reasons: all, allLinks: links };
}

// Make a link unclickable for log posts: https://evil.com -> hxxps://evil[.]com
function defang(s) {
  return String(s)
    .replace(/https?:\/\//gi, (m) => m.replace(/^http/i, 'hxxp'))
    .replace(/\./g, '[.]')
    .replace(/@(everyone|here)/g, '@\u200B$1');
}

module.exports = { analyze, extractUrls, defang };