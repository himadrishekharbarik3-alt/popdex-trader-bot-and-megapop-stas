'use strict';

/**
 * Link reporter / anti-scam guard.
 *
 * Whenever someone posts a SCAM link, the bot sends a report to a channel of your
 * choice with: who sent it, in which channel, the exact time, the message
 * content and the link(s) (made unclickable).
 *
 *   🔴 Scam link   - looks like a scam (look-alike domain, hidden/split link,
 *                    shortener + scam wording, ...). Deleted if ANTISCAM_DELETE=true.
 *   🟠 Keyword     - the message contains one of YOUR keywords.
 *   🔵 Plain link  - any other link (only if you set ANTISCAM_REPORT=all).
 *
 * The report is built from the message the moment it arrives, so it is still sent
 * even if the message is deleted a second later (by this bot, another bot or a mod).
 *
 * Purely additive: it only adds its own listeners, nothing else in the bot is
 * touched. Stays OFF unless ANTISCAM_LOG_CHANNEL_ID is set in .env.
 *
 * Env:
 *   ANTISCAM_LOG_CHANNEL_ID    (required) channel that receives the reports
 *   ANTISCAM_REPORT            scam (default) = only scam links / keywords | all = report every link
 *   ANTISCAM_DELETE            true (default) -> delete messages that look like scams
 *   ANTISCAM_KEYWORDS          comma list, e.g. free nitro,claim your reward,connect wallet
 *   ANTISCAM_KEYWORD_DELETE    false (default) | true -> also delete keyword hits
 *   ANTISCAM_TIMEOUT_MINUTES   0 (default = off) | e.g. 60 -> time out whoever posts a scam link
 *   ANTISCAM_EXEMPT_ROLE_IDS   role IDs that are never checked (comma list)
 *   ANTISCAM_EXEMPT_MODS       false (default) | true -> admins / Manage Messages are never checked
 *   ANTISCAM_TIMEZONE          e.g. Asia/Kolkata (default UTC)
 *   ANTISCAM_PING_ROLE_ID      optional role to ping on 🔴 scam reports
 *   ANTISCAM_GUILD_ID          only watch this server ID (comma list for several). Empty = all servers
 */

const fs = require('fs');
const path = require('path');
const { EmbedBuilder, PermissionFlagsBits } = require('discord.js');
const { analyze, extractUrls, defang } = require('./detector');

const csv = (v) => String(v || '').split(',').map((s) => s.trim()).filter(Boolean);
const bool = (v, d) => (v == null || v === '' ? d : String(v).toLowerCase() !== 'false');

// ---- keywords --------------------------------------------------------------

// lower-case, letters/digits only, single spaces: "Free  NITRO!!" -> "free nitro"
const norm = (s) =>
  String(s || '')
    .toLowerCase()
    .replace(/[\u200B-\u200D\u2060\uFEFF]/g, '')
    .replace(/[^\p{L}\p{N}]+/gu, ' ')
    .trim();

function loadKeywords() {
  const raw = csv(process.env.ANTISCAM_KEYWORDS);
  try {
    const file = path.resolve(__dirname, '..', '..', 'data', 'scam-keywords.json');
    if (fs.existsSync(file)) raw.push(...JSON.parse(fs.readFileSync(file, 'utf8')).map(String));
  } catch (e) {
    console.warn('[antiscam] could not read data/scam-keywords.json:', e.message);
  }
  const seen = new Set();
  const out = [];
  for (const r of raw) {
    const n = norm(r);
    if (n && !seen.has(n)) {
      seen.add(n);
      out.push({ raw: r.trim(), n });
    }
  }
  return out;
}

const KEYWORDS = loadKeywords();

// Whole-word / whole-phrase match on the normalised text.
function matchKeywords(text) {
  if (!KEYWORDS.length || !text) return [];
  const hay = ` ${norm(text)} `;
  return KEYWORDS.filter((k) => hay.includes(` ${k.n} `)).map((k) => k.raw);
}

// ---- config ----------------------------------------------------------------

const cfg = {
  logChannelId: process.env.ANTISCAM_LOG_CHANNEL_ID || null,
  reportAll: (process.env.ANTISCAM_REPORT || 'scam').toLowerCase() === 'all',
  del: bool(process.env.ANTISCAM_DELETE, true),
  keywordDelete: bool(process.env.ANTISCAM_KEYWORD_DELETE, false),
  timeoutMin: Math.max(0, Number(process.env.ANTISCAM_TIMEOUT_MINUTES || 0)),
  exemptRoles: new Set(csv(process.env.ANTISCAM_EXEMPT_ROLE_IDS)),
  exemptMods: bool(process.env.ANTISCAM_EXEMPT_MODS, false),
  timezone: process.env.ANTISCAM_TIMEZONE || 'UTC',
  pingRoleId: process.env.ANTISCAM_PING_ROLE_ID || null,
  // Only watch these server IDs (comma list). Empty = every server the bot is in.
  guildIds: new Set(csv(process.env.ANTISCAM_GUILD_ID)),
};

function readableTime(date) {
  try {
    return new Intl.DateTimeFormat('en-US', {
      timeZone: cfg.timezone,
      weekday: 'short',
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: 'numeric',
      minute: '2-digit',
      second: '2-digit',
      hour12: true,
      timeZoneName: 'short',
    }).format(date);
  } catch {
    return date.toISOString();
  }
}

const DEBUG = bool(process.env.ANTISCAM_DEBUG, false);
const dbg = (...a) => DEBUG && console.log('[antiscam:debug]', ...a);

const unix = (d) => Math.floor(d.getTime() / 1000);
const clip = (s, n) => (s.length > n ? `${s.slice(0, n - 1)}…` : s);

class AntiScamGuard {
  constructor(client) {
    this.client = client;
    this.handled = new Map(); // messageId -> ts (dedupe)
    this.warnedEmpty = false;
  }

  start() {
    if (!cfg.logChannelId) {
      console.log('[antiscam] disabled (set ANTISCAM_LOG_CHANNEL_ID in .env to enable).');
      return;
    }

    if (DEBUG) this.startupChecks().catch((e) => console.error('[antiscam:debug] startup check failed:', e));

    this.client.on('messageCreate', (m) => {
      // CHECK 1: proves the bot actually receives messages (before any filtering).
      if (cfg.guildIds.size && m.guild && !cfg.guildIds.has(m.guild.id)) return;
      dbg(
        `RECEIVED message ${m.id} in #${m.channel?.name ?? m.channelId} from ${m.author?.tag ?? '?'}` +
          ` | bot=${!!m.author?.bot} webhook=${!!m.webhookId} contentLength=${(m.content || '').length}`
      );
      this.check(m).catch((e) => console.error('[antiscam]', e));
    });
    this.client.on('messageUpdate', async (_old, m) => {
      try {
        if (m.partial) m = await m.fetch();
        await this.check(m, true);
      } catch (e) {
        console.error('[antiscam]', e);
      }
    });

    setInterval(() => {
      const cutoff = Date.now() - 10 * 60 * 1000;
      for (const [id, t] of this.handled) if (t < cutoff) this.handled.delete(id);
    }, 5 * 60 * 1000).unref();

    console.log(
      `[antiscam] active (report: ${cfg.reportAll ? 'every link' : 'scam links only'}, ${KEYWORDS.length} keyword${KEYWORDS.length === 1 ? '' : 's'}) — reports go to channel ${cfg.logChannelId}. Watching: ${cfg.guildIds.size ? [...cfg.guildIds].join(', ') : 'ALL servers'}.`
    );
  }

  // Printed once at startup when ANTISCAM_DEBUG=true.
  async startupChecks() {
    const { IntentsBitField } = require('discord.js');
    const intents = new IntentsBitField(this.client.options.intents);
    dbg(
      `intents: GuildMessages=${intents.has('GuildMessages')} MessageContent=${intents.has('MessageContent')}` +
        ' (MessageContent must ALSO be switched on in the Developer Portal -> Bot tab)'
    );
    try {
      const ch = await this.client.channels.fetch(cfg.logChannelId);
      const me = ch.guild?.members.me;
      const perms = me ? ch.permissionsFor(me) : null;
      const need = ['ViewChannel', 'SendMessages', 'EmbedLinks'];
      const missing = perms ? need.filter((n) => !perms.has(n)) : need;
      dbg(`log channel #${ch.name}: ${missing.length ? 'MISSING ' + missing.join(', ') : 'bot can post reports there'}`);
    } catch (e) {
      console.error('[antiscam:debug] log channel NOT reachable:', e.message, '- check ANTISCAM_LOG_CHANNEL_ID and bot access');
    }
    for (const g of this.client.guilds.cache.values()) {
      if (cfg.guildIds.size && !cfg.guildIds.has(g.id)) continue;
      const me = g.members.me;
      dbg(`server "${g.name}": bot ManageMessages=${me?.permissions.has('ManageMessages')} ModerateMembers=${me?.permissions.has('ModerateMembers')}`);
    }
    dbg('Waiting for messages. Post a test message now; every message the bot sees is listed here.');
  }

  isExempt(message) {
    const member = message.member;
    if (!member) return false;
    if (member.roles.cache.some((r) => cfg.exemptRoles.has(r.id))) return true;
    if (cfg.exemptMods) {
      if (member.permissions.has(PermissionFlagsBits.Administrator)) return true;
      if (member.permissions.has(PermissionFlagsBits.ManageMessages)) return true;
    }
    return false;
  }

  async check(message, edited = false) {
    if (message.guild && cfg.guildIds.size && !cfg.guildIds.has(message.guild.id)) return; // not a watched server
    if (!message.guild || message.author?.bot || message.webhookId || message.system) {
      dbg(`IGNORED ${message.id}: ${!message.guild ? 'not in a server' : message.author?.bot ? 'sent by a bot' : message.webhookId ? 'sent by a webhook' : 'system message'}`);
      return;
    }
    if (this.handled.has(message.id)) {
      dbg(`IGNORED ${message.id}: already handled`);
      return;
    }

    const content = message.content || '';
    if (!content) {
      dbg(`IGNORED ${message.id}: EMPTY content -> Message Content Intent is OFF in the Developer Portal (or message is only an attachment/embed)`);
      if (!this.warnedEmpty && !message.attachments?.size && !message.embeds?.length) {
        this.warnedEmpty = true;
        console.warn('[antiscam] Got a message with empty content — enable "Message Content Intent" in the Discord Developer Portal (Bot tab).');
      }
      return;
    }

    const urls = extractUrls(content);
    const kw = matchKeywords(content);
    const det = analyze(content);

    const isScam = det.flagged;
    const isKeyword = kw.length > 0;
    const isLink = urls.length > 0;

    // CHECK 2: shows exactly why a message was or was not flagged.
    dbg(
      `ANALYSED ${message.id}: links=${JSON.stringify(urls)} scam=${isScam} keyword=${isKeyword ? kw.join('|') : false}` +
        ` | per-link scores: ${JSON.stringify((det.allLinks || []).map((l) => ({ host: l.host, score: l.score, strong: l.strong, why: l.reasons })))}`
    );
    if (!isScam && !isKeyword && !(cfg.reportAll && isLink)) {
      dbg(`IGNORED ${message.id}: not flagged (no scam signal, no keyword${isLink && !cfg.reportAll ? '; plain links are only reported when ANTISCAM_REPORT=all' : ''})`);
      return;
    }
    if (this.isExempt(message)) {
      dbg(`IGNORED ${message.id}: author is EXEMPT (exempt role, or admin/Manage Messages with ANTISCAM_EXEMPT_MODS=true)`);
      return;
    }
    dbg(`FLAGGED ${message.id}: sending report`);

    this.handled.set(message.id, Date.now());

    // what to show
    const reasons = [];
    if (isScam) reasons.push(...det.reasons);
    if (isKeyword) reasons.push(`Keyword: ${kw.join(', ')}`);
    if (!isScam && !isKeyword) reasons.push('Link posted (no scam signals found)');
    const links = isScam ? det.links : urls.map((u) => ({ url: u }));

    // actions
    const actions = [];
    const shouldDelete = (isScam && cfg.del) || (isKeyword && cfg.keywordDelete);
    let deleted = false;
    const me = message.guild.members.me;

    if (shouldDelete) {
      const canDelete = message.channel.permissionsFor(me)?.has(PermissionFlagsBits.ManageMessages);
      if (!canDelete) {
        actions.push('❌ Not deleted — bot lacks **Manage Messages** in this channel');
      } else {
        try {
          await message.delete();
          deleted = true;
          actions.push('🗑️ Message deleted');
        } catch (e) {
          if (e.code === 10008) {
            deleted = true;
            actions.push('🗑️ Already deleted by someone else (another bot or a moderator)');
          } else {
            actions.push(`❌ Delete failed (${e.message})`);
          }
        }
      }
    } else {
      actions.push('👀 Reported only (message left in place)');
    }

    if (isScam && cfg.timeoutMin > 0) {
      try {
        const member = message.member || (await message.guild.members.fetch(message.author.id));
        if (member.moderatable) {
          await member.timeout(cfg.timeoutMin * 60 * 1000, 'Anti-scam: posted a scam link');
          actions.push(`🔇 Timed out for ${cfg.timeoutMin} min`);
        } else {
          actions.push("❌ Timeout failed — user is above the bot's role or missing permission");
        }
      } catch (e) {
        actions.push(`❌ Timeout failed (${e.message})`);
      }
    }

    const kind = isScam ? 'scam' : isKeyword ? 'keyword' : 'link';
    const title = {
      scam: `🚨 Scam link ${edited ? '(edited message) ' : ''}detected`,
      keyword: `🔎 Keyword trigger${edited ? ' (edited message)' : ''}`,
      link: `🔗 Link posted${edited ? ' (edited message)' : ''}`,
    }[kind];

    await this.report({
      kind,
      title,
      message,
      content,
      reasons,
      links,
      actions,
      deleted,
      when: edited && message.editedAt ? message.editedAt : message.createdAt,
    });
  }

  async report({ kind, title, message, content, reasons, links, actions, deleted, when }) {
    let channel;
    try {
      channel = await this.client.channels.fetch(cfg.logChannelId);
    } catch (e) {
      console.error('[antiscam] cannot open log channel:', e.message);
      return;
    }
    if (!channel?.isTextBased()) return console.error('[antiscam] log channel is not a text channel.');

    const author = message.author;
    const member = message.member;
    const ch = message.channel;
    const color = { scam: 0xed4245, keyword: 0xfaa61a, link: 0x5865f2 }[kind];

    const linkLines = links.map((l) => `• \`${defang(l.url).slice(0, 120)}\``).join('\n') || '—';
    const safeText = `\`\`\`\n${clip(defang(content).replace(/```/g, "'''"), 900)}\n\`\`\``;

    const embed = new EmbedBuilder()
      .setColor(color)
      .setTitle(title)
      .setThumbnail(author.displayAvatarURL({ size: 128 }))
      .addFields(
        {
          name: '👤 User',
          value: `${author} — **${author.tag}**\nDisplay name: ${member?.displayName || author.globalName || author.username}\nID: \`${author.id}\``,
        },
        {
          name: '📍 Channel',
          value: `<#${ch.id}> (#${ch.name})${ch.parent ? `\nCategory: ${ch.parent.name}` : ''}`,
          inline: true,
        },
        {
          name: '🕒 Time',
          value: `<t:${unix(when)}:F> (<t:${unix(when)}:R>)\n${readableTime(when)}`,
          inline: true,
        },
        { name: '⚠️ Why it was reported', value: clip(reasons.map((r) => `• ${r}`).join('\n'), 1000) },
        { name: '🔗 Link(s) (made unclickable)', value: clip(linkLines, 1000) },
        { name: '💬 Message content (made unclickable)', value: safeText },
        { name: '🛡️ Action taken', value: clip(actions.join('\n'), 1000) },
        {
          name: '🧾 Account info',
          value: [
            `Account created: <t:${unix(author.createdAt)}:R>`,
            member?.joinedAt ? `Joined server: <t:${unix(member.joinedAt)}:R>` : null,
            `Message ID: \`${message.id}\``,
            !deleted && message.url ? `[Jump to message](${message.url})` : null,
          ]
            .filter(Boolean)
            .join('\n'),
        }
      )
      .setFooter({ text: `Link report • ${message.guild.name}` })
      .setTimestamp(when);

    const payload = { embeds: [embed], allowedMentions: { parse: [] } };
    if (cfg.pingRoleId && kind === 'scam') {
      payload.content = `<@&${cfg.pingRoleId}>`;
      payload.allowedMentions = { roles: [cfg.pingRoleId] };
    }

    try {
      await channel.send(payload);
    } catch (e) {
      console.error('[antiscam] cannot post to log channel (needs View Channel, Send Messages, Embed Links):', e.message);
    }
  }
}

module.exports = { AntiScamGuard, analyze, matchKeywords };