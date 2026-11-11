'use strict';

/**
 * MegaPop live display.
 *
 * - A locked "🎰 MEGAPOP LIVE" category at the top of the channel list with one
 *   voice channel per stat (pool / jackpot / 2nd prize / tickets / end time).
 *   Voice channels can't be joined, so they work as read-only display bars.
 * - Optionally one pinned embed (MEGAPOP_TEXT_CHANNEL_ID) with the full details.
 *
 * Everything is additive: this file only reads MegaPop data and edits the
 * channels/message it created itself. It never touches slash commands.
 */

const fs = require('fs');
const path = require('path');
const {
  ChannelType,
  EmbedBuilder,
  PermissionFlagsBits,
} = require('discord.js');
const config = require('../config');
const megapop = require('../api/megapop');

const STATE_FILE = path.join(config.paths.data, 'megapop-display.json');
const KEYS = ['pool', 'jackpot', 'second', 'tickets', 'ends'];
// Discord allows ~2 renames / 10 min / channel. One rename per 5 min stays safely inside that.
const MIN_RENAME_GAP_MS = 5 * 60 * 1000;

// ---- state -----------------------------------------------------------------

function loadState() {
  try {
    return JSON.parse(fs.readFileSync(STATE_FILE, 'utf8'));
  } catch {
    return {};
  }
}

function saveState(state) {
  if (!fs.existsSync(config.paths.data)) fs.mkdirSync(config.paths.data, { recursive: true });
  fs.writeFileSync(STATE_FILE, JSON.stringify(state, null, 2), 'utf8');
}

// ---- formatting ------------------------------------------------------------

function money(n) {
  if (n == null || !Number.isFinite(n)) return '—';
  const abs = Math.abs(n);
  const opts = abs >= 1000 ? { maximumFractionDigits: 0 } : { maximumFractionDigits: 2 };
  return `$${n.toLocaleString('en-US', opts)}`;
}

function count(n) {
  if (n == null || !Number.isFinite(n)) return '—';
  return n.toLocaleString('en-US');
}

function endLabel(ms) {
  const tz = config.megapop.timezone;
  try {
    const parts = new Intl.DateTimeFormat('en-US', {
      timeZone: tz,
      month: 'short',
      day: 'numeric',
      hour: 'numeric',
      minute: '2-digit',
      hour12: true,
      timeZoneName: 'short',
    }).format(new Date(ms));
    return parts.replace(' at ', ', ');
  } catch {
    return new Date(ms).toISOString();
  }
}

function channelNames(s) {
  let ends;
  if (s.status === megapop.STATUS.ACCUMULATING) ends = `⏰ Ends: ${endLabel(s.endAtMs)}`;
  else if (s.status === megapop.STATUS.PENDING_DRAW) ends = '⏰ Draw: pending';
  else if (s.status === megapop.STATUS.DRAWING) ends = '⏰ Drawing now…';
  else ends = '⏰ Draw complete';

  return {
    pool: `🎰 Prize Pool: ${money(s.poolTotal)}`,
    jackpot: `🥇 Mega Prize: ${money(s.jackpot)}`,
    second: `🥈 Super Prize: ${money(s.secondPrize)}`,
    tickets: `🎟️ Pop Tickets: ${count(s.totalTickets)}`,
    ends,
  };
}

function buildEmbed(s) {
  const unix = Math.floor(s.endAtMs / 1000);
  const endsValue =
    s.status === megapop.STATUS.ACCUMULATING
      ? `<t:${unix}:F>\n(<t:${unix}:R>)`
      : `${s.statusLabel}`;

  return new EmbedBuilder()
    .setTitle(`🎰 MegaPop — Epoch ${s.epoch}`)
    .setColor(0x7df9ff)
    .addFields(
      { name: '💰 Prize Pool', value: money(s.poolTotal), inline: true },
      { name: '🥇 Jackpot', value: money(s.jackpot), inline: true },
      { name: '🥈 2nd Prize', value: money(s.secondPrize), inline: true },
      { name: '🎟️ Total Tickets', value: count(s.totalTickets), inline: true },
      { name: '⏰ Last Date & Time', value: endsValue, inline: true },
      { name: '📌 Status', value: s.statusLabel, inline: true }
    )
    .setFooter({ text: 'Live from the MegaPop on-chain contract' })
    .setTimestamp(new Date());
}

// ---- display service -------------------------------------------------------

class MegaPopDisplay {
  constructor(client) {
    this.client = client;
    this.state = loadState();
    this.running = false;
    this.timer = null;
    this.lastEmbedSig = null;
  }

  start() {
    const cfg = config.megapop;
    if (!cfg.rpcUrl) {
      console.warn('[megapop] MEGAPOP_RPC_URL not set — live display disabled.');
      return;
    }
    console.log(`[megapop] live display starting (refresh every ${cfg.refreshMs / 1000}s).`);
    this.tick();
    this.timer = setInterval(() => this.tick(), cfg.refreshMs);
  }

  stop() {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }

  resolveGuild() {
    const id = config.megapop.guildId;
    if (id) return this.client.guilds.cache.get(id) || null;
    if (this.client.guilds.cache.size === 1) return this.client.guilds.cache.first();
    console.warn('[megapop] Bot is in several servers — set MEGAPOP_GUILD_ID in .env.');
    return null;
  }

  async tick() {
    if (this.running) return; // never overlap runs
    this.running = true;
    try {
      const guild = this.resolveGuild();
      if (!guild) return;

      const snapshot = await megapop.getMegaPopSnapshot();
      await this.ensureChannels(guild);
      await this.updateChannels(guild, snapshot);
      await this.updateEmbed(guild, snapshot);
    } catch (err) {
      // Keep the last good values on screen; try again next tick.
      console.error('[megapop] refresh failed:', err.message, '| method:', err.method, '| path:', err.url || err.path);
    } finally {
      this.running = false;
    }
  }

  // -- channel setup ---------------------------------------------------------

  async fetchChannel(guild, id) {
    if (!id) return null;
    try {
      return (await guild.channels.fetch(id)) || null;
    } catch {
      return null; // deleted or no access
    }
  }

  async ensureChannels(guild) {
    const state = this.state;
    state.guildId = guild.id;
    state.channels = state.channels || {};

    const lockedOverwrites = [
      {
        id: guild.roles.everyone.id,
        allow: [PermissionFlagsBits.ViewChannel],
        deny: [PermissionFlagsBits.Connect],
      },
      {
        // Let the bot itself keep access so it can rename the channels.
        id: this.client.user.id,
        allow: [
          PermissionFlagsBits.ViewChannel,
          PermissionFlagsBits.Connect,
          PermissionFlagsBits.ManageChannels,
        ],
      },
    ];

    const everyoneId = guild.roles.everyone.id;

    let category = await this.fetchChannel(guild, config.megapop.categoryId || state.categoryId);
    if (!category) {
      category = await guild.channels.create({
        name: config.megapop.categoryName,
        type: ChannelType.GuildCategory,
        permissionOverwrites: lockedOverwrites,
        reason: 'MegaPop live display',
      });
      await category.setPosition(0).catch(() => {});
      state.categoryId = category.id;
      saveState(state);
      console.log('[megapop] created category', category.id);
    }
    // Re-apply the lock every run, so channels created earlier (or edited by hand) get fixed too.
    await this.enforceLock(category, everyoneId);

    for (const key of KEYS) {
      const existing = await this.fetchChannel(guild, state.channels[key]);
      if (existing) {
        await this.enforceLock(existing, everyoneId);
        continue;
      }
      const created = await guild.channels.create({
        name: `🎰 MegaPop ${key}`,
        type: ChannelType.GuildVoice,
        parent: category.id,
        permissionOverwrites: lockedOverwrites,
        reason: 'MegaPop live display',
      });
      state.channels[key] = created.id;
      delete (state.lastRenameAt || {})[key];
      saveState(state);
      console.log(`[megapop] created voice channel ${key}`, created.id);
    }
  }

  /**
   * Make sure nobody can join: @everyone can see the channel but not Connect,
   * and no other role/member override re-grants Connect. The bot keeps access.
   * Only calls the Discord API when something is actually wrong.
   * (Server admins / owner bypass channel permissions in Discord — that cannot be blocked.)
   */
  async enforceLock(target, everyoneId) {
    const botId = this.client.user.id;
    const CONNECT = PermissionFlagsBits.Connect;
    const overwrites = target.permissionOverwrites;
    try {
      const everyone = overwrites.cache.get(everyoneId);
      if (!everyone || !everyone.deny.has(CONNECT) || everyone.allow.has(CONNECT)) {
        await overwrites.edit(everyoneId, { ViewChannel: true, Connect: false }, { reason: 'MegaPop display lock' });
      }

      const bot = overwrites.cache.get(botId);
      if (!bot || !bot.allow.has(CONNECT) || !bot.allow.has(PermissionFlagsBits.ManageChannels)) {
        await overwrites.edit(
          botId,
          { ViewChannel: true, Connect: true, ManageChannels: true },
          { reason: 'MegaPop display lock' }
        );
      }

      // Any other role/member that was explicitly allowed to Connect would beat the @everyone deny.
      for (const ow of overwrites.cache.values()) {
        if (ow.id === everyoneId || ow.id === botId) continue;
        if (ow.allow.has(CONNECT)) {
          await ow.edit({ Connect: false }, 'MegaPop display lock');
        }
      }
    } catch (err) {
      console.error(
        `[megapop] could not lock "${target.name}": ${err.message} ` +
          '(the bot needs Manage Channels + Manage Roles, and its role must be above the roles it overrides)'
      );
    }
  }

  // -- updates ---------------------------------------------------------------

  async updateChannels(guild, snapshot) {
    const names = channelNames(snapshot);
    const state = this.state;
    state.lastRenameAt = state.lastRenameAt || {};
    const now = Date.now();

    for (const key of KEYS) {
      const channel = await this.fetchChannel(guild, state.channels[key]);
      if (!channel) continue;
      const wanted = names[key].slice(0, 100);
      if (channel.name === wanted) continue; // only rename when the value changed
      if (now - (state.lastRenameAt[key] || 0) < MIN_RENAME_GAP_MS) continue; // stay under Discord's limit
      try {
        await channel.setName(wanted, 'MegaPop live update');
        state.lastRenameAt[key] = now;
        saveState(state);
      } catch (err) {
        console.error(`[megapop] rename ${key} failed:`, err.message);
      }
    }
  }

  async updateEmbed(guild, snapshot) {
    const textId = config.megapop.textChannelId;
    if (!textId) return;

    const sig = JSON.stringify([
      snapshot.epoch,
      snapshot.status,
      snapshot.endAtMs,
      snapshot.poolTotal,
      snapshot.jackpot,
      snapshot.secondPrize,
      snapshot.totalTickets,
    ]);
    if (sig === this.lastEmbedSig && this.state.messageId) return; // nothing changed

    const channel = await this.fetchChannel(guild, textId);
    if (!channel || !channel.isTextBased()) {
      console.warn('[megapop] MEGAPOP_TEXT_CHANNEL_ID is not a text channel the bot can see.');
      return;
    }

    const payload = { embeds: [buildEmbed(snapshot)] };
    let message = null;
    if (this.state.messageId && this.state.textChannelId === channel.id) {
      message = await channel.messages.fetch(this.state.messageId).catch(() => null);
    }

    if (message) {
      await message.edit(payload);
    } else {
      message = await channel.send(payload);
      await message.pin().catch((err) => console.warn('[megapop] could not pin:', err.message));
      this.state.messageId = message.id;
      this.state.textChannelId = channel.id;
      saveState(this.state);
    }
    this.lastEmbedSig = sig;
  }
}

module.exports = { MegaPopDisplay, channelNames, buildEmbed };