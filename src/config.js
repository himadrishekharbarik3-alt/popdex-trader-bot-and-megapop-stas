'use strict';

require('dotenv').config();
const path = require('path');

function required(name) {
  const v = process.env[name];
  if (!v) {
    // eslint-disable-next-line no-console
    console.warn(`[config] Missing env var ${name} — set it in .env before running the bot.`);
  }
  return v;
}

const network = (process.env.POPDEX_NETWORK || 'mainnet').toLowerCase();

const restBase =
  network === 'testnet'
    ? process.env.POPDEX_REST_BASE_TESTNET || 'https://testnet-api.popdex.xyz'
    : process.env.POPDEX_REST_BASE_MAINNET || 'https://api.popdex.xyz';

const wsBase =
  network === 'testnet'
    ? process.env.POPDEX_WS_BASE_TESTNET || 'wss://testnet-ws.popdex.xyz/v1/ws/public'
    : process.env.POPDEX_WS_BASE_MAINNET || 'wss://ws.popdex.xyz/v1/ws/public';

module.exports = {
  discord: {
    token: required('DISCORD_TOKEN'),
    clientId: required('DISCORD_CLIENT_ID'),
    guildId: process.env.DISCORD_GUILD_ID || null,
  },
  popdex: {
    network,
    restBase,
    wsBase,
    language: process.env.POPDEX_LANGUAGE || 'en_US',
    httpTimeoutMs: Number(process.env.POPDEX_HTTP_TIMEOUT_MS || 8000),
  },
  megapop: {
    // JSON-RPC endpoint of the chain that hosts the MegaPop precompile (0x1013).
    rpcUrl: process.env.MEGAPOP_RPC_URL || null,
    precompile: process.env.MEGAPOP_PRECOMPILE || '0x0000000000000000000000000000000000001013',
    guildId: process.env.MEGAPOP_GUILD_ID || process.env.DISCORD_GUILD_ID || null,
    categoryId: process.env.MEGAPOP_CATEGORY_ID || null,
    categoryName: process.env.MEGAPOP_CATEGORY_NAME || '🎰 MEGAPOP LIVE',
    textChannelId: process.env.MEGAPOP_TEXT_CHANNEL_ID || null,
    refreshMs: Math.max(60000, Number(process.env.MEGAPOP_REFRESH_MS || 300000)),
    timezone: process.env.MEGAPOP_TIMEZONE || 'UTC',
    tokenDecimals: Number(process.env.MEGAPOP_TOKEN_DECIMALS || 6),
    ticketsEndpoint: process.env.MEGAPOP_TICKETS_ENDPOINT || null,
    ticketsField: process.env.MEGAPOP_TICKETS_FIELD || 'totalTickets',
  },

  cache: {
    configTtlMs: Number(process.env.CONFIG_CACHE_TTL_MS || 60000),
  },
  paths: {
    root: path.resolve(__dirname, '..'),
    assets: path.resolve(__dirname, '..', 'assets'),
    fonts: path.resolve(__dirname, '..', 'assets', 'fonts'),
    data: path.resolve(__dirname, '..', 'data'),
  },
  branding: {
    footer: 'Trade on app.popdex.xyz',
    white: '#FFFFFF',
    // Popdex brand backdrop tone used behind cards; overridden per-card asset.
    accent: '#7DF9FF',
  },
};