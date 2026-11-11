'use strict';

/**
 * MegaPop reader — talks to the MegaPop rewards precompile (0x1013) over
 * plain JSON-RPC `eth_call`. Read-only: it never sends a transaction and
 * needs no wallet or private key.
 *
 * Like the rest of src/api/, nothing in here imports discord.js.
 */

const axios = require('axios');
const { Interface, formatUnits } = require('ethers');
const config = require('../config');
const popdexClient = require('./client');

const STATUS_LABELS = ['Accumulating', 'PendingDraw', 'Drawing', 'PayingOut'];
const STATUS = { ACCUMULATING: 0, PENDING_DRAW: 1, DRAWING: 2, PAYING_OUT: 3 };

// ---- ABI (only the read functions this bot needs) -------------------------

const TIER_CFG =
  'tuple(uint8 tier, uint8 matchCount, uint8 payoutType, uint256 payoutValue, uint256 prizeBoostPctWhenMegaMiss)';
const GLOBAL_CFG =
  'tuple(address settlementTokenAddress, uint256 poolInjectionRate, uint256 ticketThreshold, uint32 ticketCap, uint256 fixedPrizeCapPct, uint64 nextEpochStartAtMs, uint64 epochDurationMs)';
const TIER_RES =
  'tuple(uint8 tier, uint8 matchCount, uint8 payoutType, uint256 payoutValue, uint256 prizeBoostPctWhenMegaMiss, uint256 winningAmountPerTicket, uint256 winningAmount, uint64 winningTicketCount, uint64 winningUserCount)';
const POOL_ROW =
  'tuple(address tokenAddress, uint256 totalAmount, uint256 cumulativeInjectAmount, uint256 rolloverFromPrevAmount, uint256 rolloverToNextAmount, uint256 totalPayoutAmount)';
const EPOCH_INFO = `tuple(uint16 epoch, uint8 status, ${GLOBAL_CFG} config, uint64 startAtMs, uint64 endAtMs, uint64 drawAtMs, uint32 winningNumber, bytes32 drawTxHash, uint64 winningTicketCount, uint64 winningUserCount, ${TIER_CFG}[] tiersConfig, ${TIER_RES}[] tiersResult)`;

const megapopIface = new Interface([
  'function getLatestEpochId() view returns (uint16 epochId)',
  `function getEpochPool(uint16 epoch) view returns (${POOL_ROW}[] pools)`,
  `function getMegaPopEpochInfo(uint16 epoch) view returns (${EPOCH_INFO} info)`,
]);
const erc20Iface = new Interface(['function decimals() view returns (uint8)']);

class MegaPopError extends Error {
  constructor(message, { cause } = {}) {
    super(message);
    this.name = 'MegaPopError';
    this.cause = cause;
  }
}

// ---- low level -------------------------------------------------------------

async function ethCall(to, data) {
  const url = config.megapop.rpcUrl;
  if (!url) throw new MegaPopError('MEGAPOP_RPC_URL is not set.');
  let res;
  try {
    res = await axios.post(
      url,
      { jsonrpc: '2.0', id: 1, method: 'eth_call', params: [{ to, data }, 'latest'] },
      { timeout: config.popdex.httpTimeoutMs, headers: { 'Content-Type': 'application/json' } }
    );
  } catch (err) {
    throw new MegaPopError(`MegaPop RPC request failed: ${err.message}`, { cause: err });
  }
  const body = res.data;
  if (!body || body.error) {
    throw new MegaPopError(`MegaPop RPC error: ${body?.error?.message || 'empty response'}`);
  }
  return body.result;
}

async function callPrecompile(fn, args = []) {
  const data = megapopIface.encodeFunctionData(fn, args);
  const raw = await ethCall(config.megapop.precompile, data);
  return megapopIface.decodeFunctionResult(fn, raw)[0];
}

// ---- token decimals (cached) ----------------------------------------------

const decimalsCache = new Map();

async function getTokenDecimals(tokenAddress) {
  const key = (tokenAddress || '').toLowerCase();
  if (decimalsCache.has(key)) return decimalsCache.get(key);
  let decimals = config.megapop.tokenDecimals;
  try {
    const raw = await ethCall(tokenAddress, erc20Iface.encodeFunctionData('decimals', []));
    decimals = Number(erc20Iface.decodeFunctionResult('decimals', raw)[0]);
  } catch {
    // Settlement token may not expose decimals() — fall back to MEGAPOP_TOKEN_DECIMALS.
  }
  decimalsCache.set(key, decimals);
  return decimals;
}

// ---- optional total-ticket adapter -----------------------------------------
// The MegaPop precompile interface has NO "total tickets in epoch" read (only
// getAccountTicketCount per wallet, and winningTicketCount after the draw).
// If Popdex exposes a REST endpoint for it, set MEGAPOP_TICKETS_ENDPOINT
// (use {epoch} as a placeholder) and MEGAPOP_TICKETS_FIELD (dot path inside
// the response `data`). Until then the display shows "—" — nothing is faked.

function pick(obj, dotPath) {
  return String(dotPath)
    .split('.')
    .reduce((acc, k) => (acc == null ? acc : acc[k]), obj);
}

let warnedNoTicketsEndpoint = false;

async function getTotalTickets(epoch) {
  const { ticketsEndpoint, ticketsField } = config.megapop;
  if (!ticketsEndpoint) {
    if (!warnedNoTicketsEndpoint) {
      warnedNoTicketsEndpoint = true;
      console.warn(
        '[megapop] MEGAPOP_TICKETS_ENDPOINT is empty, so the Tickets channel will show "—". ' +
          'The on-chain contract has no total-tickets read; set the Popdex REST path (use {epoch}) in .env.'
      );
    }
    return null;
  }
  try {
    const url = ticketsEndpoint.replace('{epoch}', String(epoch));
    let payload;
    if (/^https?:\/\//i.test(url)) {
      // Full URL (any host) — plain GET, accept either { data: {...} } or a bare object.
      const res = await axios.get(url, { timeout: config.popdex.httpTimeoutMs });
      payload = res.data && res.data.data !== undefined ? res.data.data : res.data;
    } else {
      // Path relative to the Popdex REST base — uses the { code, msg, data } envelope.
      payload = (await popdexClient.get(url)).data;
    }
    const raw = pick(payload, ticketsField);
    const value = Number(raw);
    if (raw == null || !Number.isFinite(value)) {
      console.error(
        `[megapop] tickets field "${ticketsField}" not found in response: ` +
          JSON.stringify(payload).slice(0, 300)
      );
      return null;
    }
    return value;
  } catch (err) {
    console.error('[megapop] total tickets lookup failed:', err.message);
    return null;
  }
}

// ---- main snapshot ---------------------------------------------------------

function tierAmount(tier, poolTotal, resultsByTier, status, decimals) {
  if (!tier) return null;
  if (status === STATUS.PAYING_OUT) {
    const r = resultsByTier.get(Number(tier.tier));
    if (r && r.winningAmount > 0n) return Number(formatUnits(r.winningAmount, decimals));
  }
  const value = Number(formatUnits(tier.payoutValue, 18));
  // payoutType: 0 = Fixed (amount, 18dp), 1 = FloatingPct (share of pool, 18dp)
  return Number(tier.payoutType) === 1 ? value * poolTotal : value;
}

/**
 * Returns everything the Discord display needs for the latest epoch.
 * Throws MegaPopError if the chain can't be read.
 */
async function getMegaPopSnapshot() {
  const epoch = Number(await callPrecompile('getLatestEpochId'));
  if (!epoch) throw new MegaPopError('MegaPop has no epoch yet (latestEpochId = 0).');

  const [info, pools] = await Promise.all([
    callPrecompile('getMegaPopEpochInfo', [epoch]),
    callPrecompile('getEpochPool', [epoch]),
  ]);

  const settlement = info.config.settlementTokenAddress;
  const decimals = await getTokenDecimals(settlement);

  const poolRow =
    pools.find((p) => p.tokenAddress.toLowerCase() === settlement.toLowerCase()) || pools[0];
  const poolTotal = poolRow ? Number(formatUnits(poolRow.totalAmount, decimals)) : 0;

  // Highest matchCount = jackpot, next highest = 2nd prize.
  const tiers = [...info.tiersConfig].sort((a, b) => Number(b.matchCount) - Number(a.matchCount));
  const status = Number(info.status);
  const resultsByTier = new Map(info.tiersResult.map((r) => [Number(r.tier), r]));

  return {
    epoch,
    status,
    statusLabel: STATUS_LABELS[status] || `Status ${status}`,
    startAtMs: Number(info.startAtMs),
    endAtMs: Number(info.endAtMs),
    drawAtMs: Number(info.drawAtMs),
    poolTotal,
    jackpot: tierAmount(tiers[0], poolTotal, resultsByTier, status, decimals),
    secondPrize: tierAmount(tiers[1], poolTotal, resultsByTier, status, decimals),
    totalTickets: await getTotalTickets(epoch),
  };
}

module.exports = { getMegaPopSnapshot, MegaPopError, STATUS, STATUS_LABELS };