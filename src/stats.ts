/**
 * Local usage statistics — stored in ~/.depguard/stats.json
 *
 * PRIVACY: All data stays local on the user's machine.
 * Nothing is sent to any server. No telemetry. No tracking.
 * The user owns their data and can delete it anytime.
 */

import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs'
import { join } from 'node:path'
import { homedir } from 'node:os'

const DEPGUARD_DIR = join(homedir(), '.depguard')
const STATS_PATH = join(DEPGUARD_DIR, 'stats.json')

export interface DepguardStats {
  firstUsed: string
  lastUsed: string
  totalCalls: number
  calls: Record<string, number>
  tokensEstimatedSaved: number
  packagesAudited: number
  threatsBlocked: number
  reviewFindings: number
}

function defaultStats(): DepguardStats {
  return {
    firstUsed: new Date().toISOString().slice(0, 10),
    lastUsed: new Date().toISOString().slice(0, 10),
    totalCalls: 0,
    calls: {},
    tokensEstimatedSaved: 0,
    packagesAudited: 0,
    threatsBlocked: 0,
    reviewFindings: 0,
  }
}

/** Load stats from disk. Returns defaults if file doesn't exist. */
export function loadStats(): DepguardStats {
  try {
    if (!existsSync(STATS_PATH)) return defaultStats()
    const raw = readFileSync(STATS_PATH, 'utf-8')
    return { ...defaultStats(), ...JSON.parse(raw) }
  } catch {
    return defaultStats()
  }
}

/** Save stats to disk. Never throws. */
function saveStats(stats: DepguardStats): void {
  try {
    if (!existsSync(DEPGUARD_DIR)) {
      mkdirSync(DEPGUARD_DIR, { recursive: true })
    }
    writeFileSync(STATS_PATH, JSON.stringify(stats, null, 2))
  } catch { /* silent — stats are best-effort */ }
}

/** Record a tool call with optional metrics. */
export function recordCall(
  toolName: string,
  metrics?: {
    tokensSaved?: number
    packagesAudited?: number
    threatsBlocked?: number
    reviewFindings?: number
  },
): void {
  const stats = loadStats()
  stats.lastUsed = new Date().toISOString().slice(0, 10)
  stats.totalCalls++
  stats.calls[toolName] = (stats.calls[toolName] ?? 0) + 1

  if (metrics?.tokensSaved) stats.tokensEstimatedSaved += metrics.tokensSaved
  if (metrics?.packagesAudited) stats.packagesAudited += metrics.packagesAudited
  if (metrics?.threatsBlocked) stats.threatsBlocked += metrics.threatsBlocked
  if (metrics?.reviewFindings) stats.reviewFindings += metrics.reviewFindings

  saveStats(stats)
}

/** Format a number with K/M suffix. */
function formatNumber(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`
  return String(n)
}

/** Format days since first use. */
function daysSince(dateStr: string): number {
  const then = new Date(dateStr).getTime()
  return Math.max(1, Math.floor((Date.now() - then) / (1000 * 60 * 60 * 24)))
}

/**
 * Print a compact stats banner to stderr.
 * Called when the MCP server starts.
 */
export function printStatsBanner(): void {
  const stats = loadStats()

  // Don't show banner on first ever run
  if (stats.totalCalls === 0) {
    process.stderr.write(`\n  depguard v${getVersion()} — ready\n\n`)
    return
  }

  const days = daysSince(stats.firstUsed)
  const tokens = formatNumber(stats.tokensEstimatedSaved)
  const calls = formatNumber(stats.totalCalls)

  const lines = [
    '',
    `  depguard v${getVersion()}`,
    `  ${calls} calls over ${days} day${days > 1 ? 's' : ''} | ${tokens} tokens saved | ${stats.packagesAudited} packages audited`,
  ]

  if (stats.threatsBlocked > 0) {
    lines.push(`  ${stats.threatsBlocked} threat${stats.threatsBlocked > 1 ? 's' : ''} blocked`)
  }

  lines.push('')

  process.stderr.write(lines.join('\n'))
}

/** Get version from package.json (lazy, cached). */
// Version is passed from the caller or defaults to unknown
let _version = 'unknown'

/** Set the version string (called from mcp.ts on startup) */
export function setVersion(v: string): void {
  _version = v
}

function getVersion(): string {
  return _version
}
