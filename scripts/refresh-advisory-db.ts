#!/usr/bin/env node --import tsx
/**
 * Refresh advisory-db.json from the GitHub Security Advisory (GHSA) database.
 *
 * Two sources, each paginated newest → oldest down to its last refresh:
 *   - type=malware                 malicious packages (typosquats, droppers)
 *   - type=reviewed + CWE-506      legitimate packages hijacked to ship
 *                                  malware (debug@4.4.2, @tanstack/*,
 *                                  eslint-config-prettier...). These are
 *                                  never typed "malware" by GitHub.
 *
 * Conversion rules live in ghsa-import.ts (unit-tested): every npm package
 * and range of an advisory is imported, withdrawn advisories and packages
 * only "indirectly exposed" through a malicious dependency are skipped.
 * Curated incident descriptions are never overwritten.
 *
 * When the stored importerVersion is older than IMPORTER_VERSION, the missing
 * history is read once (see IMPORTER_VERSION for what each step does).
 *
 * Run: npx tsx scripts/refresh-advisory-db.ts [--full]
 * Env:  GITHUB_TOKEN (recommended — bumps rate limit 60 → 5000/h)
 *       DEPGUARD_ADVISORY_DB_PATH (optional, defaults to src/data/advisory-db.json)
 */

import { readFileSync, writeFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { advisoryToIncidents, incidentId } from './ghsa-import.js'
import type { GhsaAdvisory, Incident } from './ghsa-import.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const DB_PATH = process.env.DEPGUARD_ADVISORY_DB_PATH ?? join(__dirname, '..', 'src', 'data', 'advisory-db.json')

/**
 * Bump when import rules change in a way that requires re-reading history.
 * v1 → anything: full rebuild of every source (v1 kept only the first package
 *      of each advisory, so every entry may need repair).
 * v2 → v3: one-time backfill of malware advisories published before the v2
 *      window, which began on 2025-11-17 (the original 180-day backfill).
 *      That cut left out Shai-Hulud and the chalk hijack (September 2025).
 */
const IMPORTER_VERSION = 3
const V2_MALWARE_WINDOW_START = '2025-11-17'

/**
 * GitHub's npm malware history (2022 onwards) is read in full on a rebuild:
 * before the v2 window it holds ~18k advisories, versus ~89k in the 11 months
 * after it, so completeness costs little and removes an arbitrary cut-off.
 */
const SOURCES = [
  { key: 'malware', label: 'malware', query: 'type=malware' },
  { key: 'reviewed-cwe506', label: 'hijacked (reviewed, CWE-506)', query: 'type=reviewed&cwes=506' },
] as const

interface CompromisedPackage {
  compromised: boolean
  severity: 'critical' | 'high' | 'low'
  incidents: Incident[]
}

interface AdvisoryDB {
  version: string
  lastRefresh?: string
  lastRefreshBySource?: Record<string, string>
  importerVersion?: number
  packages: Record<string, CompromisedPackage>
}

function loadDB(): AdvisoryDB {
  const raw = readFileSync(DB_PATH, 'utf-8')
  return JSON.parse(raw)
}

const SEV_RANK: Record<CompromisedPackage['severity'], number> = { low: 0, high: 1, critical: 2 }

function findImported(pkg: CompromisedPackage, adv: GhsaAdvisory): Incident | undefined {
  const id = incidentId(adv)
  return pkg.incidents.find(i => i.cve === id || i.cve === adv.ghsa_id || (adv.cve_id !== null && i.cve === adv.cve_id))
}

const REQUEST_TIMEOUT_MS = 30_000
const MAX_ATTEMPTS = 5

/**
 * One page of advisories. Every request has a timeout (a hung socket once
 * stalled a rebuild indefinitely) and transient failures are retried with
 * backoff: network errors, 5xx, and GitHub's rate limits (429, or 403 with
 * retry-after / an exhausted quota), honouring retry-after when present.
 */
async function fetchPage(url: string, token: string | undefined): Promise<{ items: GhsaAdvisory[]; next: string | null }> {
  const headers: Record<string, string> = {
    'Accept': 'application/vnd.github+json',
    'User-Agent': 'depguard-advisory-refresh',
  }
  if (token) headers['Authorization'] = `Bearer ${token}`

  for (let attempt = 1; ; attempt++) {
    let res: Response
    try {
      res = await fetch(url, { headers, signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) })
    } catch (e) {
      if (attempt >= MAX_ATTEMPTS) throw new Error(`GHSA fetch failed after ${attempt} attempts: ${(e as Error).message}`)
      await backoff(attempt, null)
      continue
    }

    const rateLimited = res.status === 429 ||
      (res.status === 403 && (res.headers.has('retry-after') || res.headers.get('x-ratelimit-remaining') === '0'))
    if ((rateLimited || res.status >= 500) && attempt < MAX_ATTEMPTS) {
      await backoff(attempt, res.headers.get('retry-after'))
      continue
    }
    if (!res.ok) {
      throw new Error(`GHSA fetch failed: ${res.status} ${res.statusText} — ${await res.text()}`)
    }

    const items = (await res.json()) as GhsaAdvisory[]
    const link = res.headers.get('link') ?? ''
    const nextMatch = link.match(/<([^>]+)>;\s*rel="next"/)
    return { items, next: nextMatch ? nextMatch[1] : null }
  }
}

async function backoff(attempt: number, retryAfter: string | null): Promise<void> {
  const seconds = Number(retryAfter)
  const ms = Number.isFinite(seconds) && seconds > 0 ? seconds * 1000 : 2000 * 2 ** (attempt - 1)
  console.log(`    retrying in ${Math.round(ms / 1000)}s (attempt ${attempt + 1}/${MAX_ATTEMPTS})`)
  await new Promise(resolve => setTimeout(resolve, Math.min(ms, 120_000)))
}

async function refresh(): Promise<void> {
  const startedAt = new Date()
  const db = loadDB()
  const storedVersion = db.importerVersion ?? 1
  const fullRebuild = process.argv.includes('--full') || storedVersion < 2
  const historyBackfill = !fullRebuild && storedVersion < 3

  console.log(`[refresh-advisory-db] current DB version: ${db.version}, packages: ${Object.keys(db.packages).length}`)
  if (fullRebuild) console.log(`  full rebuild: importer v${storedVersion} → v${IMPORTER_VERSION}, re-reading every source from the start`)
  if (historyBackfill) console.log(`  importer v${storedVersion} → v${IMPORTER_VERSION}: backfilling malware published before ${V2_MALWARE_WINDOW_START}`)

  const token = process.env.GITHUB_TOKEN
  if (!token) console.log('  [warn] no GITHUB_TOKEN — limited to 60 req/hour')

  const stats = { pages: 0, seen: 0, addedPkgs: 0, addedIncidents: 0, updatedRanges: 0, skippedDup: 0 }
  const skipped: Array<{ ghsa: string; reason: string; summary: string }> = []
  const sampleAdditions: Array<{ name: string; ghsa: string; range: string; summary: string }> = []
  const lastBySource = { ...(db.lastRefreshBySource ?? {}) }

  // Each pass reads one query, newest first. Incremental passes start at the
  // day of their source's last refresh; the v3 backfill reads what lies before
  // the old malware window. Overlaps are harmless: re-seen advisories dedupe.
  const passes: Array<{ key: string | null; label: string; query: string; filter: string }> = []
  for (const source of SOURCES) {
    // The malware source predates per-source state and used db.lastRefresh
    const since = fullRebuild
      ? null
      : lastBySource[source.key] ?? (source.key === 'malware' ? db.lastRefresh : undefined) ?? null
    // >= the day, not >: a refresh runs mid-day, so ">" would skip for good
    // every advisory published later that same day.
    passes.push({
      key: source.key,
      label: `${source.label}${since ? ` since ${since.split('T')[0]}` : ' (full history)'}`,
      query: source.query,
      filter: since ? `&published=%3E%3D${since.split('T')[0]}` : '',
    })
  }
  if (historyBackfill) {
    passes.push({
      key: null,
      label: `malware published before ${V2_MALWARE_WINDOW_START}`,
      query: 'type=malware',
      filter: `&published=%3C%3D${V2_MALWARE_WINDOW_START}`,
    })
  }

  for (const source of passes) {
    console.log(`  source: ${source.label}`)

    let url: string | null =
      `https://api.github.com/advisories?${source.query}&ecosystem=npm&sort=published&direction=desc&per_page=100${source.filter}`

    while (url) {
      stats.pages++
      if (stats.pages % 10 === 0) console.log(`    ...page ${stats.pages}, ${stats.seen} advisories seen`)
      const { items, next } = await fetchPage(url, token)
      if (items.length === 0) break

      for (const adv of items) {
        stats.seen++
        const { incidents, skipped: reason } = advisoryToIncidents(adv)
        if (reason) {
          if (reason !== 'withdrawn') skipped.push({ ghsa: adv.ghsa_id, reason, summary: adv.summary.slice(0, 80) })
          continue
        }

        for (const { name, incident, severity } of incidents) {
          const sample = { name, ghsa: adv.ghsa_id, range: incident.version, summary: incident.description.slice(0, 80) }
          const existing = db.packages[name]

          if (!existing) {
            db.packages[name] = { compromised: true, severity, incidents: [incident] }
            stats.addedPkgs++
            if (sampleAdditions.length < 5) sampleAdditions.push(sample)
            continue
          }

          const imported = findImported(existing, adv)
          if (imported) {
            // Repair ranges written by importer v1, which kept only the first
            // npm entry. Curated incidents are never touched.
            if (imported.origin === 'ghsa' && imported.version !== incident.version) {
              imported.version = incident.version
              stats.updatedRanges++
            } else {
              stats.skippedDup++
            }
            continue
          }

          existing.incidents.push(incident)
          if (SEV_RANK[severity] > SEV_RANK[existing.severity]) existing.severity = severity
          stats.addedIncidents++
          if (sampleAdditions.length < 5) sampleAdditions.push(sample)
        }
      }

      url = next
    }
    if (source.key) lastBySource[source.key] = startedAt.toISOString()
  }

  db.version = startedAt.toISOString().split('T')[0]
  db.lastRefresh = startedAt.toISOString()
  db.lastRefreshBySource = lastBySource
  db.importerVersion = IMPORTER_VERSION

  // Sort package keys for deterministic diffs in git.
  const sorted: Record<string, CompromisedPackage> = {}
  for (const k of Object.keys(db.packages).sort()) sorted[k] = db.packages[k]
  db.packages = sorted

  writeFileSync(DB_PATH, JSON.stringify(db, null, 2) + '\n')

  console.log(`  pages fetched: ${stats.pages}`)
  console.log(`  advisories seen: ${stats.seen}`)
  console.log(`  new packages added: ${stats.addedPkgs}`)
  console.log(`  new incidents on existing packages: ${stats.addedIncidents}`)
  console.log(`  incomplete ranges repaired: ${stats.updatedRanges}`)
  console.log(`  skipped (already imported): ${stats.skippedDup}`)
  console.log(`  DB now contains ${Object.keys(db.packages).length} packages`)
  if (skipped.length > 0) {
    console.log(`  skipped by false-positive rules (${skipped.length}), review occasionally:`)
    for (const s of skipped.slice(0, 20)) console.log(`    - ${s.ghsa} [${s.reason}] ${s.summary}`)
  }
  if (sampleAdditions.length > 0) {
    console.log('  sample of new entries (spot-check for false positives):')
    for (const s of sampleAdditions) {
      console.log(`    - ${s.name} (${s.ghsa}) versions=${s.range} — ${s.summary}`)
    }
  }
  console.log(`  wrote: ${DB_PATH}`)
}

refresh().catch(e => {
  console.error('refresh-advisory-db failed:', e)
  process.exit(1)
})
