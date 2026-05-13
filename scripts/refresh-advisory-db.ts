#!/usr/bin/env node --import tsx
/**
 * Refresh advisory-db.json from the GitHub Security Advisory (GHSA) database.
 *
 * Queries advisories with `type=malware` and `ecosystem=npm`, paginating from
 * newest to oldest until we reach the `lastRefresh` timestamp recorded in the
 * existing DB. New entries are merged into `src/data/advisory-db.json`,
 * never overwriting curated incident descriptions.
 *
 * Run: npx tsx scripts/refresh-advisory-db.ts
 * Env:  GITHUB_TOKEN (optional, but recommended — bumps rate limit 60 → 5000/h)
 * Output: src/data/advisory-db.json (updated in place)
 */

import { readFileSync, writeFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const DB_PATH = join(__dirname, '..', 'src', 'data', 'advisory-db.json')

// Backfill window for first run (when no lastRefresh is recorded).
const FIRST_RUN_BACKFILL_DAYS = 180

interface Incident {
  version: string
  type: 'supply-chain' | 'account-hijack' | 'maintainer-sabotage' | 'typosquat' | 'protestware'
  date: string
  cve: string | null
  description: string
  origin?: 'curated' | 'ghsa' | 'osv'
}

interface CompromisedPackage {
  compromised: boolean
  severity: 'critical' | 'high' | 'low'
  incidents: Incident[]
}

interface AdvisoryDB {
  version: string
  lastRefresh?: string
  packages: Record<string, CompromisedPackage>
}

interface GhsaAdvisory {
  ghsa_id: string
  cve_id: string | null
  summary: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'unknown'
  published_at: string
  withdrawn_at: string | null
  vulnerabilities: Array<{
    package: { ecosystem: string; name: string }
    vulnerable_version_range: string | null
  }>
}

function loadDB(): AdvisoryDB {
  const raw = readFileSync(DB_PATH, 'utf-8')
  return JSON.parse(raw)
}

function mapSeverity(s: GhsaAdvisory['severity']): CompromisedPackage['severity'] {
  if (s === 'critical') return 'critical'
  if (s === 'high') return 'high'
  return 'low'
}

const SEV_RANK: Record<CompromisedPackage['severity'], number> = { low: 0, high: 1, critical: 2 }

function normalizeVersionRange(range: string | null): string {
  if (!range || range.trim() === '' || range.trim() === '>= 0') return 'all'
  return range.trim()
}

function pickIncidentId(adv: GhsaAdvisory): string {
  return adv.cve_id ?? adv.ghsa_id
}

function alreadyImported(pkg: CompromisedPackage, adv: GhsaAdvisory): boolean {
  const id = pickIncidentId(adv)
  return pkg.incidents.some(i => i.cve === id || (i.cve === adv.ghsa_id) || (i.cve === adv.cve_id))
}

async function fetchPage(url: string, token: string | undefined): Promise<{ items: GhsaAdvisory[]; next: string | null }> {
  const headers: Record<string, string> = {
    'Accept': 'application/vnd.github+json',
    'User-Agent': 'depguard-advisory-refresh',
  }
  if (token) headers['Authorization'] = `Bearer ${token}`

  const res = await fetch(url, { headers })
  if (!res.ok) {
    throw new Error(`GHSA fetch failed: ${res.status} ${res.statusText} — ${await res.text()}`)
  }
  const items = (await res.json()) as GhsaAdvisory[]
  const link = res.headers.get('link') ?? ''
  const nextMatch = link.match(/<([^>]+)>;\s*rel="next"/)
  return { items, next: nextMatch ? nextMatch[1] : null }
}

async function refresh(): Promise<void> {
  const startedAt = new Date()
  const db = loadDB()
  const sinceISO = db.lastRefresh
    ?? new Date(Date.now() - FIRST_RUN_BACKFILL_DAYS * 86_400_000).toISOString()
  const sinceDay = sinceISO.split('T')[0]

  console.log(`[refresh-advisory-db] fetching GHSA malware advisories since ${sinceDay}`)
  console.log(`  current DB version: ${db.version}, packages: ${Object.keys(db.packages).length}`)

  const token = process.env.GITHUB_TOKEN
  if (!token) console.log('  [warn] no GITHUB_TOKEN — limited to 60 req/hour')

  let url: string | null =
    `https://api.github.com/advisories?type=malware&ecosystem=npm&sort=published&direction=desc&per_page=100&published=%3E${sinceDay}`

  let pages = 0
  let seen = 0
  let addedPkgs = 0
  let addedIncidents = 0
  let skippedDup = 0
  const sampleAdditions: Array<{ name: string; ghsa: string; range: string; summary: string }> = []

  while (url) {
    pages++
    const { items, next } = await fetchPage(url, token)
    if (items.length === 0) break

    for (const adv of items) {
      seen++
      if (adv.withdrawn_at) continue
      const v = adv.vulnerabilities.find(v => v.package.ecosystem === 'npm')
      if (!v) continue

      const name = v.package.name
      const incident: Incident = {
        version: normalizeVersionRange(v.vulnerable_version_range),
        type: 'supply-chain',
        date: adv.published_at.split('T')[0],
        cve: pickIncidentId(adv),
        description: adv.summary || `Malware advisory ${adv.ghsa_id}`,
        origin: 'ghsa',
      }

      const existing = db.packages[name]
      const sampleEntry = {
        name,
        ghsa: adv.ghsa_id,
        range: incident.version,
        summary: incident.description.slice(0, 80),
      }

      if (!existing) {
        db.packages[name] = {
          compromised: true,
          severity: mapSeverity(adv.severity),
          incidents: [incident],
        }
        addedPkgs++
        if (sampleAdditions.length < 5) sampleAdditions.push(sampleEntry)
        continue
      }

      if (alreadyImported(existing, adv)) {
        skippedDup++
        continue
      }

      existing.incidents.push(incident)
      const newSev = mapSeverity(adv.severity)
      if (SEV_RANK[newSev] > SEV_RANK[existing.severity]) existing.severity = newSev
      addedIncidents++
      if (sampleAdditions.length < 5) sampleAdditions.push(sampleEntry)
    }

    url = next
  }

  db.version = startedAt.toISOString().split('T')[0]
  db.lastRefresh = startedAt.toISOString()

  // Sort package keys for deterministic diffs in git.
  const sorted: Record<string, CompromisedPackage> = {}
  for (const k of Object.keys(db.packages).sort()) sorted[k] = db.packages[k]
  db.packages = sorted

  writeFileSync(DB_PATH, JSON.stringify(db, null, 2) + '\n')

  console.log(`  pages fetched: ${pages}`)
  console.log(`  advisories seen: ${seen}`)
  console.log(`  new packages added: ${addedPkgs}`)
  console.log(`  new incidents on existing packages: ${addedIncidents}`)
  console.log(`  skipped (already imported): ${skippedDup}`)
  console.log(`  DB now contains ${Object.keys(db.packages).length} packages`)
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
