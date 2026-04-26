#!/usr/bin/env node --import tsx
/**
 * Daily scan alert script — runs after daily-scan.ts.
 *
 * Diffs today's actionable alerts (severity = critical | high) against the
 * last-seen state, and posts only NEW findings to a single rolling GitHub
 * issue (creating it if no open one exists). Score-drops without new
 * advisories don't open a fresh issue per day — they roll up as comments.
 *
 * Triggered by .github/workflows/daily-scan.yml. Requires gh CLI (preinstalled
 * on GitHub-hosted runners) and GH_TOKEN with issues:write.
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { execSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const ROOT = join(__dirname, '..')

const SCAN_PATH = join(ROOT, 'docs/data/daily-scan.json')
const STATE_PATH = join(ROOT, '.github/state/daily-scan-state.json')
const REPO = process.env.GITHUB_REPOSITORY ?? 'mopanc/depguard'
const RANKING_URL = 'https://depguard.dev/#/ranking'

interface ScanAlert {
  package: string
  type: 'score-drop' | 'new-vulnerability' | 'compromised' | 'deprecated' | 'score-rise'
  severity: 'critical' | 'high' | 'medium' | 'info'
  message: string
  from?: number
  to?: number
}

interface DailyScan {
  date: string
  scannedAt: string
  totalPackages: number
  totalAlerts: number
  alerts: ScanAlert[]
}

interface AlertState {
  lastUpdated: string
  fingerprints: string[]
}

function fingerprint(a: ScanAlert): string {
  return `${a.package}|${a.type}|${a.severity}|${a.message}`
}

function loadScan(): DailyScan {
  if (!existsSync(SCAN_PATH)) {
    throw new Error(`No scan output at ${SCAN_PATH}. Did daily-scan.ts run first?`)
  }
  return JSON.parse(readFileSync(SCAN_PATH, 'utf-8'))
}

function loadState(): AlertState {
  if (!existsSync(STATE_PATH)) {
    return { lastUpdated: '', fingerprints: [] }
  }
  return JSON.parse(readFileSync(STATE_PATH, 'utf-8'))
}

function saveState(state: AlertState): void {
  mkdirSync(dirname(STATE_PATH), { recursive: true })
  writeFileSync(STATE_PATH, JSON.stringify(state, null, 2) + '\n')
}

function findRollingIssue(): number | null {
  // Rolling issues carry all 3 labels — prevents matching legacy daily-alert issues
  const out = execSync(
    `gh issue list --repo ${REPO} --label automated --label security --label rolling --state open --json number --jq '.[0].number // empty'`,
    { encoding: 'utf-8' },
  ).trim()
  return out ? parseInt(out, 10) : null
}

function ghIssueCreate(title: string, body: string): number {
  const out = execSync(
    `gh issue create --repo ${REPO} --title ${shellQuote(title)} --label "automated,security,rolling" --body-file -`,
    { encoding: 'utf-8', input: body },
  ).trim()
  const match = out.match(/\/issues\/(\d+)/)
  if (!match) throw new Error(`Couldn't parse issue number from gh output: ${out}`)
  return parseInt(match[1], 10)
}

function ghIssueComment(issueNumber: number, body: string): void {
  execSync(
    `gh issue comment ${issueNumber} --repo ${REPO} --body-file -`,
    { encoding: 'utf-8', input: body },
  )
}

/** Minimal POSIX shell quoting — escapes single quotes for the title argument. */
function shellQuote(s: string): string {
  return `'${s.replace(/'/g, `'\\''`)}'`
}

function renderRollingBody(scan: DailyScan, newAlerts: ScanAlert[]): string {
  return [
    `## Rolling Security Alerts`,
    ``,
    `Started ${scan.date}. New findings appear here as comments. Close this issue once everything is triaged — the next new alert will open a fresh one.`,
    ``,
    `### ${scan.date} — initial findings`,
    ``,
    ...newAlerts.map(a => `- **[${a.severity.toUpperCase()}]** ${a.message}`),
    ``,
    `---`,
    `Packages scanned: ${scan.totalPackages}`,
    `Full ranking: ${RANKING_URL}`,
    ``,
    `_Automated by depguard daily scan_`,
  ].join('\n')
}

function renderCommentBody(scan: DailyScan, newAlerts: ScanAlert[]): string {
  return [
    `### ${scan.date} — ${newAlerts.length} new finding${newAlerts.length === 1 ? '' : 's'}`,
    ``,
    ...newAlerts.map(a => `- **[${a.severity.toUpperCase()}]** ${a.message}`),
    ``,
    `Packages scanned: ${scan.totalPackages}. Full ranking: ${RANKING_URL}`,
  ].join('\n')
}

function main(): void {
  const scan = loadScan()
  const state = loadState()

  const actionable = scan.alerts.filter(a => a.severity === 'critical' || a.severity === 'high')
  const seen = new Set(state.fingerprints)
  const newOnes = actionable.filter(a => !seen.has(fingerprint(a)))

  // Update state to today's actionable set — alerts that have rolled off (e.g. CVE patched)
  // are forgotten; if they reappear later they will count as new again.
  saveState({
    lastUpdated: scan.date,
    fingerprints: actionable.map(fingerprint),
  })

  if (newOnes.length === 0) {
    console.log(`No new alerts (${actionable.length} known fingerprints). Nothing to post.`)
    return
  }

  console.log(`Posting ${newOnes.length} new alert(s)...`)
  const existing = findRollingIssue()
  if (existing) {
    ghIssueComment(existing, renderCommentBody(scan, newOnes))
    console.log(`Commented on rolling issue #${existing}.`)
  } else {
    const created = ghIssueCreate(
      `🚨 Rolling Security Alerts (since ${scan.date})`,
      renderRollingBody(scan, newOnes),
    )
    console.log(`Created rolling issue #${created}.`)
  }
}

main()
