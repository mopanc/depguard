#!/usr/bin/env node --import tsx
/**
 * Daily security scan — audits the top 150 npm packages and generates
 * a ranked report with alerts for score changes and new threats.
 *
 * Run: npx tsx scripts/daily-scan.ts
 * Output: docs/data/daily-scan.json
 */

import { readFileSync, writeFileSync, existsSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { audit, DOWNLOADS_UNAVAILABLE_WARNING, PACKAGE_UNAVAILABLE_WARNING } from '../src/audit.js'
import { fetchBulkDownloads } from '../src/registry.js'
import { scoreFromReport } from '../src/scorer.js'
import { isVersionCompromised } from '../src/advisory-db.js'

const __dirname = dirname(fileURLToPath(import.meta.url))

// ─── Top 150 npm packages by weekly downloads ────────────────────────────────
// Curated from npmjs.com/browse/depended + cross-referenced with download stats.
// Updated periodically. Covers frameworks, utilities, tooling, and transitive deps.
const TOP_PACKAGES = [
  // Frameworks & runtimes
  'express', 'next', 'react', 'react-dom', 'vue', 'svelte', '@angular/core',
  'nuxt', 'gatsby', 'fastify', 'koa', 'hapi', 'nest', '@nestjs/core',
  // Build tools & bundlers
  'webpack', 'esbuild', 'vite', 'rollup', 'parcel', 'turbo', 'tsup',
  'typescript', 'babel-core', '@babel/core', '@babel/preset-env', 'swc',
  // Testing
  'jest', 'mocha', 'vitest', 'cypress', 'playwright', '@testing-library/react',
  'chai', 'sinon', 'nyc', 'c8',
  // Utilities
  'lodash', 'underscore', 'ramda', 'date-fns', 'moment', 'dayjs',
  'uuid', 'nanoid', 'chalk', 'colors', 'debug', 'dotenv',
  'commander', 'yargs', 'inquirer', 'ora', 'got', 'axios',
  'node-fetch', 'cross-fetch', 'isomorphic-fetch',
  'fs-extra', 'glob', 'minimatch', 'micromatch', 'chokidar',
  'rimraf', 'mkdirp', 'semver', 'minimist', 'yargs-parser',
  // Data & validation
  'zod', 'joi', 'yup', 'ajv', 'validator', 'class-validator',
  // HTTP & API
  'cors', 'helmet', 'body-parser', 'cookie-parser', 'morgan',
  'jsonwebtoken', 'bcrypt', 'bcryptjs', 'passport', 'express-session',
  // Database
  'mongoose', 'sequelize', 'prisma', '@prisma/client', 'typeorm',
  'knex', 'pg', 'mysql2', 'better-sqlite3', 'redis', 'ioredis',
  // State & data fetching
  'redux', '@reduxjs/toolkit', 'zustand', 'mobx', 'recoil',
  'swr', '@tanstack/react-query', 'graphql', 'apollo-server',
  // Styling
  'tailwindcss', 'postcss', 'autoprefixer', 'sass', 'less',
  'styled-components', '@emotion/react', '@emotion/styled',
  // Linting & formatting
  'eslint', 'prettier', 'stylelint',
  // Crypto & security
  'crypto-js', 'jose', 'node-forge',
  // File handling
  'multer', 'formidable', 'busboy', 'sharp', 'jimp',
  // Logging
  'winston', 'pino', 'bunyan', 'log4js',
  // Templating
  'ejs', 'handlebars', 'pug', 'nunjucks',
  // WebSocket & real-time
  'socket.io', 'ws', 'engine.io',
  // Process & system
  'pm2', 'nodemon', 'concurrently', 'cross-env', 'dotenv-expand',
  // Markdown & parsing
  'marked', 'markdown-it', 'remark', 'cheerio', 'jsdom',
  // Email
  'nodemailer',
  // Cloud & deployment
  'aws-sdk', '@aws-sdk/client-s3', 'firebase', '@google-cloud/storage',
  // Misc high-download
  'tslib', 'core-js', 'regenerator-runtime', 'source-map',
  'source-map-support', 'which', 'graceful-fs', 'readable-stream',
  'string-width', 'strip-ansi', 'ansi-styles', 'supports-color',
  'escape-string-regexp', 'color-convert', 'has-flag', 'wrap-ansi',
  'cliui', 'p-limit', 'p-locate', 'locate-path', 'path-exists',
  'lru-cache', 'ms', 'inherits', 'safe-buffer',
]

interface PackageResult {
  name: string
  version: string
  score: number
  prevScore: number | null
  rank: number
  prevRank: number | null
  vulns: { critical: number; high: number; moderate: number; low: number }
  license: string | null
  downloads: number
  /** true when today's download count was unavailable and the previous scan's was reused */
  downloadsStale?: boolean
  deprecated: boolean
  compromised: boolean
  codeFindings: number
  lastPublish: string | null
}

interface Alert {
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
  packages: PackageResult[]
  alerts: Alert[]
}

const DATA_DIR = join(__dirname, '..', 'docs', 'data')
const SCAN_FILE = join(DATA_DIR, 'daily-scan.json')
const CONCURRENCY = 5 // parallel audits
const SCORE_DROP_THRESHOLD = 10 // alert if score drops by this much
// Refuse to publish a scan where more than this share of packages has missing
// data. A stale ranking is better than a wrong one, and a failed run is visible.
const MAX_INCOMPLETE_RATIO = 0.05

function loadPreviousScan(): DailyScan | null {
  if (!existsSync(SCAN_FILE)) return null
  try {
    return JSON.parse(readFileSync(SCAN_FILE, 'utf-8'))
  } catch { return null }
}

type AuditOutcome =
  | { status: 'ok'; result: PackageResult }
  | { status: 'incomplete'; name: string; reason: string }

async function auditPackage(name: string, prev: PackageResult | undefined): Promise<AuditOutcome> {
  try {
    const report = await audit(name, 'MIT')
    if (report.warnings.includes(PACKAGE_UNAVAILABLE_WARNING)) {
      return { status: 'incomplete', name, reason: 'registry metadata unavailable' }
    }

    // Unknown downloads would score as 0 and tank the package's rank. Reuse the
    // previous scan's count (a day old, far closer to the truth than 0).
    let downloadsStale = false
    if (report.warnings.includes(DOWNLOADS_UNAVAILABLE_WARNING)) {
      if (!prev || prev.downloads <= 0) {
        return { status: 'incomplete', name, reason: 'download count unavailable' }
      }
      report.weeklyDownloads = prev.downloads
      downloadsStale = true
    }

    const compromised = isVersionCompromised(name, report.version)
    const totalScore = compromised ? 0 : scoreFromReport(report)

    return {
      status: 'ok',
      result: {
        name,
        version: report.version,
        score: totalScore,
        prevScore: null, // filled later
        rank: 0, // filled later
        prevRank: null, // filled later
        vulns: report.vulnerabilities,
        license: report.license,
        downloads: report.weeklyDownloads,
        ...(downloadsStale ? { downloadsStale } : {}),
        deprecated: report.deprecated,
        compromised,
        codeFindings: report.codeAnalysis?.findings.length ?? 0,
        lastPublish: report.lastPublish,
      },
    }
  } catch (e) {
    return { status: 'incomplete', name, reason: `audit failed: ${(e as Error).message}` }
  }
}

function generateAlerts(current: PackageResult[], previous: DailyScan | null): Alert[] {
  const alerts: Alert[] = []
  if (!previous) return alerts

  const prevMap = new Map(previous.packages.map(p => [p.name, p]))

  for (const pkg of current) {
    const prev = prevMap.get(pkg.name)

    // New compromise detected
    if (pkg.compromised && (!prev || !prev.compromised)) {
      alerts.push({
        package: pkg.name,
        type: 'compromised',
        severity: 'critical',
        message: `${pkg.name} is now flagged as a KNOWN COMPROMISED package`,
      })
      continue
    }

    if (!prev) continue

    // Score dropped significantly
    if (prev.score - pkg.score >= SCORE_DROP_THRESHOLD) {
      const severity = prev.score - pkg.score >= 30 ? 'critical'
        : prev.score - pkg.score >= 20 ? 'high' : 'medium'
      alerts.push({
        package: pkg.name,
        type: 'score-drop',
        severity,
        message: `${pkg.name} score dropped from ${prev.score} to ${pkg.score}`,
        from: prev.score,
        to: pkg.score,
      })
    }

    // Score rose significantly (recovery)
    if (pkg.score - prev.score >= SCORE_DROP_THRESHOLD) {
      alerts.push({
        package: pkg.name,
        type: 'score-rise',
        severity: 'info',
        message: `${pkg.name} score recovered from ${prev.score} to ${pkg.score}`,
        from: prev.score,
        to: pkg.score,
      })
    }

    // New vulnerability appeared
    const prevTotal = prev.vulns.critical + prev.vulns.high + prev.vulns.moderate + prev.vulns.low
    const currTotal = pkg.vulns.critical + pkg.vulns.high + pkg.vulns.moderate + pkg.vulns.low
    if (currTotal > prevTotal && (pkg.vulns.critical > prev.vulns.critical || pkg.vulns.high > prev.vulns.high)) {
      alerts.push({
        package: pkg.name,
        type: 'new-vulnerability',
        severity: pkg.vulns.critical > prev.vulns.critical ? 'critical' : 'high',
        message: `${pkg.name} has new vulnerabilities (${currTotal - prevTotal} new)`,
      })
    }

    // Newly deprecated
    if (pkg.deprecated && !prev.deprecated) {
      alerts.push({
        package: pkg.name,
        type: 'deprecated',
        severity: 'medium',
        message: `${pkg.name} is now deprecated`,
      })
    }
  }

  // Sort: critical first
  const severityOrder = { critical: 0, high: 1, medium: 2, info: 3 }
  alerts.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity])

  return alerts
}

async function runScan() {
  const startTime = Date.now()
  const previous = loadPreviousScan()
  const dedupedPackages = [...new Set(TOP_PACKAGES)]

  console.log(`\n[depguard daily scan] Auditing ${dedupedPackages.length} packages...`)
  if (previous) console.log(`  Previous scan: ${previous.date} (${previous.totalPackages} packages)`)

  // Prefetch download counts in bulk: one request per 128 unscoped packages
  // instead of one per package, which api.npmjs.org rate-limits on shared CI IPs.
  const downloads = await fetchBulkDownloads(dedupedPackages)
  console.log(`  Download counts: ${downloads.size}/${dedupedPackages.length} prefetched`)

  const prevMap = previous ? new Map(previous.packages.map(p => [p.name, p])) : new Map<string, PackageResult>()

  // Audit in batches for concurrency control
  const results: PackageResult[] = []
  const incomplete: { name: string; reason: string }[] = []
  for (let i = 0; i < dedupedPackages.length; i += CONCURRENCY) {
    const batch = dedupedPackages.slice(i, i + CONCURRENCY)
    const batchResults = await Promise.all(batch.map(name => auditPackage(name, prevMap.get(name))))
    for (const r of batchResults) {
      if (r.status === 'ok') results.push(r.result)
      else incomplete.push({ name: r.name, reason: r.reason })
    }
    const pct = Math.round(((i + batch.length) / dedupedPackages.length) * 100)
    process.stdout.write(`\r  Progress: ${pct}% (${results.length} audited)`)
  }
  console.log('')

  const stale = results.filter(r => r.downloadsStale)
  if (stale.length > 0) {
    console.log(`  Reused previous download count for ${stale.length}: ${stale.map(r => r.name).join(', ')}`)
  }
  if (incomplete.length > 0) {
    console.error(`  Incomplete data for ${incomplete.length} package(s):`)
    for (const { name, reason } of incomplete) console.error(`    - ${name}: ${reason}`)
  }
  if (incomplete.length / dedupedPackages.length > MAX_INCOMPLETE_RATIO) {
    throw new Error(
      `${incomplete.length}/${dedupedPackages.length} packages have incomplete data ` +
      `(limit ${MAX_INCOMPLETE_RATIO * 100}%). Not publishing this scan.`,
    )
  }

  // Sort by score (descending), then by downloads (descending) for ties
  results.sort((a, b) => b.score - a.score || b.downloads - a.downloads)

  // Assign ranks and previous data
  results.forEach((pkg, i) => {
    pkg.rank = i + 1
    const prev = prevMap.get(pkg.name)
    if (prev) {
      pkg.prevScore = prev.score
      pkg.prevRank = prev.rank
    }
  })

  // Generate alerts
  const alerts = generateAlerts(results, previous)

  const scan: DailyScan = {
    date: new Date().toISOString().split('T')[0],
    scannedAt: new Date().toISOString(),
    totalPackages: results.length,
    totalAlerts: alerts.length,
    packages: results,
    alerts,
  }

  writeFileSync(SCAN_FILE, JSON.stringify(scan, null, 2))

  const elapsed = ((Date.now() - startTime) / 1000).toFixed(1)
  console.log(`\n  Results: ${results.length} packages ranked`)
  console.log(`  Alerts: ${alerts.length}`)
  if (alerts.length > 0) {
    console.log('  ---')
    for (const a of alerts) {
      const icon = a.severity === 'critical' ? '!!!' : a.severity === 'high' ? '!!' : a.severity === 'medium' ? '!' : 'i'
      console.log(`  [${icon}] ${a.message}`)
    }
  }
  console.log(`  Time: ${elapsed}s`)
  console.log(`  Saved to: ${SCAN_FILE}\n`)
}

runScan().catch(e => { console.error('Scan failed:', e); process.exit(1) })
