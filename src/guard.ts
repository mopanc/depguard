/**
 * Pre-install guardian and AI hallucination guard.
 *
 * Verifies that npm packages exist, checks for typosquatting against popular
 * packages, and runs a quick audit to produce an allow/warn/block decision.
 *
 * Zero dependencies — uses only depguard internals.
 */

import type { GuardResult, GuardOptions, VerifyResult, VerifyOptions } from './types.js'
import { fetchPackage } from './registry.js'
import { audit } from './audit.js'
import { score } from './scorer.js'

/**
 * Top ~100 popular npm packages for typosquatting detection.
 * Curated from npm weekly download rankings.
 */
const POPULAR_PACKAGES: string[] = [
  // Web frameworks
  'express', 'fastify', 'koa', 'next', 'nuxt', 'hapi',
  // Frontend
  'react', 'vue', 'angular', 'svelte', 'solid-js', 'preact',
  'react-dom', 'react-router', 'react-query',
  // Utilities
  'lodash', 'underscore', 'ramda', 'immer', 'date-fns', 'dayjs', 'moment',
  'uuid', 'nanoid', 'debug', 'dotenv',
  // HTTP
  'axios', 'node-fetch', 'got', 'superagent', 'request',
  // CLI
  'commander', 'yargs', 'inquirer', 'ora', 'chalk', 'minimist', 'meow',
  // Build tools
  'webpack', 'rollup', 'esbuild', 'vite', 'parcel', 'turbo',
  'typescript', 'babel', 'swc', 'tsup', 'unbuild', 'tsx', 'ts-node',
  // Testing
  'jest', 'mocha', 'vitest', 'ava', 'tap', 'cypress', 'playwright',
  'puppeteer', 'supertest', 'nock', 'sinon', 'chai', 'nyc', 'c8',
  // Linting / formatting
  'eslint', 'prettier', 'stylelint',
  // Database
  'mongoose', 'sequelize', 'prisma', 'knex', 'pg', 'mysql', 'mysql2',
  'redis', 'ioredis', 'sqlite3', 'better-sqlite3', 'typeorm',
  // Validation
  'zod', 'joi', 'ajv', 'yup',
  // Auth / security
  'passport', 'jsonwebtoken', 'bcrypt', 'bcryptjs', 'helmet', 'cors',
  // Logging
  'winston', 'pino', 'bunyan', 'morgan',
  // File / process
  'rimraf', 'glob', 'globby', 'fs-extra', 'chokidar', 'sharp', 'jimp',
  'nodemon', 'pm2', 'concurrently',
  // Middleware
  'body-parser', 'cookie-parser', 'compression', 'multer',
  // Email / network
  'nodemailer', 'socket.io', 'ws',
  // State management
  'redux', 'mobx', 'zustand', 'jotai', 'recoil', 'rxjs',
  // CSS
  'tailwindcss', 'postcss', 'sass', 'less', 'autoprefixer',
  // GraphQL
  'graphql', 'apollo-server',
  // Misc
  'cheerio', 'marked', 'highlight.js', 'storybook', 'lerna', 'nx',
  'formik', 'swr',
]

/**
 * Compute Levenshtein edit distance between two strings.
 */
export function levenshtein(a: string, b: string): number {
  const m = a.length
  const n = b.length
  const dp: number[][] = Array.from({ length: m + 1 }, (_, i) =>
    Array.from({ length: n + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0)),
  )
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] = a[i - 1] === b[j - 1]
        ? dp[i - 1][j - 1]
        : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1])
    }
  }
  return dp[m][n]
}

/**
 * Find popular packages within edit distance of the given name.
 * Returns empty array if the name is itself in the popular list.
 */
export function findSimilarPackages(name: string, maxDistance = 2): string[] {
  const lower = name.toLowerCase()
  // If it's an exact match to a popular package, no typosquatting
  if (POPULAR_PACKAGES.includes(lower)) return []

  const similar: Array<{ name: string; distance: number }> = []
  for (const pkg of POPULAR_PACKAGES) {
    // Skip if length difference is too large (quick filter)
    if (Math.abs(pkg.length - lower.length) > maxDistance) continue
    const dist = levenshtein(lower, pkg)
    if (dist > 0 && dist <= maxDistance) {
      similar.push({ name: pkg, distance: dist })
    }
  }

  // Sort by distance (closest first)
  similar.sort((a, b) => a.distance - b.distance)
  return similar.map(s => s.name)
}

/**
 * Verify if an npm package exists and check for typosquatting.
 * Lightweight — no audit, just existence + name similarity check.
 */
export async function verify(
  packageName: string,
  options: VerifyOptions = {},
): Promise<VerifyResult> {
  const fetcher = options.fetcher ?? globalThis.fetch
  const similarTo = findSimilarPackages(packageName)
  const possibleTyposquat = similarTo.length > 0

  const pkg = await fetchPackage(packageName, fetcher)

  if (!pkg) {
    return {
      package: packageName,
      exists: false,
      possibleTyposquat,
      similarTo,
      description: null,
      version: null,
    }
  }

  return {
    package: packageName,
    exists: true,
    possibleTyposquat,
    similarTo,
    description: pkg.description ?? null,
    version: pkg['dist-tags']?.latest ?? null,
  }
}

/**
 * Pre-install guardian: verify existence, check typosquatting, run audit,
 * and return allow/warn/block decision.
 */
export async function guard(
  packageName: string,
  options: GuardOptions = {},
): Promise<GuardResult> {
  const threshold = options.threshold ?? 60
  const targetLicense = options.targetLicense ?? 'MIT'
  const blockMode = options.block ?? false
  const fetcher = options.fetcher ?? globalThis.fetch

  const reasons: string[] = []
  let decision: GuardResult['decision'] = 'allow'

  // Step 1: Verify existence (hallucination guard)
  const verifyResult = await verify(packageName, { fetcher })

  if (!verifyResult.exists) {
    reasons.push('Package does not exist on npm — possible AI hallucination')
    if (verifyResult.possibleTyposquat) {
      reasons.push(`Possible typosquat of: ${verifyResult.similarTo.join(', ')}`)
    }
    return {
      package: packageName,
      decision: 'block',
      exists: false,
      possibleTyposquat: verifyResult.possibleTyposquat,
      similarTo: verifyResult.similarTo,
      score: null,
      reasons,
      auditSummary: null,
    }
  }

  // Step 2: Typosquatting warning (package exists but name is suspiciously similar)
  if (verifyResult.possibleTyposquat) {
    reasons.push(`Possible typosquat of: ${verifyResult.similarTo.join(', ')}`)
    decision = 'warn'
  }

  // Step 3: Quick audit + score
  let scoreResult: number | null = null
  let auditSummary: GuardResult['auditSummary'] = null

  try {
    const [auditReport, scoreReport] = await Promise.all([
      audit(packageName, targetLicense, fetcher),
      score(packageName, { targetLicense, fetcher }),
    ])

    scoreResult = scoreReport.total
    auditSummary = {
      vulnerabilities: auditReport.vulnerabilities.total,
      critical: auditReport.vulnerabilities.critical,
      high: auditReport.vulnerabilities.high,
      deprecated: auditReport.deprecated,
      hasInstallScripts: auditReport.hasInstallScripts,
      scriptAnalysisSuspicious: auditReport.scriptAnalysis.suspicious,
      license: auditReport.license,
    }

    // Decision logic based on audit results
    if (auditReport.vulnerabilities.critical > 0) {
      reasons.push(`${auditReport.vulnerabilities.critical} critical vulnerabilities`)
      decision = 'warn'
    }
    if (auditReport.vulnerabilities.high > 0) {
      reasons.push(`${auditReport.vulnerabilities.high} high severity vulnerabilities`)
      decision = 'warn'
    }
    if (auditReport.deprecated) {
      reasons.push('Package is deprecated')
      decision = 'warn'
    }
    if (auditReport.scriptAnalysis.suspicious) {
      reasons.push('Suspicious install scripts detected')
      decision = 'warn'
    }

    // Score-based decision (can escalate to block)
    if (scoreResult < threshold - 20) {
      reasons.push(`Score ${scoreResult}/100 is critically below threshold ${threshold}`)
      decision = 'block'
    } else if (scoreResult < threshold) {
      reasons.push(`Score ${scoreResult}/100 is below threshold ${threshold}`)
      if (decision === 'allow') decision = 'warn'
    } else if (reasons.length === 0) {
      reasons.push(`Score ${scoreResult}/100 — safe to install`)
    }
  } catch {
    reasons.push('Could not complete audit — proceeding with caution')
    if (decision === 'allow') decision = 'warn'
  }

  // Escalate warn to block if --block mode is active
  if (blockMode && decision === 'warn') {
    decision = 'block'
  }

  return {
    package: packageName,
    decision,
    exists: true,
    possibleTyposquat: verifyResult.possibleTyposquat,
    similarTo: verifyResult.similarTo,
    score: scoreResult,
    reasons,
    auditSummary,
  }
}
