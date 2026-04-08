/**
 * Netlify serverless function — live package audit API.
 * Imports the depguard audit engine directly (zero extra dependencies).
 *
 * Endpoint: GET /api/audit?package=express&version=latest
 * Returns: JSON with score, vulnerabilities, license, maintenance, etc.
 */

import { audit, scoreFromReport, lookupCompromised } from '../../dist/index.js'

// Simple in-memory rate limiting (per-function instance)
const rateMap = new Map<string, number[]>()
const RATE_LIMIT = 10 // requests per minute per IP
const RATE_WINDOW = 60_000 // 1 minute

function isRateLimited(ip: string): boolean {
  const now = Date.now()
  const timestamps = rateMap.get(ip) ?? []
  const recent = timestamps.filter(t => now - t < RATE_WINDOW)
  if (recent.length >= RATE_LIMIT) return true
  recent.push(now)
  rateMap.set(ip, recent)
  return false
}

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Content-Type': 'application/json',
  'Cache-Control': 'public, max-age=300', // 5 min cache
}

// Validate package name — alphanumeric, hyphens, dots, slashes (scoped)
const VALID_PKG = /^(@[a-z0-9\-_.]+\/)?[a-z0-9\-_.]+$/

export default async function handler(req: Request) {
  // CORS preflight
  if (req.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: CORS_HEADERS })
  }

  if (req.method !== 'GET') {
    return new Response(JSON.stringify({ error: 'Method not allowed' }), {
      status: 405, headers: CORS_HEADERS,
    })
  }

  const url = new URL(req.url)
  const pkgName = url.searchParams.get('package')?.trim().toLowerCase()
  const version = url.searchParams.get('version')?.trim() || undefined

  if (!pkgName) {
    return new Response(JSON.stringify({ error: 'Missing ?package= parameter' }), {
      status: 400, headers: CORS_HEADERS,
    })
  }

  if (!VALID_PKG.test(pkgName) || pkgName.length > 214) {
    return new Response(JSON.stringify({ error: 'Invalid package name' }), {
      status: 400, headers: CORS_HEADERS,
    })
  }

  // Rate limiting
  const ip = req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || 'unknown'
  if (isRateLimited(ip)) {
    return new Response(JSON.stringify({ error: 'Rate limited. Try again in a minute.' }), {
      status: 429, headers: CORS_HEADERS,
    })
  }

  try {
    // Check known compromised database first
    const compromised = lookupCompromised(pkgName)

    // Run full audit
    const report = await audit(pkgName, 'MIT', globalThis.fetch, version)

    // Score from report (returns a number 0-100)
    const totalScore = compromised ? 0 : scoreFromReport(report)

    // Scripts info
    const scripts = {
      hasInstallScripts: report.hasInstallScripts,
      risks: report.scriptAnalysis?.risks ?? [],
    }

    // Build response — only the fields the frontend needs
    const response = {
      name: report.name,
      version: report.version,
      score: totalScore,
      vulns: report.vulnerabilities,
      license: report.license,
      licenseCompatible: report.licenseCompatibility?.compatible ?? null,
      downloads: report.weeklyDownloads,
      deprecated: report.deprecated,
      lastPublish: report.lastPublish,
      maintainers: report.maintainerAnalysis ?? null,
      publication: report.publicationAnalysis ?? null,
      scripts,
      codeAnalysis: report.codeAnalysis
        ? { findings: report.codeAnalysis.findings.length, skipped: report.codeAnalysis.skipped }
        : null,
      compromised: compromised
        ? { compromised: compromised.compromised, severity: compromised.severity }
        : null,
      warnings: report.warnings,
    }

    return new Response(JSON.stringify(response), {
      status: 200, headers: CORS_HEADERS,
    })
  } catch {
    return new Response(JSON.stringify({ error: 'Audit failed. Try again.' }), {
      status: 500, headers: CORS_HEADERS,
    })
  }
}
