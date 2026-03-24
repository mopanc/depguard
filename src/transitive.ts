/**
 * Transitive dependency tree audit.
 *
 * BFS traversal through npm package dependencies with concurrency control,
 * circular dependency detection, and configurable depth limit.
 *
 * Reuses existing fetchPackage (with caching), fetchAdvisories, and
 * fetchGitHubAdvisories from registry.ts. Never throws on network errors.
 *
 * Zero dependencies — only Node.js built-ins + depguard internals.
 */

import type {
  FetchFn,
  NpmAdvisory,
  TransitiveAuditOptions,
  TransitiveAuditResult,
  TransitiveDepNode,
  VulnerabilitySummary,
} from './types.js'
import { fetchPackage, fetchAdvisories, fetchGitHubAdvisories, isGitHubRateLimited } from './registry.js'
import { mergeAdvisories } from './audit.js'

/** Maximum total packages to fetch (safety cap) */
const MAX_TOTAL_FETCHES = 200

/** Maximum allowed depth (hard limit) */
const MAX_DEPTH_LIMIT = 10

interface QueueItem {
  name: string
  depth: number
  requiredBy: string[]
}

function emptyVulnerabilities(): VulnerabilitySummary {
  return { total: 0, critical: 0, high: 0, moderate: 0, low: 0, advisories: [] }
}

function summarizeAdvisories(advisories: NpmAdvisory[]): VulnerabilitySummary {
  return {
    total: advisories.length,
    critical: advisories.filter(a => a.severity === 'critical').length,
    high: advisories.filter(a => a.severity === 'high').length,
    moderate: advisories.filter(a => a.severity === 'moderate').length,
    low: advisories.filter(a => a.severity === 'low').length,
    advisories,
  }
}

/**
 * Audit the full transitive dependency tree of an npm package.
 * BFS traversal with concurrency control, circular detection, and depth limiting.
 * Never throws — returns degraded results with warnings on network errors.
 */
export async function auditTransitive(
  name: string,
  options: TransitiveAuditOptions = {},
): Promise<TransitiveAuditResult> {
  const maxDepth = Math.min(options.maxDepth ?? 5, MAX_DEPTH_LIMIT)
  const concurrency = options.concurrency ?? 5
  const fetcher: FetchFn = options.fetcher ?? globalThis.fetch

  const visited = new Map<string, TransitiveDepNode>()
  const queue: QueueItem[] = []
  const circularDeps: Array<{ from: string; to: string }> = []
  const warnings: string[] = []
  let totalFetches = 0

  // Step 1: Fetch root package
  const rootPkg = await fetchPackage(name, fetcher)
  if (!rootPkg) {
    return {
      root: name,
      rootVersion: 'unknown',
      maxDepthReached: 0,
      maxDepthLimit: maxDepth,
      totalTransitiveDeps: 0,
      uniquePackages: 0,
      nodes: [],
      circularDeps: [],
      aggregateVulnerabilities: { total: 0, critical: 0, high: 0, moderate: 0, low: 0, byPackage: [] },
      warnings: [`Could not fetch root package "${name}" from npm registry`],
    }
  }

  const rootVersion = rootPkg['dist-tags']?.latest ?? Object.keys(rootPkg.versions).pop() ?? 'unknown'
  const rootVersionData = rootPkg.versions[rootVersion]
  const rootDeps = rootVersionData?.dependencies ?? {}

  // Seed queue with root's direct dependencies
  for (const depName of Object.keys(rootDeps)) {
    queue.push({ name: depName, depth: 1, requiredBy: [name] })
  }

  // Step 2: BFS with concurrency control
  while (queue.length > 0) {
    // Safety cap
    if (totalFetches >= MAX_TOTAL_FETCHES) {
      warnings.push(`Reached maximum fetch limit (${MAX_TOTAL_FETCHES}). Some transitive dependencies may not be audited.`)
      break
    }

    // Dequeue a batch
    const batch = queue.splice(0, concurrency)

    // Filter already-visited (but record requiredBy edges)
    const toFetch: QueueItem[] = []
    for (const item of batch) {
      if (visited.has(item.name)) {
        const existing = visited.get(item.name) as TransitiveDepNode
        for (const req of item.requiredBy) {
          if (!existing.requiredBy.includes(req)) {
            existing.requiredBy.push(req)
          }
        }
        circularDeps.push({ from: item.requiredBy[0], to: item.name })
        existing.circular = true
        continue
      }
      toFetch.push(item)
    }

    if (toFetch.length === 0) continue

    // Fetch all in parallel
    const results = await Promise.all(
      toFetch.map(async (item) => {
        totalFetches++
        try {
          const pkg = await fetchPackage(item.name, fetcher)
          return { item, pkg }
        } catch {
          warnings.push(`Could not fetch "${item.name}"`)
          return { item, pkg: null }
        }
      }),
    )

    for (const { item, pkg } of results) {
      if (!pkg) {
        // Record as node with no data
        visited.set(item.name, {
          name: item.name,
          version: 'unknown',
          depth: item.depth,
          requiredBy: [...item.requiredBy],
          dependencies: [],
          vulnerabilities: emptyVulnerabilities(),
          license: null,
          deprecated: false,
          circular: false,
        })
        continue
      }

      const version = pkg['dist-tags']?.latest ?? Object.keys(pkg.versions).pop() ?? 'unknown'
      const versionData = pkg.versions[version]
      const deps = versionData?.dependencies ?? {}

      // Fetch advisories for this package
      let advisories: NpmAdvisory[] = []
      try {
        const [npmAdv, ghAdv] = await Promise.all([
          fetchAdvisories(item.name, version, fetcher).catch(() => [] as NpmAdvisory[]),
          fetchGitHubAdvisories(item.name, fetcher).catch(() => []),
        ])
        advisories = mergeAdvisories(npmAdv, ghAdv, version)
      } catch {
        warnings.push(`Could not fetch advisories for "${item.name}"`)
      }

      const node: TransitiveDepNode = {
        name: item.name,
        version,
        depth: item.depth,
        requiredBy: [...item.requiredBy],
        dependencies: Object.keys(deps),
        vulnerabilities: summarizeAdvisories(advisories),
        license: versionData?.license ?? pkg.license ?? null,
        deprecated: !!versionData?.deprecated,
        circular: false,
      }
      visited.set(item.name, node)

      // Enqueue children if within depth limit
      if (item.depth < maxDepth) {
        for (const childName of Object.keys(deps)) {
          queue.push({ name: childName, depth: item.depth + 1, requiredBy: [item.name] })
        }
      }
    }
  }

  // Step 3: Aggregate results
  const nodes = Array.from(visited.values())
    .sort((a, b) => a.depth - b.depth || a.name.localeCompare(b.name))

  const maxDepthReached = nodes.reduce((max, n) => Math.max(max, n.depth), 0)

  // Aggregate vulnerabilities
  let totalVulns = 0
  let totalCritical = 0
  let totalHigh = 0
  let totalModerate = 0
  let totalLow = 0
  const byPackage: TransitiveAuditResult['aggregateVulnerabilities']['byPackage'] = []

  for (const node of nodes) {
    const v = node.vulnerabilities
    totalVulns += v.total
    totalCritical += v.critical
    totalHigh += v.high
    totalModerate += v.moderate
    totalLow += v.low

    if (v.total > 0) {
      byPackage.push({
        name: node.name,
        depth: node.depth,
        total: v.total,
        critical: v.critical,
        high: v.high,
      })
    }
  }

  // Warn if GitHub rate limit was exhausted during the crawl
  if (isGitHubRateLimited()) {
    warnings.push('GitHub Advisory API rate limit reached. Some packages were audited with npm advisories only (GitHub advisories skipped). Set GITHUB_TOKEN env var for 5,000 requests/hour instead of 60.')
  }

  return {
    root: name,
    rootVersion,
    maxDepthReached,
    maxDepthLimit: maxDepth,
    totalTransitiveDeps: nodes.length,
    uniquePackages: visited.size,
    nodes,
    circularDeps,
    aggregateVulnerabilities: {
      total: totalVulns,
      critical: totalCritical,
      high: totalHigh,
      moderate: totalModerate,
      low: totalLow,
      byPackage,
    },
    warnings,
  }
}
