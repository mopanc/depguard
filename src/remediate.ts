/**
 * Remediation planner — turns the flat list of vulnerabilities from
 * auditProject() into an actionable plan grouped by the direct
 * dependency a developer needs to bump.
 *
 * This is the read-only L1 layer of the remediate roadmap. It does not
 * write to the filesystem, propose codemods, or invoke npm. Output is a
 * pure JSON report that an agent or human can act on.
 *
 * Phase 1b will add a constraint solver that picks the minimum set of
 * direct-dep bumps to resolve the most criticals; until then, sorting
 * is by aggregate severity weight per direct dep.
 */

import type { NpmAdvisory } from './types.js'
import { auditProject } from './bulk.js'
import type { ProjectAuditOptions, TransitiveVulnerability } from './bulk.js'

export interface RemediationItem {
  /** Direct dep declared in package.json. Bumping this is the proposed fix. */
  directDep: string
  /** True if the direct dep itself has a CVE (vs only its transitives). */
  isDirectVulnerable: boolean
  /** Advisories reported against the direct dep itself. Empty if it is only a parent of vulnerable transitives. */
  directAdvisories: NpmAdvisory[]
  /** Vulnerable transitives this direct dep pulls into the install tree. */
  transitives: TransitiveVulnerability[]
  /** Counts aggregated across the direct dep AND all its vulnerable transitives. */
  severityCounts: { critical: number; high: number; moderate: number; low: number }
  /** Sum of severityCounts. */
  totalVulns: number
  /**
   * Suggested action.
   * - `bump`: at least one of the affected advisories has a patched range.
   * - `no-fix-available`: every affected advisory has no patched range.
   * - `investigate`: mixed or unknown; user must read the per-advisory data.
   */
  action: 'bump' | 'no-fix-available' | 'investigate'
}

export interface RemediateReport {
  projectPath: string
  /** Aggregate severity counts across the whole project (from auditProject.summary). */
  summary: { critical: number; high: number; moderate: number; low: number }
  /** Number of distinct direct deps that, if bumped, would resolve at least one vuln. */
  totalRemediations: number
  /** Number of vulnerable transitive packages found in the lock file. */
  totalVulnerableTransitives: number
  /** Sorted by severity weight, descending. Most impactful fix first. */
  remediations: RemediationItem[]
  /**
   * Transitives whose parent chain could not be resolved. Happens when
   * the lockfile format is not yet supported by getDependencyParents
   * (only npm v2/v3 is supported in this version) or when the file is
   * malformed. These still appear in the report so they are not lost,
   * but with no actionable direct-dep target.
   */
  unattributed: TransitiveVulnerability[]
  warnings: string[]
}

const SEVERITY_WEIGHT = { critical: 100, high: 10, moderate: 1, low: 0.1 } as const

function severityScore(counts: RemediationItem['severityCounts']): number {
  return counts.critical * SEVERITY_WEIGHT.critical
    + counts.high * SEVERITY_WEIGHT.high
    + counts.moderate * SEVERITY_WEIGHT.moderate
    + counts.low * SEVERITY_WEIGHT.low
}

function actionFor(advisories: NpmAdvisory[]): RemediationItem['action'] {
  if (advisories.length === 0) return 'bump'
  let withFix = 0
  let withoutFix = 0
  for (const a of advisories) {
    if (a.patched_versions && a.patched_versions.trim() !== '' && a.patched_versions !== '<0.0.0') {
      withFix++
    } else {
      withoutFix++
    }
  }
  if (withFix === 0) return 'no-fix-available'
  if (withoutFix === 0) return 'bump'
  return 'investigate'
}

/**
 * Generate a remediation plan for a project. Reads package.json and
 * the lockfile, runs auditProject under the hood, and returns a plan
 * grouped by the direct dep that should be bumped.
 *
 * Read-only. Does not mutate project files or run npm.
 */
export async function remediate(
  packageJsonPath: string,
  options: ProjectAuditOptions = {},
): Promise<RemediateReport> {
  const audit = await auditProject(packageJsonPath, options)

  const byDep = new Map<string, RemediationItem>()
  const unattributed: TransitiveVulnerability[] = []

  // Step 1. Direct deps that are themselves vulnerable seed remediations.
  for (const direct of audit.results) {
    const v = direct.vulnerabilities
    if (v.total === 0) continue
    byDep.set(direct.name, {
      directDep: direct.name,
      isDirectVulnerable: true,
      directAdvisories: v.advisories,
      transitives: [],
      severityCounts: { critical: v.critical, high: v.high, moderate: v.moderate, low: v.low },
      totalVulns: v.total,
      action: actionFor(v.advisories),
    })
  }

  // Step 2. Distribute each vulnerable transitive to every direct dep
  // that pulls it in. A transitive shared by two direct deps appears
  // under both (the developer can choose which to bump first).
  for (const t of audit.transitiveSummary?.details ?? []) {
    if (t.pulledInBy.length === 0) {
      unattributed.push(t)
      continue
    }
    for (const parent of t.pulledInBy) {
      let item = byDep.get(parent)
      if (!item) {
        item = {
          directDep: parent,
          isDirectVulnerable: false,
          directAdvisories: [],
          transitives: [],
          severityCounts: { critical: 0, high: 0, moderate: 0, low: 0 },
          totalVulns: 0,
          action: 'bump',
        }
        byDep.set(parent, item)
      }
      item.transitives.push(t)
      for (const adv of t.advisories) {
        if (adv.severity === 'critical') item.severityCounts.critical++
        else if (adv.severity === 'high') item.severityCounts.high++
        else if (adv.severity === 'moderate') item.severityCounts.moderate++
        else if (adv.severity === 'low') item.severityCounts.low++
        item.totalVulns++
      }
      // Recompute action over the union of all advisories now attached.
      const combined = [...item.directAdvisories, ...item.transitives.flatMap(x => x.advisories)]
      item.action = actionFor(combined)
    }
  }

  const remediations = [...byDep.values()].sort(
    (a, b) => severityScore(b.severityCounts) - severityScore(a.severityCounts),
  )

  return {
    projectPath: packageJsonPath,
    summary: audit.summary,
    totalRemediations: remediations.length,
    totalVulnerableTransitives: audit.transitiveSummary?.vulnerable ?? 0,
    remediations,
    unattributed,
    warnings: audit.warnings ?? [],
  }
}
