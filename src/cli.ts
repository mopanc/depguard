#!/usr/bin/env node

import { parseArgs } from 'node:util'
import { DEPGUARD_VERSION } from './version.js'
import { audit } from './audit.js'
import { search } from './search.js'
import { score } from './scorer.js'
import { shouldUse } from './advisor.js'
import { guard } from './guard.js'
import { sweep } from './sweep.js'
import { auditTransitive } from './transitive.js'
import { review } from './review.js'
import { generateSBOM } from './sbom.js'
import { remediate } from './remediate.js'
import { auditWorkspace } from './workspace-audit.js'
import type { AutoExecFinding, AutoExecSeverity, WorkspaceAuditResult } from './workspace-audit.js'
import { loadStats, recordCall } from './stats.js'
import { writeFileSync } from 'node:fs'

const { values, positionals } = parseArgs({
  allowPositionals: true,
  options: {
    'target-license': { type: 'string', default: 'MIT' },
    'threshold': { type: 'string', default: '60' },
    'limit': { type: 'string', default: '10' },
    'json': { type: 'boolean', default: false },
    'mcp': { type: 'boolean', default: false },
    'block': { type: 'boolean', default: false },
    'include-dev': { type: 'boolean', default: false },
    'full': { type: 'boolean', default: false },
    'include-vex': { type: 'boolean', default: false },
    'output': { type: 'string', short: 'o' },
    'help': { type: 'boolean', short: 'h', default: false },
    'version': { type: 'boolean', short: 'v', default: false },
  },
})

if (values.version) {
  console.log(DEPGUARD_VERSION)
  process.exit(0)
}

// Launch MCP server when --mcp flag is passed
if (values.mcp) {
  void import('./mcp.js')
} else {

const command = positionals[0]

if (values.help || !command) {
  console.log(`
depguard-cli — Audit npm packages for security, maintenance, and license compatibility

Usage:
  depguard-cli <command> <args> [options]

Commands:
  audit <package[@version]> Full audit report for a package (or specific version)
  search <keywords...>     Search npm for packages by keywords
  score <package>          Score a package 0-100
  should-use <intent...>   Recommend install vs write-from-scratch
  guard <package>          Pre-install check: verify, audit, allow/warn/block
  sweep [path]             Detect unused dependencies in a project
  audit-deep <package>     Deep transitive dependency tree audit
  review [path]            AI code review (detect debris left by AI agents)
  sbom <path/package.json> Generate CycloneDX 1.6 SBOM for a project
  remediate <path/package.json> Group vulnerabilities by direct dep to bump
  audit-workspace [path]   Pre-open audit: list files that auto-execute when the repo is opened
  stats                    Show local usage statistics

Options:
  --target-license <id>    Target project license (default: MIT)
  --threshold <n>          Score threshold for should-use/guard (default: 60)
  --limit <n>              Max results for search (default: 10)
  --json                   Output as JSON
  --mcp                    Start MCP server (JSON-RPC over stdio)
  --block                  Guard: escalate warnings to blocks
  --include-dev            Sweep/sbom: include devDependencies
  --include-vex            Sbom: include VEX vulnerability data (runs audit)
  -o, --output <file>      Sbom: write to file instead of stdout
  -h, --help               Show this help
  -v, --version            Show version
`)
  process.exit(0)
}

function output(data: unknown, json: boolean): void {
  if (json) {
    console.log(JSON.stringify(data, null, 2))
  } else if (typeof data === 'object' && data !== null) {
    printFormatted(data as Record<string, unknown>)
  }
}

function printFormatted(obj: Record<string, unknown>, indent = 0): void {
  const pad = '  '.repeat(indent)
  for (const [key, val] of Object.entries(obj)) {
    // Skip undefined and null values
    if (val === undefined || val === null) continue
    if (Array.isArray(val)) {
      if (val.length === 0) {
        console.log(`${pad}${key}: (none)`)
      } else if (typeof val[0] === 'object') {
        console.log(`${pad}${key}:`)
        for (const item of val) {
          printFormatted(item as Record<string, unknown>, indent + 1)
          console.log()
        }
      } else {
        console.log(`${pad}${key}: ${val.join(', ')}`)
      }
    } else if (typeof val === 'object' && val !== null) {
      console.log(`${pad}${key}:`)
      printFormatted(val as Record<string, unknown>, indent + 1)
    } else {
      console.log(`${pad}${key}: ${val}`)
    }
  }
}

function severityTag(s: AutoExecSeverity): string {
  return s === 'HIGH' ? '[HIGH]' : s === 'WARN' ? '[WARN]' : '[INFO]'
}

function printWorkspaceAudit(result: WorkspaceAuditResult): void {
  console.log('')
  console.log(`Workspace auto-exec surface audit — ${result.scannedPath}`)
  console.log(`  Surfaces checked: ${result.surfacesChecked.length}${result.surfacesChecked.length > 0 ? ` (${result.surfacesChecked.join(', ')})` : ''}`)
  console.log('')

  if (result.findings.length === 0) {
    if (result.surfacesChecked.length === 0) {
      console.log('  No auto-execution surfaces present in this repo.')
    } else {
      console.log('  No actionable findings. All surfaces above look benign.')
    }
    console.log('')
    console.log(`  Note: ${result.note}`)
    console.log('')
    return
  }

  for (const f of result.findings as AutoExecFinding[]) {
    console.log(`  ${severityTag(f.severity)} ${f.source} — ${f.file}`)
    console.log(`         Trigger: ${f.trigger}`)
    console.log(`         Command: ${f.command}`)
    for (const reason of f.reasons) {
      console.log(`         - ${reason}`)
    }
    console.log('')
  }

  const { high, warn, info } = result.summary
  console.log(`  Summary: ${high} HIGH, ${warn} WARN, ${info} INFO  (${result.findings.length} findings across ${result.surfacesChecked.length} surfaces)`)
  console.log('')
  console.log(`  Note: ${result.note}`)
  console.log('')
}

async function main() {
  const targetLicense = values['target-license'] ?? 'MIT'
  const json = values.json ?? false
  const limit = parseInt(values.limit ?? '10', 10)
  const threshold = parseInt(values.threshold ?? '60', 10)

  switch (command) {
    case 'audit': {
      const rawName = positionals[1]
      if (!rawName) {
        console.error('Usage: depguard-cli audit <package[@version]>')
        process.exit(1)
      }
      // Support name@version syntax (e.g. "express@4.17.1")
      const atIdx = rawName.lastIndexOf('@')
      const hasVersion = atIdx > 0 && !rawName.startsWith('@') || atIdx > rawName.indexOf('/')
      const name = hasVersion ? rawName.slice(0, atIdx) : rawName
      const version = hasVersion ? rawName.slice(atIdx + 1) : undefined
      const report = await audit(name, targetLicense, undefined, version)
      recordCall('depguard_audit', { packagesAudited: 1 })
      output(report, json)
      break
    }

    case 'search': {
      const keywords = positionals.slice(1).join(' ')
      if (!keywords) {
        console.error('Usage: depguard-cli search <keywords...>')
        process.exit(1)
      }
      const results = await search(keywords, { limit })
      if (json) {
        output(results, true)
      } else {
        for (const entry of results) {
          console.log(`  ${String(entry.score).padStart(3)}/100  ${entry.name}@${entry.version}`)
          if (entry.description) console.log(`         ${entry.description}`)
          console.log()
        }
      }
      break
    }

    case 'score': {
      const name = positionals[1]
      if (!name) {
        console.error('Usage: depguard-cli score <package>')
        process.exit(1)
      }
      const result = await score(name, { targetLicense })
      output(result, json)
      break
    }

    case 'should-use': {
      const intent = positionals.slice(1).join(' ')
      if (!intent) {
        console.error('Usage: depguard-cli should-use <intent...>')
        process.exit(1)
      }
      const rec = await shouldUse(intent, { threshold, targetLicense, limit: 5 })
      output(rec, json)
      break
    }

    case 'guard': {
      const name = positionals[1]
      if (!name) {
        console.error('Usage: depguard-cli guard <package>')
        process.exit(1)
      }
      const result = await guard(name, {
        threshold,
        targetLicense,
        block: values.block ?? false,
      })
      recordCall('depguard_guard', {
        packagesAudited: 1,
        threatsBlocked: result.decision === 'block' ? 1 : 0,
      })
      if (json) {
        output(result, true)
      } else {
        const icon = result.decision === 'allow' ? 'ALLOW' : result.decision === 'warn' ? 'WARN' : 'BLOCK'
        console.log(`\n[${icon}] ${result.package}`)
        if (!result.exists) console.log('  Package does NOT exist on npm!')
        if (result.possibleTyposquat) console.log(`  Possible typosquat of: ${result.similarTo.join(', ')}`)
        if (result.score !== null) console.log(`  Score: ${result.score}/100`)
        for (const reason of result.reasons) console.log(`  - ${reason}`)
        console.log()
      }
      if (result.decision === 'block') process.exit(1)
      break
    }

    case 'sweep': {
      const projectPath = positionals[1] ?? process.cwd()
      const result = await sweep(projectPath, {
        includeDevDependencies: values['include-dev'] ?? false,
      })
      if (json) {
        output(result, true)
      } else {
        console.log(`\nScanned ${result.scannedFiles} files, ${result.totalDependencies} dependencies\n`)
        if (result.unused.length > 0) {
          console.log(`Unused (${result.unused.length}):`)
          for (const dep of result.unused) {
            const size = dep.estimatedSizeKB ? ` (~${dep.estimatedSizeKB} KB)` : ''
            console.log(`  - ${dep.name}@${dep.version}${size}`)
          }
        }
        if (result.maybeUnused.length > 0) {
          console.log(`\nMaybe unused (${result.maybeUnused.length}):`)
          for (const dep of result.maybeUnused) {
            console.log(`  ? ${dep.name}@${dep.version}`)
          }
        }
        if (result.unused.length === 0 && result.maybeUnused.length === 0) {
          console.log('All dependencies appear to be in use.')
        }
        if (result.estimatedSavingsKB > 0) {
          console.log(`\nEstimated savings: ~${result.estimatedSavingsKB} KB`)
        }
        console.log(`\nNote: ${result.note}`)
        console.log()
      }
      break
    }

    case 'audit-deep': {
      const name = positionals[1]
      if (!name) {
        console.error('Usage: depguard-cli audit-deep <package>')
        process.exit(1)
      }
      const result = await auditTransitive(name, {
        maxDepth: 5,
        targetLicense,
      })
      if (json) {
        output(result, true)
      } else {
        console.log(`\nTransitive dependency tree for ${result.root}@${result.rootVersion}`)
        console.log(`  Depth: ${result.maxDepthReached}/${result.maxDepthLimit}`)
        console.log(`  Total packages: ${result.uniquePackages}`)
        console.log(`  Circular deps: ${result.circularDeps.length}`)
        const v = result.aggregateVulnerabilities
        if (v.total > 0) {
          console.log(`\n  Vulnerabilities: ${v.total} (critical: ${v.critical}, high: ${v.high}, moderate: ${v.moderate}, low: ${v.low})`)
          for (const pkg of v.byPackage) {
            console.log(`    - ${pkg.name} (depth ${pkg.depth}): ${pkg.total} vulns${pkg.critical > 0 ? ' [CRITICAL]' : ''}`)
          }
        } else {
          console.log(`\n  No vulnerabilities found in dependency tree`)
        }
        if (result.warnings.length > 0) {
          console.log(`\n  Warnings:`)
          for (const w of result.warnings) console.log(`    - ${w}`)
        }
        console.log()
      }
      break
    }

    case 'review': {
      const projectPath = positionals[1] ?? process.cwd()
      const mode = values.full ? 'full' as const : 'quick' as const
      const result = await review(projectPath, { mode })
      recordCall('depguard_review', { reviewFindings: result.totalFindings })
      if (json) {
        output(result, true)
      } else {
        console.log(`\nAI Code Review (${result.mode} mode) — ${result.filesAnalyzed} files`)
        console.log(`${result.summary}\n`)
        if (result.findings.length > 0) {
          for (const f of result.findings) {
            const icon = f.severity === 'error' ? 'ERROR' : f.severity === 'warning' ? 'WARN' : 'INFO'
            console.log(`  [${icon}] ${f.type} — ${f.file}:${f.line}`)
            console.log(`         ${f.code}`)
            console.log(`         ${f.suggestion}\n`)
          }
        }
        console.log(`Note: ${result.note}\n`)
      }
      break
    }

    case 'sbom': {
      const pkgPath = positionals[1]
      if (!pkgPath) {
        console.error('Usage: depguard-cli sbom <path-to-package.json> [--include-vex] [--include-dev] [--output <file>]')
        process.exit(1)
      }
      const bom = await generateSBOM(pkgPath, {
        includeVex: values['include-vex'] ?? false,
        includeDevDependencies: values['include-dev'] ?? false,
        targetLicense,
      })
      recordCall('depguard_sbom', { packagesAudited: bom.components?.length ?? 0 })
      const serialized = JSON.stringify(bom, null, 2)
      if (values.output) {
        writeFileSync(values.output, serialized + '\n')
        console.error(`Wrote CycloneDX 1.6 SBOM to ${values.output} (${bom.components?.length ?? 0} components)`)
      } else {
        process.stdout.write(serialized + '\n')
      }
      break
    }

    case 'remediate': {
      const pkgPath = positionals[1]
      if (!pkgPath) {
        console.error('Usage: depguard-cli remediate <path-to-package.json> [--include-dev] [--json]')
        process.exit(1)
      }
      const report = await remediate(pkgPath, {
        includeDevDependencies: values['include-dev'] ?? false,
        targetLicense,
      })
      recordCall('depguard_remediate', { packagesAudited: report.totalRemediations })
      if (json) {
        output(report, true)
      } else {
        const sev = report.summary
        console.log('')
        console.log(`Project: ${pkgPath}`)
        console.log(`Total remediations: ${report.totalRemediations}`)
        console.log(`Vulnerable transitives: ${report.totalVulnerableTransitives}`)
        console.log(`Severity: ${sev.critical} critical, ${sev.high} high, ${sev.moderate} moderate, ${sev.low} low`)
        if (report.unattributed.length > 0) {
          console.log(`Unattributed (parent chain unresolved): ${report.unattributed.length}`)
        }
        console.log('')
        for (const r of report.remediations) {
          const tag = r.isDirectVulnerable ? 'DIRECT' : 'TRANSITIVE'
          console.log(`[${tag}] bump ${r.directDep}  (action: ${r.action})`)
          console.log(`  Severity: ${r.severityCounts.critical}c ${r.severityCounts.high}h ${r.severityCounts.moderate}m ${r.severityCounts.low}l   Total vulns: ${r.totalVulns}`)
          if (r.transitives.length > 0) {
            console.log(`  Pulls in: ${r.transitives.map(t => `${t.name}@${t.version}`).join(', ')}`)
          }
          console.log('')
        }
        if (report.warnings.length > 0) {
          console.log('Warnings:')
          for (const w of report.warnings) console.log(`  - ${w}`)
        }
      }
      break
    }

    case 'workspace-audit':
    case 'audit-workspace': {
      if (command === 'workspace-audit') {
        process.stderr.write("depguard: subcommand 'workspace-audit' is deprecated and will be removed in a future major release. Use 'audit-workspace' instead.\n")
      }
      const repoPath = positionals[1] ?? process.cwd()
      const result = auditWorkspace(repoPath)
      recordCall('depguard_audit_workspace', {
        threatsBlocked: result.summary.high,
      })
      if (json) {
        output(result, true)
      } else {
        printWorkspaceAudit(result)
      }
      if (result.summary.high > 0) process.exit(2)
      if (result.summary.warn > 0) process.exit(1)
      break
    }

    case 'stats': {
      const stats = loadStats()
      if (json) {
        output(stats, true)
      } else {
        const formatNum = (n: number) => n >= 1_000_000 ? `${(n / 1_000_000).toFixed(1)}M` : n >= 1_000 ? `${(n / 1_000).toFixed(1)}K` : String(n)
        console.log('\n  depguard usage statistics (local only, never sent anywhere)\n')
        console.log(`  First used:          ${stats.firstUsed}`)
        console.log(`  Last used:           ${stats.lastUsed}`)
        console.log(`  Total calls:         ${formatNum(stats.totalCalls)}`)
        console.log(`  Tokens saved:        ${formatNum(stats.tokensEstimatedSaved)}`)
        console.log(`  Packages audited:    ${formatNum(stats.packagesAudited)}`)
        console.log(`  Threats blocked:     ${stats.threatsBlocked}`)
        console.log(`  Review findings:     ${stats.reviewFindings}`)
        if (Object.keys(stats.calls).length > 0) {
          console.log('\n  Calls by tool:')
          const sorted = Object.entries(stats.calls).sort((a, b) => b[1] - a[1])
          for (const [tool, count] of sorted) {
            console.log(`    ${tool.replace('depguard_', '')}: ${count}`)
          }
        }
        console.log('\n  Data stored in: ~/.depguard/stats.json')
        console.log('  Privacy: all data is local. Nothing is sent to any server.\n')
      }
      break
    }

    default:
      console.error(`Unknown command: ${command}. Use: audit, search, score, should-use, guard, sweep, audit-deep, review, sbom, remediate, stats`)
      process.exit(1)
  }
}

main().catch(err => {
  console.error(err.message)
  process.exit(1)
})
} // end else --mcp
