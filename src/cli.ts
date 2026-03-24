#!/usr/bin/env node

import { parseArgs } from 'node:util'
import { audit } from './audit.js'
import { search } from './search.js'
import { score } from './scorer.js'
import { shouldUse } from './advisor.js'
import { guard } from './guard.js'
import { sweep } from './sweep.js'
import { auditTransitive } from './transitive.js'

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
    'help': { type: 'boolean', short: 'h', default: false },
  },
})

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
  audit <package>          Full audit report for a package
  search <keywords...>     Search npm for packages by keywords
  score <package>          Score a package 0-100
  should-use <intent...>   Recommend install vs write-from-scratch
  guard <package>          Pre-install check: verify, audit, allow/warn/block
  sweep [path]             Detect unused dependencies in a project
  audit-deep <package>     Deep transitive dependency tree audit

Options:
  --target-license <id>    Target project license (default: MIT)
  --threshold <n>          Score threshold for should-use/guard (default: 60)
  --limit <n>              Max results for search (default: 10)
  --json                   Output as JSON
  --mcp                    Start MCP server (JSON-RPC over stdio)
  --block                  Guard: escalate warnings to blocks
  --include-dev            Sweep: include devDependencies
  -h, --help               Show this help
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

async function main() {
  const targetLicense = values['target-license'] ?? 'MIT'
  const json = values.json ?? false
  const limit = parseInt(values.limit ?? '10', 10)
  const threshold = parseInt(values.threshold ?? '60', 10)

  switch (command) {
    case 'audit': {
      const name = positionals[1]
      if (!name) {
        console.error('Usage: depguard-cli audit <package>')
        process.exit(1)
      }
      const report = await audit(name, targetLicense)
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

    default:
      console.error(`Unknown command: ${command}. Use: audit, search, score, should-use, guard, sweep, audit-deep`)
      process.exit(1)
  }
}

main().catch(err => {
  console.error(err.message)
  process.exit(1)
})
} // end else --mcp
