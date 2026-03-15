#!/usr/bin/env node

import { parseArgs } from 'node:util'
import { audit } from './audit.js'
import { search } from './search.js'
import { score } from './scorer.js'
import { shouldUse } from './advisor.js'

const { values, positionals } = parseArgs({
  allowPositionals: true,
  options: {
    'target-license': { type: 'string', default: 'MIT' },
    'threshold': { type: 'string', default: '60' },
    'limit': { type: 'string', default: '10' },
    'json': { type: 'boolean', default: false },
    'help': { type: 'boolean', short: 'h', default: false },
  },
})

const command = positionals[0]

if (values.help || !command) {
  console.log(`
depguard — Audit npm packages for security, maintenance, and license compatibility

Usage:
  depguard <command> <args> [options]

Commands:
  audit <package>          Full audit report for a package
  search <keywords...>     Search npm for packages by keywords
  score <package>          Score a package 0-100
  should-use <intent...>   Recommend install vs write-from-scratch

Options:
  --target-license <id>    Target project license (default: MIT)
  --threshold <n>          Score threshold for should-use (default: 60)
  --limit <n>              Max results for search (default: 10)
  --json                   Output as JSON
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
        console.error('Usage: depguard audit <package>')
        process.exit(1)
      }
      const report = await audit(name, targetLicense)
      output(report, json)
      break
    }

    case 'search': {
      const keywords = positionals.slice(1).join(' ')
      if (!keywords) {
        console.error('Usage: depguard search <keywords...>')
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
        console.error('Usage: depguard score <package>')
        process.exit(1)
      }
      const result = await score(name, { targetLicense })
      output(result, json)
      break
    }

    case 'should-use': {
      const intent = positionals.slice(1).join(' ')
      if (!intent) {
        console.error('Usage: depguard should-use <intent...>')
        process.exit(1)
      }
      const rec = await shouldUse(intent, { threshold, targetLicense, limit: 5 })
      output(rec, json)
      break
    }

    default:
      console.error(`Unknown command: ${command}. Use: audit, search, score, should-use`)
      process.exit(1)
  }
}

main().catch(err => {
  console.error(err.message)
  process.exit(1)
})
