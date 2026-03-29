#!/usr/bin/env node

/**
 * MCP (Model Context Protocol) server for depguard.
 *
 * Exposes depguard functions as MCP tools over stdio transport.
 * Protocol: JSON-RPC 2.0 over stdin/stdout (one JSON object per line).
 *
 * Zero dependencies — implements the MCP subset needed for tool serving.
 */

import { cleanupDiskCache } from './disk-cache.js'
import { audit } from './audit.js'
import { auditBulk, auditProject } from './bulk.js'
import { search } from './search.js'
import { score } from './scorer.js'
import { shouldUse } from './advisor.js'
import { guard, verify } from './guard.js'
import { sweep } from './sweep.js'
import { auditTransitive } from './transitive.js'
import { review } from './review.js'
import { scoreFromReport } from './scorer.js'
import { calculateSavings } from './tokens.js'
import { printStatsBanner, recordCall, setVersion } from './stats.js'

const SERVER_INFO = {
  name: 'depguard',
  version: '1.8.2',
}

const TOOLS = [
  // === BEFORE INSTALLING — call these before npm install ===
  {
    name: 'depguard_guard',
    description: 'MANDATORY: call this BEFORE running npm install, yarn add, or pnpm add — whether the user asked for the package or you decided to install it yourself. Verifies the package exists (blocks hallucinated names), checks for typosquatting, runs security audit, and returns allow/warn/block. If the result is "block" or "warn", do NOT install the package without informing the user.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        name: { type: 'string', description: 'npm package name to check before installing' },
        threshold: { type: 'number', description: 'Score threshold for allow decision (default: 60)' },
        targetLicense: { type: 'string', description: 'Project license for compatibility check (default: MIT)' },
      },
      required: ['name'],
    },
  },
  {
    name: 'depguard_should_use',
    description: 'When you need functionality (e.g. "RTSP streaming", "date formatting"), call this BEFORE choosing a package yourself. Checks if Node.js has a native solution first, then evaluates npm candidates and recommends install, caution, or write-from-scratch. Always prefer this over picking a package from your training data — it gives you up-to-date security and quality data.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        intent: { type: 'string', description: 'What you want to accomplish (e.g. "http client", "date formatting")' },
        threshold: { type: 'number', description: 'Score threshold for install recommendation (default: 60)' },
        targetLicense: { type: 'string', description: 'Project license for compatibility check (default: MIT)' },
      },
      required: ['intent'],
    },
  },
  // === AFTER CODE CHANGES — call these after modifying code ===
  {
    name: 'depguard_review',
    description: 'Call this AFTER making significant code changes or before the user commits. Scans source files for issues you may have introduced: console.logs left in production code, empty catch blocks, broken imports, TODOs without issue references, empty test files, orphan files. Fix the findings before reporting your work as done.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        path: { type: 'string', description: 'Absolute path to project root' },
        mode: { type: 'string', description: 'quick = per-file only (~500ms), full = cross-file analysis (~2-5s). Default: quick' },
      },
      required: ['path'],
    },
  },
  // === PROJECT HEALTH — call these when auditing a project ===
  {
    name: 'depguard_audit',
    description: 'Deep security audit of a single npm package. Downloads the tarball, scans source code for malware, checks vulnerabilities (npm + GitHub Advisory), analyzes install scripts, verifies license. Use when you need full details on a specific package. Pass a version to audit a specific installed version instead of latest.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        name: { type: 'string', description: 'npm package name' },
        version: { type: 'string', description: 'Specific version to audit (e.g. "4.17.1"). If omitted, audits the latest version.' },
        targetLicense: { type: 'string', description: 'Project license for compatibility check (default: MIT)' },
      },
      required: ['name'],
    },
  },
  {
    name: 'depguard_audit_project',
    description: 'Audit ALL dependencies in a project at once. Scans direct deps (full audit), transitive deps from lock file (vulnerability check), and the packageManager field. Pass the path to package.json and get a consolidated security report. Use this when the user asks to review project security or after cloning a new repo.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        path: { type: 'string', description: 'Absolute path to package.json file' },
        includeDevDependencies: { type: 'boolean', description: 'Include devDependencies in audit (default: false)' },
        targetLicense: { type: 'string', description: 'Project license for compatibility check (auto-detected from package.json if not set)' },
      },
      required: ['path'],
    },
  },
  {
    name: 'depguard_audit_deep',
    description: 'Audit the full transitive dependency tree of a package. Crawls all nested dependencies recursively and aggregates vulnerabilities across the entire graph. Use when you need to know the total attack surface, not just direct deps.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        name: { type: 'string', description: 'npm package name' },
        maxDepth: { type: 'number', description: 'Max recursion depth (default: 5, max: 10)' },
        targetLicense: { type: 'string', description: 'Project license for compatibility check (default: MIT)' },
      },
      required: ['name'],
    },
  },
  {
    name: 'depguard_sweep',
    description: 'Find unused npm packages in the project. Scans source files for imports and cross-references with package.json. Also detects phantom deps (installed but not declared). Call this after a coding session where you installed multiple packages — some may no longer be needed.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        path: { type: 'string', description: 'Absolute path to project root (must contain package.json)' },
        includeDevDependencies: { type: 'boolean', description: 'Include devDependencies in scan (default: false)' },
      },
      required: ['path'],
    },
  },
  // === QUICK LOOKUPS — lightweight tools for specific checks ===
  {
    name: 'depguard_score',
    description: 'Quick 0-100 quality score for a package. Faster than depguard_audit when you only need the score. Critical vulns cap at 30, high at 50.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        name: { type: 'string', description: 'npm package name' },
        targetLicense: { type: 'string', description: 'Project license for compatibility check (default: MIT)' },
      },
      required: ['name'],
    },
  },
  {
    name: 'depguard_verify',
    description: 'Quick check if a package name exists on npm + typosquatting detection. Faster than depguard_guard when you only need existence verification without a full audit.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        name: { type: 'string', description: 'npm package name to verify' },
      },
      required: ['name'],
    },
  },
  {
    name: 'depguard_search',
    description: 'Search npm for packages by keywords, sorted by depguard quality score. Use when you need to find packages but already know the keywords.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        keywords: { type: 'string', description: 'Search keywords' },
        limit: { type: 'number', description: 'Max results (default: 10)' },
        minScore: { type: 'number', description: 'Minimum score filter 0-100 (default: 0)' },
      },
      required: ['keywords'],
    },
  },
  {
    name: 'depguard_audit_bulk',
    description: 'Audit multiple packages in one call. Accepts an array of names or a dependencies object from package.json. Use depguard_audit_project instead if you have a package.json path.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        packages: {
          description: 'Array of package names OR a dependencies object from package.json (e.g. {"react": "^18.0.0", "express": "^4.0.0"})',
          oneOf: [
            { type: 'array', items: { type: 'string' } },
            { type: 'object' },
          ],
        },
        targetLicense: { type: 'string', description: 'Project license for compatibility check (default: MIT)' },
      },
      required: ['packages'],
    },
  },
]

interface JsonRpcRequest {
  jsonrpc: '2.0'
  id: number | string
  method: string
  params?: Record<string, unknown>
}

interface JsonRpcResponse {
  jsonrpc: '2.0'
  id: number | string | null
  result?: unknown
  error?: { code: number; message: string; data?: unknown }
}

function success(id: number | string, result: unknown): JsonRpcResponse {
  return { jsonrpc: '2.0', id, result }
}

function error(id: number | string | null, code: number, message: string): JsonRpcResponse {
  return { jsonrpc: '2.0', id, error: { code, message } }
}

/** Maximum response size in characters to avoid exceeding MCP client limits */
/** Keep responses under 50K to avoid MCP client limits (~12K tokens) */
const MAX_RESPONSE_CHARS = 50_000

function toolResult(toolName: string, content: unknown, argCount?: number): unknown {
  const responseJson = JSON.stringify(content, null, 2)
  const savings = calculateSavings(toolName, responseJson, argCount)

  // Record local stats (never sent anywhere)
  const contentObj = content as Record<string, unknown>
  recordCall(toolName, {
    tokensSaved: savings.saved,
    packagesAudited: toolName.includes('audit') ? (argCount ?? 1) : 0,
    threatsBlocked: toolName === 'depguard_guard' && contentObj.decision === 'block' ? 1 : 0,
    reviewFindings: toolName === 'depguard_review' ? (contentObj.totalFindings as number ?? 0) : 0,
  })

  const enriched = { ...(content as Record<string, unknown>), tokenSavings: savings }
  let resultJson = JSON.stringify(enriched, null, 2)

  // If response is too large, condense it to fit MCP client limits
  if (resultJson.length > MAX_RESPONSE_CHARS) {
    const condensed = condenseResult(enriched, toolName)
    resultJson = JSON.stringify(condensed, null, 2)
  }

  return {
    content: [{ type: 'text', text: resultJson }],
  }
}

/**
 * Condense a large result by removing verbose fields while keeping the summary.
 * This ensures bulk/project audits don't exceed MCP client limits.
 */
function condenseResult(data: Record<string, unknown>, toolName: string): Record<string, unknown> {
  // For bulk/project audits: keep summary, remove individual package details
  if (toolName === 'depguard_audit_bulk' || toolName === 'depguard_audit_project') {
    const results = data.results as Array<Record<string, unknown>> | undefined
    if (results && Array.isArray(results)) {
      const condensedResults = results.map(r => ({
        name: r.name,
        version: r.version,
        score: scoreFromReport(r as unknown as Parameters<typeof scoreFromReport>[0]),
        vulnerabilities: r.vulnerabilities ? {
          total: (r.vulnerabilities as Record<string, unknown>).total,
          critical: (r.vulnerabilities as Record<string, unknown>).critical,
          high: (r.vulnerabilities as Record<string, unknown>).high,
        } : undefined,
        deprecated: r.deprecated,
        hasInstallScripts: r.hasInstallScripts,
        license: r.license,
        warnings: (r.warnings as string[] | undefined)?.length ?? 0,
        codeAnalysisFindings: r.securityFindings ? (r.securityFindings as unknown[]).length : 0,
      }))
      return {
        ...data,
        results: condensedResults,
        _condensed: true,
        _note: 'Response was condensed to fit MCP limits. Use depguard_audit on individual packages for full details.',
      }
    }
  }

  // For sweep: keep summary, limit unused/maybeUnused lists
  if (toolName === 'depguard_sweep') {
    const unused = data.unused as unknown[] | undefined
    const maybeUnused = data.maybeUnused as unknown[] | undefined
    const phantomDeps = data.phantomDeps as unknown[] | undefined
    return {
      ...data,
      unused: unused?.slice(0, 20),
      maybeUnused: maybeUnused?.slice(0, 20),
      phantomDeps: phantomDeps?.slice(0, 20),
      _condensed: true,
      _note: `Response condensed. Showing first 20 of each category. Full counts: ${unused?.length ?? 0} unused, ${maybeUnused?.length ?? 0} maybe-unused, ${phantomDeps?.length ?? 0} phantom.`,
    }
  }

  // For review: limit findings list
  if (toolName === 'depguard_review') {
    const findings = data.findings as unknown[] | undefined
    return {
      ...data,
      findings: findings?.slice(0, 30),
      _condensed: true,
      _note: `Response condensed. Showing first 30 of ${findings?.length ?? 0} findings.`,
    }
  }

  // Generic: just truncate the JSON
  return {
    _condensed: true,
    _note: 'Response was too large and has been condensed.',
    summary: data.summary ?? data.total ?? 'See depguard-cli for full output',
    tokenSavings: data.tokenSavings,
  }
}

async function handleRequest(req: JsonRpcRequest): Promise<JsonRpcResponse> {
  switch (req.method) {
    case 'initialize':
      return success(req.id, {
        protocolVersion: '2024-11-05',
        capabilities: { tools: {} },
        serverInfo: SERVER_INFO,
      })

    case 'notifications/initialized':
      // Client acknowledgment, no response needed but we return anyway
      return success(req.id, {})

    case 'tools/list':
      return success(req.id, { tools: TOOLS })

    case 'tools/call': {
      const params = req.params as { name: string; arguments?: Record<string, unknown> } | undefined
      if (!params?.name) {
        return error(req.id, -32602, 'Missing tool name')
      }

      const args = params.arguments ?? {}

      try {
        switch (params.name) {
          case 'depguard_audit': {
            const result = await audit(
              args.name as string,
              (args.targetLicense as string) ?? 'MIT',
              undefined,
              args.version as string | undefined,
            )
            return success(req.id, toolResult('depguard_audit', result))
          }

          case 'depguard_search': {
            const result = await search(args.keywords as string, {
              limit: (args.limit as number) ?? 10,
              minScore: (args.minScore as number) ?? 0,
            })
            return success(req.id, toolResult('depguard_search', result))
          }

          case 'depguard_score': {
            const result = await score(args.name as string, {
              targetLicense: (args.targetLicense as string) ?? 'MIT',
            })
            return success(req.id, toolResult('depguard_score', result))
          }

          case 'depguard_audit_bulk': {
            const raw = args.packages
            // Accept either an array of names or a dependencies object
            const packageNames: string[] = Array.isArray(raw)
              ? raw as string[]
              : typeof raw === 'object' && raw !== null
                ? Object.keys(raw as Record<string, unknown>)
                : []

            if (packageNames.length === 0) {
              return error(req.id, -32602, 'packages must be a non-empty array or dependencies object')
            }

            const result = await auditBulk(packageNames, {
              targetLicense: (args.targetLicense as string) ?? 'MIT',
            })
            return success(req.id, toolResult('depguard_audit_bulk', result, packageNames.length))
          }

          case 'depguard_audit_project': {
            const filePath = args.path as string
            if (!filePath) {
              return error(req.id, -32602, 'path is required')
            }
            try {
              const result = await auditProject(filePath, {
                includeDevDependencies: (args.includeDevDependencies as boolean) ?? false,
                targetLicense: args.targetLicense as string | undefined,
              })
              return success(req.id, toolResult('depguard_audit_bulk', result, result.total))
            } catch (err) {
              const msg = err instanceof Error ? err.message : 'Failed to read package.json'
              return success(req.id, {
                content: [{ type: 'text', text: `Error: ${msg}` }],
                isError: true,
              })
            }
          }

          case 'depguard_should_use': {
            const limit = (args.limit as number) ?? 5
            const result = await shouldUse(args.intent as string, {
              threshold: (args.threshold as number) ?? 60,
              targetLicense: (args.targetLicense as string) ?? 'MIT',
            })
            return success(req.id, toolResult('depguard_should_use', result, limit))
          }

          case 'depguard_guard': {
            const name = args.name as string
            if (!name) return error(req.id, -32602, 'name is required')
            const result = await guard(name, {
              threshold: (args.threshold as number) ?? 60,
              targetLicense: (args.targetLicense as string) ?? 'MIT',
            })
            return success(req.id, toolResult('depguard_guard', result))
          }

          case 'depguard_verify': {
            const name = args.name as string
            if (!name) return error(req.id, -32602, 'name is required')
            const result = await verify(name)
            return success(req.id, toolResult('depguard_verify', result))
          }

          case 'depguard_audit_deep': {
            const name = args.name as string
            if (!name) return error(req.id, -32602, 'name is required')
            const result = await auditTransitive(name, {
              maxDepth: (args.maxDepth as number) ?? 5,
              targetLicense: (args.targetLicense as string) ?? 'MIT',
            })
            return success(req.id, toolResult('depguard_audit_deep', result, result.totalTransitiveDeps))
          }

          case 'depguard_review': {
            const filePath = args.path as string
            if (!filePath) return error(req.id, -32602, 'path is required')
            const result = await review(filePath, {
              mode: (args.mode as 'quick' | 'full') ?? 'quick',
            })
            return success(req.id, toolResult('depguard_review', result))
          }

          case 'depguard_sweep': {
            const filePath = args.path as string
            if (!filePath) return error(req.id, -32602, 'path is required')
            const result = await sweep(filePath, {
              includeDevDependencies: (args.includeDevDependencies as boolean) ?? false,
            })
            return success(req.id, toolResult('depguard_sweep', result))
          }

          default:
            return error(req.id, -32601, `Unknown tool: ${params.name}`)
        }
      } catch (err) {
        const message = err instanceof Error ? err.message : 'Unknown error'
        return success(req.id, {
          content: [{ type: 'text', text: `Error: ${message}` }],
          isError: true,
        })
      }
    }

    default:
      // Ignore unknown notifications (method starts with notifications/)
      if (req.method.startsWith('notifications/')) {
        return success(req.id, {})
      }
      return error(req.id, -32601, `Method not found: ${req.method}`)
  }
}

async function main() {
  // Show stats banner on startup (stderr only, never interferes with MCP protocol on stdout)
  setVersion(SERVER_INFO.version)
  printStatsBanner()

  // Clean up expired cache files on startup
  cleanupDiskCache()

  const { createInterface } = await import('node:readline')

  const rl = createInterface({ input: process.stdin })

  for await (const line of rl) {
    const trimmed = line.trim()
    if (!trimmed) continue

    try {
      const req = JSON.parse(trimmed) as JsonRpcRequest

      // Notifications have no id — don't send a response
      if (req.id === undefined || req.id === null) {
        // Still handle it (e.g. notifications/initialized) but don't respond
        await handleRequest({ ...req, id: 0 })
        continue
      }

      const response = await handleRequest(req)
      process.stdout.write(JSON.stringify(response) + '\n')
    } catch {
      const errResponse = error(null, -32700, 'Parse error')
      process.stdout.write(JSON.stringify(errResponse) + '\n')
    }
  }
}

main().catch(err => {
  process.stderr.write(`MCP server error: ${err.message}\n`)
  process.exit(1)
})
