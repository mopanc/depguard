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
import { calculateSavings } from './tokens.js'

const SERVER_INFO = {
  name: 'depguard',
  version: '1.4.0',
}

const TOOLS = [
  {
    name: 'depguard_audit',
    description: 'Full security audit of an npm package: vulnerabilities, maintenance, license compatibility, dependencies, and install scripts.',
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
    name: 'depguard_search',
    description: 'Search npm for packages matching keywords, sorted by quality score.',
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
    name: 'depguard_score',
    description: 'Score an npm package 0-100 across security, maintenance, popularity, license, and dependencies.',
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
    name: 'depguard_audit_bulk',
    description: 'Audit multiple npm packages in a single call. Accepts a list of package names or a full dependencies object from package.json. Returns a consolidated report with vulnerability summary.',
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
  {
    name: 'depguard_audit_project',
    description: 'Audit all dependencies from a package.json file path. Reads the file, extracts all dependency names, and runs a bulk audit.',
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
    name: 'depguard_should_use',
    description: 'Given an intent (e.g. "date formatting"), search packages, audit top candidates, and recommend install vs write-from-scratch.',
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
  {
    name: 'depguard_guard',
    description: 'Pre-install guardian: verify a package exists on npm, check for AI hallucination and typosquatting, run quick security audit, and return allow/warn/block decision. Use this BEFORE installing any package.',
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
    name: 'depguard_verify',
    description: 'AI hallucination guard: verify if an npm package name actually exists on the registry. Also checks for possible typosquatting against 100+ popular packages using Levenshtein distance.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        name: { type: 'string', description: 'npm package name to verify' },
      },
      required: ['name'],
    },
  },
  {
    name: 'depguard_sweep',
    description: 'Dead dependency detection: scan a project for npm packages in package.json that are not actually imported or used in source code. Reports unused deps with estimated size savings.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        path: { type: 'string', description: 'Absolute path to project root (must contain package.json)' },
        includeDevDependencies: { type: 'boolean', description: 'Include devDependencies in scan (default: false)' },
      },
      required: ['path'],
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

function toolResult(toolName: string, content: unknown, argCount?: number): unknown {
  const responseJson = JSON.stringify(content, null, 2)
  const savings = calculateSavings(toolName, responseJson, argCount)
  const enriched = { ...(content as Record<string, unknown>), tokenSavings: savings }
  return {
    content: [{ type: 'text', text: JSON.stringify(enriched, null, 2) }],
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
