#!/usr/bin/env node

/**
 * MCP (Model Context Protocol) server for depguard.
 *
 * Exposes depguard functions as MCP tools over stdio transport.
 * Protocol: JSON-RPC 2.0 over stdin/stdout (one JSON object per line).
 *
 * Zero dependencies — implements the MCP subset needed for tool serving.
 */

import { audit } from './audit.js'
import { search } from './search.js'
import { score } from './scorer.js'
import { shouldUse } from './advisor.js'
import { calculateSavings } from './tokens.js'

const SERVER_INFO = {
  name: 'depguard',
  version: '1.1.2',
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

          case 'depguard_should_use': {
            const limit = (args.limit as number) ?? 5
            const result = await shouldUse(args.intent as string, {
              threshold: (args.threshold as number) ?? 60,
              targetLicense: (args.targetLicense as string) ?? 'MIT',
            })
            return success(req.id, toolResult('depguard_should_use', result, limit))
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
