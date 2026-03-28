/**
 * AI Code Review — detects debris left by AI coding agents.
 *
 * Scans local project files for common quality issues:
 * console.logs in production, empty catch blocks, TODOs without issues,
 * broken imports, empty tests, and orphan files.
 *
 * Designed as an AI-to-AI tool: the MCP response tells the coding agent
 * what to fix, with structured findings it can act on immediately.
 *
 * Zero dependencies — only Node.js built-ins + depguard internals.
 * Zero shell access — no git, no subprocesses, no new security alerts.
 */

import { readFileSync, existsSync } from 'node:fs'
import { join, dirname, basename, resolve, relative } from 'node:path'
import type { ReviewFinding, ReviewResult, ReviewOptions } from './types.js'
import { collectSourceFiles } from './sweep.js'

const REVIEW_NOTE = 'These are recommendations from static analysis. Review each finding before acting.'

/** Patterns that indicate a file is a test file */
const TEST_PATTERNS = ['.test.', '.spec.', '__tests__', '/test/', '/tests/', '/spec/']

/** Patterns that indicate a file is a logger module */
const LOGGER_PATTERNS = ['logger', 'logging', 'log-utils', 'debug-utils']

/** Entry point filenames that should not be flagged as orphans */
const ENTRY_POINT_PATTERNS = ['index.', 'main.', 'app.', 'cli.', 'server.', 'worker.', 'setup.']

/** Extensions to try when resolving relative imports */
const RESOLVE_EXTENSIONS = ['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs']

/**
 * TypeScript ESM pattern: imports use .js extension but actual files are .ts
 * e.g., `import from './types.js'` → real file is `./types.ts`
 */
const JS_TO_TS_MAP: Record<string, string> = {
  '.js': '.ts',
  '.jsx': '.tsx',
  '.mjs': '.mts',
  '.cjs': '.cts',
}

// ========================
// Per-file detectors (quick mode)
// ========================

function isTestFile(filePath: string): boolean {
  const lower = filePath.toLowerCase()
  return TEST_PATTERNS.some(p => lower.includes(p))
}

function isLoggerFile(filePath: string): boolean {
  const name = basename(filePath).toLowerCase()
  return LOGGER_PATTERNS.some(p => name.includes(p))
}

function isEntryPoint(filePath: string): boolean {
  const name = basename(filePath).toLowerCase()
  return ENTRY_POINT_PATTERNS.some(p => name.startsWith(p))
}

function isConfigFile(filePath: string): boolean {
  const name = basename(filePath).toLowerCase()
  return name.endsWith('.config.ts') || name.endsWith('.config.js') ||
    name.endsWith('.config.mjs') || name.endsWith('.config.cjs') ||
    name.startsWith('.') || name === 'tsconfig.json' ||
    name.endsWith('.d.ts')
}

/**
 * Detect console.log/debug/warn/info in production code.
 * Skips test files and logger modules.
 */
function detectConsoleLogs(file: string, content: string): ReviewFinding[] {
  if (isTestFile(file) || isLoggerFile(file)) return []

  // Skip CLI files — they use console.log for output legitimately
  const name = basename(file).toLowerCase()
  if (name === 'cli.ts' || name === 'cli.js') return []

  const findings: ReviewFinding[] = []
  const lines = content.split('\n')
  const pattern = /\bconsole\.(log|debug|warn|info)\s*\(/

  for (let i = 0; i < lines.length; i++) {
    if (pattern.test(lines[i])) {
      // Skip if inside a comment
      const trimmed = lines[i].trim()
      if (trimmed.startsWith('//') || trimmed.startsWith('*')) continue

      findings.push({
        type: 'console-log',
        severity: 'warning',
        file,
        line: i + 1,
        code: lines[i].trim(),
        suggestion: 'Remove this console statement or replace with a proper logger.',
      })
    }
  }

  return findings
}

/**
 * Detect empty catch blocks that silently swallow errors.
 */
function detectEmptyCatch(file: string, content: string): ReviewFinding[] {
  const findings: ReviewFinding[] = []
  const lines = content.split('\n')

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]
    // Single-line empty catch: catch (e) {} or catch {}
    if (/catch\s*(?:\([^)]*\))?\s*\{\s*\}/.test(line)) {
      findings.push({
        type: 'empty-catch',
        severity: 'warning',
        file,
        line: i + 1,
        code: line.trim(),
        suggestion: 'Empty catch block silently swallows errors. Add error handling or a comment explaining why the error is ignored.',
      })
      continue
    }

    // Multi-line empty catch: catch (...) {\n}
    if (/catch\s*(?:\([^)]*\))?\s*\{\s*$/.test(line)) {
      const nextLine = lines[i + 1]?.trim()
      if (nextLine === '}') {
        findings.push({
          type: 'empty-catch',
          severity: 'warning',
          file,
          line: i + 1,
          code: `${line.trim()} ${nextLine}`,
          suggestion: 'Empty catch block silently swallows errors. Add error handling or a comment explaining why the error is ignored.',
        })
      }
    }
  }

  return findings
}

/**
 * Detect TODO/FIXME/HACK/XXX comments without linked issue (#123 or URL).
 */
function detectAbandonedTodos(file: string, content: string): ReviewFinding[] {
  const findings: ReviewFinding[] = []
  const lines = content.split('\n')
  const todoPattern = /\/\/\s*(?:TODO|FIXME|HACK|XXX)\b/i
  const hasReference = /#\d+|https?:\/\//

  for (let i = 0; i < lines.length; i++) {
    if (todoPattern.test(lines[i]) && !hasReference.test(lines[i])) {
      findings.push({
        type: 'abandoned-todo',
        severity: 'info',
        file,
        line: i + 1,
        code: lines[i].trim(),
        suggestion: 'This TODO has no linked issue. Create an issue and reference it (e.g. TODO #123), or resolve it now.',
      })
    }
  }

  return findings
}

/**
 * Detect relative imports that point to files that don't exist.
 */
function detectBrokenImports(file: string, content: string, _projectPath: string): ReviewFinding[] {
  // Test files intentionally import fake paths — skip them
  if (isTestFile(file)) return []

  const findings: ReviewFinding[] = []
  const lines = content.split('\n')
  const fileDir = dirname(file)

  // Match relative imports: import ... from './path' or require('./path')
  const importPattern = /(?:import\s+.*?from\s+|require\s*\(\s*)['"](\.[^'"]+)['"]/g

  for (let i = 0; i < lines.length; i++) {
    const trimmed = lines[i].trim()
    // Skip comments and strings in non-import contexts
    if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('/*')) continue

    importPattern.lastIndex = 0
    let match: RegExpExecArray | null
    while ((match = importPattern.exec(lines[i])) !== null) {
      const importPath = match[1]
      if (resolveImportPath(fileDir, importPath)) continue

      findings.push({
        type: 'broken-import',
        severity: 'error',
        file,
        line: i + 1,
        code: lines[i].trim(),
        suggestion: `The imported file "${importPath}" does not exist. Fix the path or remove this import.`,
      })
    }
  }

  return findings
}

/**
 * Try to resolve a relative import path to an actual file.
 */
function resolveImportPath(fromDir: string, importPath: string): boolean {
  const fullPath = join(fromDir, importPath)

  // Direct file exists
  if (existsSync(fullPath) && !importPath.endsWith('/')) return true

  // TypeScript ESM pattern: import './foo.js' → actual file is './foo.ts'
  const ext = importPath.match(/\.[^.]+$/)?.[0]
  if (ext && JS_TO_TS_MAP[ext]) {
    const tsPath = fullPath.replace(new RegExp(`\\${ext}$`), JS_TO_TS_MAP[ext])
    if (existsSync(tsPath)) return true
  }

  // Try with extensions
  for (const resolveExt of RESOLVE_EXTENSIONS) {
    if (existsSync(fullPath + resolveExt)) return true
  }

  // Try as directory with index
  for (const resolveExt of RESOLVE_EXTENSIONS) {
    if (existsSync(join(fullPath, `index${resolveExt}`))) return true
  }

  return false
}

// ========================
// Cross-file detectors (full mode)
// ========================

/**
 * Detect test files that have zero test assertions.
 */
function detectEmptyTests(files: string[]): ReviewFinding[] {
  const findings: ReviewFinding[] = []
  const testPatterns = /\b(?:describe|it|test)\s*\(|assert\.|expect\s*\(/

  for (const file of files) {
    if (!isTestFile(file)) continue

    try {
      const content = readFileSync(file, 'utf-8')
      if (!testPatterns.test(content)) {
        findings.push({
          type: 'empty-test',
          severity: 'warning',
          file,
          line: 1,
          code: basename(file),
          suggestion: 'This test file has no test assertions. Add tests or remove the file.',
        })
      }
    } catch { /* skip unreadable files */ }
  }

  return findings
}

/**
 * Read tsconfig.json path aliases (e.g. "@/*" → "src/*").
 * Returns a map of alias prefix → resolved base path.
 */
function readPathAliases(projectPath: string): Map<string, string> {
  const aliases = new Map<string, string>()
  const tsconfigPath = join(projectPath, 'tsconfig.json')

  if (!existsSync(tsconfigPath)) return aliases

  try {
    // Simple JSON parse — strips comments by removing // lines
    const raw = readFileSync(tsconfigPath, 'utf-8')
      .split('\n')
      .filter(line => !line.trim().startsWith('//'))
      .join('\n')
    const config = JSON.parse(raw)
    const paths = config.compilerOptions?.paths as Record<string, string[]> | undefined
    const baseUrl = config.compilerOptions?.baseUrl ?? '.'

    if (paths) {
      for (const [alias, targets] of Object.entries(paths)) {
        if (targets.length > 0) {
          // "@/*" → strip trailing "/*", target "src/*" → strip trailing "/*"
          const aliasPrefix = alias.replace(/\/\*$/, '')
          const targetPath = targets[0].replace(/\/\*$/, '')
          aliases.set(aliasPrefix, join(projectPath, baseUrl, targetPath))
        }
      }
    }
  } catch { /* skip unparseable tsconfig */ }

  return aliases
}

/**
 * Detect source files that are not imported by any other file in the project.
 * Skips: test files, config files, entry points, type declarations.
 * Supports tsconfig path aliases (e.g. @/components/ui/button).
 */
function detectOrphanFiles(files: string[], projectPath: string): ReviewFinding[] {
  const findings: ReviewFinding[] = []
  const pathAliases = readPathAliases(projectPath)

  // Build set of all files that are imported by at least one other file
  const importedFiles = new Set<string>()

  for (const file of files) {
    try {
      const content = readFileSync(file, 'utf-8')
      // Match ALL imports (relative and alias-based)
      const importPattern = /(?:import\s+.*?from\s+|require\s*\(\s*|export\s+.*?from\s+)['"]([^'"]+)['"]/g
      const fileDir = dirname(file)

      let match: RegExpExecArray | null
      while ((match = importPattern.exec(content)) !== null) {
        const importPath = match[1]

        // Skip node_modules packages (no dot prefix AND no alias prefix)
        if (!importPath.startsWith('.') && !importPath.startsWith('/')) {
          // Check if it matches a path alias
          let resolvedAlias = false
          for (const [prefix, basePath] of pathAliases) {
            if (importPath.startsWith(prefix)) {
              const aliasPath = importPath.replace(prefix, basePath)
              const resolved = resolveImport(dirname(aliasPath), basename(aliasPath))
                ?? resolveImport(projectPath, aliasPath)
              if (resolved) {
                importedFiles.add(resolved)
                resolvedAlias = true
              }
              break
            }
          }
          if (!resolvedAlias) continue // node_modules package, skip
        } else {
          // Relative import
          const resolved = resolveImport(fileDir, importPath)
          if (resolved) importedFiles.add(resolved)
        }
      }
    } catch { /* skip unreadable files */ }
  }

  // Find files that nobody imports
  for (const file of files) {
    if (isTestFile(file)) continue
    if (isConfigFile(file)) continue
    if (isEntryPoint(file)) continue
    if (file.endsWith('.d.ts')) continue

    if (!importedFiles.has(file)) {
      findings.push({
        type: 'orphan-file',
        severity: 'info',
        file,
        line: 1,
        code: relative(projectPath, file),
        suggestion: 'This file is not imported by any other file in the project. It may be unused. Verify and remove if not needed.',
      })
    }
  }

  return findings
}

/**
 * Resolve a relative import to an absolute file path.
 */
function resolveImport(fromDir: string, importPath: string): string | null {
  const fullPath = join(fromDir, importPath)

  // Direct match
  if (existsSync(fullPath)) return resolve(fullPath)

  // TypeScript ESM pattern: import './foo.js' → actual file is './foo.ts'
  const ext = importPath.match(/\.[^.]+$/)?.[0]
  if (ext && JS_TO_TS_MAP[ext]) {
    const tsPath = fullPath.replace(new RegExp(`\\${ext}$`), JS_TO_TS_MAP[ext])
    if (existsSync(tsPath)) return resolve(tsPath)
  }

  // Try extensions
  for (const resolveExt of RESOLVE_EXTENSIONS) {
    const withExt = fullPath + resolveExt
    if (existsSync(withExt)) return resolve(withExt)
  }

  // Try index files
  for (const resolveExt of RESOLVE_EXTENSIONS) {
    const indexPath = join(fullPath, `index${resolveExt}`)
    if (existsSync(indexPath)) return resolve(indexPath)
  }

  return null
}

// ========================
// Main review function
// ========================

function buildSummary(findings: ReviewFinding[]): string {
  const counts: Record<string, number> = {}
  for (const f of findings) {
    counts[f.type] = (counts[f.type] ?? 0) + 1
  }

  if (Object.keys(counts).length === 0) return 'No issues found. Clean code.'

  const parts: string[] = []
  if (counts['broken-import']) parts.push(`${counts['broken-import']} broken import(s)`)
  if (counts['console-log']) parts.push(`${counts['console-log']} console statement(s)`)
  if (counts['empty-catch']) parts.push(`${counts['empty-catch']} empty catch block(s)`)
  if (counts['abandoned-todo']) parts.push(`${counts['abandoned-todo']} TODO(s) without issue`)
  if (counts['empty-test']) parts.push(`${counts['empty-test']} empty test file(s)`)
  if (counts['orphan-file']) parts.push(`${counts['orphan-file']} orphan file(s)`)

  return `Found ${parts.join(', ')}.`
}

/**
 * Review a project for AI-generated code debris.
 * Quick mode: per-file analysis only (~500ms).
 * Full mode: per-file + cross-file analysis (~2-5s).
 */
export async function review(
  projectPath: string,
  options: ReviewOptions = {},
): Promise<ReviewResult> {
  const absPath = resolve(projectPath)
  const mode = options.mode ?? 'quick'
  const excludePatterns = options.excludePatterns ?? []

  // Collect source files (reuse sweep.ts infrastructure)
  const excludeDirs = new Set([
    'node_modules', 'dist', 'build', '.git', '.next', '.nuxt', '.svelte-kit',
    'coverage', 'out', '.output', '.cache', '.turbo', '__pycache__',
    ...excludePatterns,
  ])

  const sourceExts = new Set(['.js', '.ts', '.mjs', '.cjs', '.jsx', '.tsx'])
  const files = collectSourceFiles(absPath, sourceExts, excludeDirs)

  if (files.length === 0) {
    return {
      mode,
      projectPath: absPath,
      filesAnalyzed: 0,
      totalFindings: 0,
      findings: [],
      summary: 'No source files found.',
      note: REVIEW_NOTE,
    }
  }

  const allFindings: ReviewFinding[] = []

  // Quick mode: per-file analysis
  for (const file of files) {
    try {
      const content = readFileSync(file, 'utf-8')
      allFindings.push(...detectConsoleLogs(file, content))
      allFindings.push(...detectEmptyCatch(file, content))
      allFindings.push(...detectAbandonedTodos(file, content))
      allFindings.push(...detectBrokenImports(file, content, absPath))
    } catch { /* skip unreadable files */ }
  }

  // Full mode: cross-file analysis
  if (mode === 'full') {
    allFindings.push(...detectEmptyTests(files))
    allFindings.push(...detectOrphanFiles(files, absPath))
  }

  // Sort: errors first, then warnings, then info
  const severityOrder = { error: 0, warning: 1, info: 2 }
  allFindings.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity])

  return {
    mode,
    projectPath: absPath,
    filesAnalyzed: files.length,
    totalFindings: allFindings.length,
    findings: allFindings,
    summary: buildSummary(allFindings),
    note: REVIEW_NOTE,
  }
}
