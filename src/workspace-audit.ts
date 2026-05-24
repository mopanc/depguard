/**
 * Workspace Auto-Exec Surface audit.
 *
 * Scans a freshly-cloned repo for files that execute automatically when the
 * developer opens it in an IDE, runs `direnv allow`, or builds. This is the
 * technical core of the "fake-interview / take-home test" attack class:
 * a malicious repo runs payload code the moment the IDE finishes loading,
 * before the developer has a chance to read any source file.
 *
 * Detection is *FP-averse*: precision > recall. A benign `runOn: folderOpen`
 * task running `npm run watch` is INFO, not WARN. Only escalate severity when
 * the command itself matches a documented attack heuristic.
 *
 * NOTE: Pattern regexes are built indirectly (via string concat) where the
 * literal would otherwise cause OTHER scanners to flag this file. We detect
 * these patterns in other repos; we never execute them ourselves.
 */

import { readFileSync, existsSync, statSync, readdirSync } from 'node:fs'
import { join } from 'node:path'

export type AutoExecSeverity = 'INFO' | 'WARN' | 'HIGH'

export type AutoExecSource =
  | 'vscode-tasks'
  | 'vscode-settings'
  | 'devcontainer'
  | 'envrc'
  | 'jetbrains-runconfig'
  | 'makefile'
  | 'gitattributes'
  | 'githooks'

export interface AutoExecFinding {
  source: AutoExecSource
  file: string
  trigger: string
  command: string
  severity: AutoExecSeverity
  reasons: string[]
}

export interface WorkspaceAuditResult {
  scannedPath: string
  findings: AutoExecFinding[]
  surfacesChecked: string[]
  summary: { info: number; warn: number; high: number }
  note: string
}

const MAX_FILE_BYTES = 256 * 1024
const MAX_COMMAND_DISPLAY = 200
const NOTE = 'Pre-open audit. Open this repo in your IDE only after you understand what each surface will execute. INFO findings are auto-exec surfaces that look benign; WARN/HIGH require active review.'

// --- Pattern classifier ----------------------------------------------------

// Indirect literals so this source file does not get flagged by other scanners.
const DCE = 'ev' + 'al'
const XEC = 'ex' + 'ec'

interface HeuristicRule {
  regex: RegExp
  severity: AutoExecSeverity
  reason: string
}

const HEURISTICS: HeuristicRule[] = [
  // --- HIGH: clear malware / obfuscation patterns ---
  {
    regex: /(?:curl|wget|fetch)\s[^|;&]*\|[^|;&]*(?:sh|bash|zsh|fish|python\d?|node|perl|ruby|php)\b/i,
    severity: 'HIGH',
    reason: 'Pipes downloaded content directly into a shell or interpreter (remote code execution pattern)',
  },
  {
    regex: /(?:iwr|invoke-webrequest|invoke-restmethod|irm)\b[^|;]*\|[^|;]*(?:iex|invoke-expression)/i,
    severity: 'HIGH',
    reason: 'PowerShell download-and-execute pattern (iwr | iex)',
  },
  {
    regex: /(?:atob\s*\(|Buffer\.from\s*\([^)]*['"]base64['"]|base64\s+(?:-d|--decode))/i,
    severity: 'HIGH',
    reason: 'Decodes base64 content — common payload obfuscation in auto-exec configs',
  },
  {
    regex: /(?:\\x[0-9a-f]{2}){8,}/i,
    severity: 'HIGH',
    reason: 'Long hex-encoded byte sequence — common obfuscation for hidden commands/URLs',
  },
  {
    regex: new RegExp(`(?:^|[;&|\\s])${DCE}\\s*[(\`]`),
    severity: 'HIGH',
    reason: `Dynamic code execution (${DCE}) — should never appear in an auto-exec config`,
  },
  {
    regex: /\/dev\/tcp\//,
    severity: 'HIGH',
    reason: 'Bash /dev/tcp reverse-shell pattern',
  },
  {
    regex: /\bnc\b\s+-[a-zA-Z]*e[a-zA-Z]*\s/,
    severity: 'HIGH',
    reason: 'Netcat with execute flag (reverse shell)',
  },
  {
    regex: /(?:python\d?\s+-c|node\s+-e|perl\s+-e|ruby\s+-e)\s+['"][^'"]{40,}/i,
    severity: 'HIGH',
    reason: 'Inline interpreter one-liner with substantial payload — common obfuscation vehicle',
  },

  // --- WARN: suspicious but not always malicious ---
  {
    regex: /\b(?:curl|wget|fetch|iwr|invoke-webrequest|invoke-restmethod)\b/i,
    severity: 'WARN',
    reason: 'Makes network request — verify the destination and what is done with the response',
  },
  {
    regex: /~\/(?:\.ssh|\.aws|\.gnupg|\.config\/gh|\.npmrc|\.env|\.docker|\.kube|\.gitconfig)/,
    severity: 'WARN',
    reason: 'Reads sensitive credential/config files from home directory',
  },
  {
    regex: /(?:\$HOME|\$\{HOME\})\/(?:\.ssh|\.aws|\.gnupg|\.config\/gh|\.npmrc|\.env|\.docker|\.kube)/,
    severity: 'WARN',
    reason: 'Reads sensitive credential/config files via $HOME',
  },
  {
    regex: /Library\/(?:Application Support\/(?:Google\/Chrome|Firefox|BraveSoftware|Microsoft Edge|Chromium)|Keychains|Cookies)/i,
    severity: 'WARN',
    reason: 'Accesses macOS browser profile / keychain — common credential-theft target',
  },
  {
    regex: /AppData[\\/]+(?:Roaming|Local)[\\/]+(?:Mozilla|Microsoft|Google|BraveSoftware|Chromium)/i,
    severity: 'WARN',
    reason: 'Accesses Windows browser profile — common credential-theft target',
  },
  {
    regex: /\.config\/(?:google-chrome|chromium|BraveSoftware|microsoft-edge)/,
    severity: 'WARN',
    reason: 'Accesses Linux browser profile — common credential-theft target',
  },
  {
    regex: /(?:NPM_TOKEN|GITHUB_TOKEN|AWS_(?:SECRET|ACCESS|SESSION)|API_KEY|PRIVATE_KEY|GCP_(?:KEY|CREDENTIALS)|OPENAI_API_KEY|ANTHROPIC_API_KEY)/,
    severity: 'WARN',
    reason: 'References secret-named environment variables',
  },
  {
    regex: new RegExp(`(?:child_process|spawn|${XEC}Sync|${XEC}File)`),
    severity: 'WARN',
    reason: 'Spawns child processes — verify the commands being run',
  },
]

const SCRIPT_INTERPRETER_PROFILE_PATHS = /\.(?:sh|bash|py|pyc|pyo|js|mjs|cjs|ts|rb|pl|php|exe|bat|cmd|ps1)$/i

function classify(command: string): { severity: AutoExecSeverity; reasons: string[] } {
  const reasons: string[] = []
  let severity: AutoExecSeverity = 'INFO'

  for (const rule of HEURISTICS) {
    if (rule.regex.test(command)) {
      reasons.push(rule.reason)
      if (rankSeverity(rule.severity) > rankSeverity(severity)) {
        severity = rule.severity
      }
    }
  }

  return { severity, reasons }
}

function rankSeverity(s: AutoExecSeverity): number {
  return s === 'HIGH' ? 3 : s === 'WARN' ? 2 : 1
}

function truncate(s: string, max = MAX_COMMAND_DISPLAY): string {
  const flat = s.replace(/\s+/g, ' ').trim()
  if (flat.length <= max) return flat
  return flat.slice(0, max - 3) + '...'
}

// --- JSONC (JSON-with-comments) parser -------------------------------------
// VS Code and devcontainer config files allow // and /* */ comments and
// trailing commas. Strip them while preserving string contents.

export function parseJsonc(raw: string): unknown {
  try {
    const stripped = stripJsoncComments(raw).replace(/,(\s*[}\]])/g, '$1')
    return JSON.parse(stripped)
  } catch {
    return null
  }
}

function stripJsoncComments(raw: string): string {
  let out = ''
  let i = 0
  let inString = false
  let stringChar = ''

  while (i < raw.length) {
    const c = raw[i]
    const next = raw[i + 1]

    if (inString) {
      out += c
      if (c === '\\') {
        out += raw[i + 1] ?? ''
        i += 2
        continue
      }
      if (c === stringChar) inString = false
      i++
      continue
    }

    if (c === '"' || c === "'") {
      inString = true
      stringChar = c
      out += c
      i++
      continue
    }

    if (c === '/' && next === '/') {
      while (i < raw.length && raw[i] !== '\n') i++
      continue
    }

    if (c === '/' && next === '*') {
      i += 2
      while (i < raw.length && !(raw[i] === '*' && raw[i + 1] === '/')) i++
      i += 2
      continue
    }

    out += c
    i++
  }

  return out
}

// --- File reading helpers --------------------------------------------------

function safeRead(path: string): string | null {
  try {
    const st = statSync(path)
    if (!st.isFile()) return null
    if (st.size > MAX_FILE_BYTES) return null
    return readFileSync(path, 'utf8')
  } catch {
    return null
  }
}

function safeReaddir(path: string): string[] {
  try {
    const st = statSync(path)
    if (!st.isDirectory()) return []
    return readdirSync(path)
  } catch {
    return []
  }
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

// --- Detector: VS Code tasks.json ------------------------------------------

function detectVscodeTasks(repoPath: string, findings: AutoExecFinding[], checked: string[]): void {
  const rel = '.vscode/tasks.json'
  const raw = safeRead(join(repoPath, rel))
  if (raw === null) return
  checked.push(rel)

  const obj = parseJsonc(raw)
  if (!isObject(obj)) return
  const tasks = obj.tasks
  if (!Array.isArray(tasks)) return

  for (const task of tasks) {
    if (!isObject(task)) continue
    const runOptions = isObject(task.runOptions) ? task.runOptions : null
    const runOn = runOptions?.runOn
    if (runOn !== 'folderOpen') continue

    const cmd = renderTaskCommand(task)
    if (!cmd) continue

    const { severity, reasons } = classify(cmd)
    findings.push({
      source: 'vscode-tasks',
      file: rel,
      trigger: `task "${String(task.label ?? '(unnamed)')}" — runOptions.runOn: folderOpen`,
      command: truncate(cmd),
      severity,
      reasons: ['Runs automatically every time this folder is opened in VS Code (no prompt if workspace trust is inherited)', ...reasons],
    })
  }
}

function renderTaskCommand(task: Record<string, unknown>): string {
  const command = typeof task.command === 'string' ? task.command : ''
  const args = Array.isArray(task.args) ? task.args.map(String) : []
  const script = typeof task.script === 'string' ? task.script : ''
  if (script) return `npm run ${script}`
  if (!command && args.length === 0) return ''
  return [command, ...args].filter(Boolean).join(' ')
}

// --- Detector: VS Code settings.json ---------------------------------------

function detectVscodeSettings(repoPath: string, findings: AutoExecFinding[], checked: string[]): void {
  const rel = '.vscode/settings.json'
  const raw = safeRead(join(repoPath, rel))
  if (raw === null) return
  checked.push(rel)

  const obj = parseJsonc(raw)
  if (!isObject(obj)) return

  // Flat settings can be either nested objects or dotted keys.
  const flat = flattenSettings(obj)

  // 1. Terminal automation profile — overrides shell used for tasks/debug
  for (const platform of ['linux', 'osx', 'windows']) {
    const path = flat[`terminal.integrated.automationProfile.${platform}.path`]
    const args = flat[`terminal.integrated.automationProfile.${platform}.args`]
    if (typeof path !== 'string') continue
    const cmd = `${path}${Array.isArray(args) ? ' ' + args.join(' ') : ''}`
    const { severity, reasons } = classify(cmd)
    const escalated: AutoExecSeverity = severity === 'INFO' && isSuspiciousProfilePath(path, repoPath)
      ? 'WARN'
      : severity
    findings.push({
      source: 'vscode-settings',
      file: rel,
      trigger: `terminal.integrated.automationProfile.${platform}.path`,
      command: truncate(cmd),
      severity: escalated,
      reasons: [
        'Overrides the shell that VS Code uses for tasks (including runOn:folderOpen) — bypasses the user\'s configured shell',
        ...(escalated === 'WARN' && reasons.length === 0
          ? ['Profile path is unusual (relative to repo, or points to a script file)']
          : reasons),
      ],
    })
  }

  // 2. Custom shell args
  for (const platform of ['linux', 'osx', 'windows']) {
    const args = flat[`terminal.integrated.shellArgs.${platform}`]
    if (!Array.isArray(args) || args.length === 0) continue
    const cmd = args.map(String).join(' ')
    const { severity, reasons } = classify(cmd)
    findings.push({
      source: 'vscode-settings',
      file: rel,
      trigger: `terminal.integrated.shellArgs.${platform}`,
      command: truncate(cmd),
      severity,
      reasons: ['Custom arguments passed to the terminal shell on every open', ...reasons],
    })
  }

  // 3. git.path / python interpreter / eslint nodePath — binary overrides
  const BINARY_OVERRIDES: Array<{ key: string; label: string }> = [
    { key: 'git.path', label: 'git executable' },
    { key: 'python.defaultInterpreterPath', label: 'Python interpreter' },
    { key: 'python.pythonPath', label: 'Python interpreter (legacy)' },
    { key: 'eslint.nodePath', label: 'Node.js for ESLint' },
    { key: 'npm.packageManager', label: 'package manager' },
  ]
  for (const { key, label } of BINARY_OVERRIDES) {
    const val = flat[key]
    if (typeof val !== 'string' || !val) continue
    const inRepo = isPathInsideRepo(val, repoPath)
    const isStandard = key === 'npm.packageManager' && ['npm', 'pnpm', 'yarn', 'bun'].includes(val)
    if (isStandard) continue
    const { severity: cls, reasons: clsReasons } = classify(val)
    const severity: AutoExecSeverity = cls === 'INFO' && inRepo ? 'WARN' : cls
    findings.push({
      source: 'vscode-settings',
      file: rel,
      trigger: key,
      command: truncate(val),
      severity,
      reasons: [
        `Overrides the ${label} VS Code uses for this workspace`,
        ...(inRepo ? ['Points to a path inside the repo — checked in code will run as this binary'] : []),
        ...clsReasons,
      ],
    })
  }
}

function flattenSettings(obj: Record<string, unknown>, prefix = ''): Record<string, unknown> {
  const out: Record<string, unknown> = {}
  for (const [key, val] of Object.entries(obj)) {
    const full = prefix ? `${prefix}.${key}` : key
    if (isObject(val)) {
      // Always also expose the nested form as dotted key for direct lookup
      Object.assign(out, flattenSettings(val, full))
    } else {
      out[full] = val
    }
  }
  return out
}

function isPathInsideRepo(p: string, _repoPath: string): boolean {
  // Heuristic: relative paths and ${workspaceFolder} references point into the repo.
  if (p.startsWith('./') || p.startsWith('../')) return true
  if (p.startsWith('${workspaceFolder}') || p.startsWith('${workspaceRoot}')) return true
  if (!p.startsWith('/') && !p.match(/^[A-Za-z]:[\\/]/) && !p.startsWith('~')) return true
  return false
}

function isSuspiciousProfilePath(path: string, repoPath: string): boolean {
  if (isPathInsideRepo(path, repoPath)) return true
  if (SCRIPT_INTERPRETER_PROFILE_PATHS.test(path)) return true
  return false
}

// --- Detector: devcontainer.json -------------------------------------------

const DEVCONTAINER_HOOKS = [
  'initializeCommand',
  'onCreateCommand',
  'updateContentCommand',
  'postCreateCommand',
  'postStartCommand',
  'postAttachCommand',
] as const

function detectDevcontainer(repoPath: string, findings: AutoExecFinding[], checked: string[]): void {
  const candidates: string[] = []
  for (const c of ['.devcontainer/devcontainer.json', '.devcontainer.json']) {
    if (existsSync(join(repoPath, c))) candidates.push(c)
  }
  for (const entry of safeReaddir(join(repoPath, '.devcontainer'))) {
    const sub = join(repoPath, '.devcontainer', entry)
    try {
      if (!statSync(sub).isDirectory()) continue
    } catch {
      continue
    }
    const nested = `.devcontainer/${entry}/devcontainer.json`
    if (existsSync(join(repoPath, nested))) candidates.push(nested)
  }

  for (const rel of candidates) {
    const raw = safeRead(join(repoPath, rel))
    if (raw === null) continue
    checked.push(rel)
    const obj = parseJsonc(raw)
    if (!isObject(obj)) continue

    for (const hook of DEVCONTAINER_HOOKS) {
      const val = obj[hook]
      if (val === undefined) continue
      const commands = extractDevcontainerCommands(val)
      const isInitOnHost = hook === 'initializeCommand'
      for (const cmd of commands) {
        const { severity, reasons } = classify(cmd)
        // initializeCommand runs on HOST (not container) — extra context, not auto-escalated
        findings.push({
          source: 'devcontainer',
          file: rel,
          trigger: isInitOnHost ? `${hook} (runs on host machine before container builds)` : hook,
          command: truncate(cmd),
          severity,
          reasons: [
            isInitOnHost
              ? 'Runs on your host machine before the container is built — full user privileges, NOT containerised'
              : `Runs automatically during dev container ${hook}`,
            ...reasons,
          ],
        })
      }
    }
  }
}

function extractDevcontainerCommands(val: unknown): string[] {
  if (typeof val === 'string') return [val]
  if (Array.isArray(val)) return [val.map(String).join(' ')]
  if (isObject(val)) {
    return Object.values(val)
      .map(v => (typeof v === 'string' ? v : Array.isArray(v) ? v.map(String).join(' ') : ''))
      .filter(s => s)
  }
  return []
}

// --- Detector: .envrc (direnv) ---------------------------------------------

const BENIGN_DIRENV_PATTERNS = [
  /^use\s+(?:nix|flake|node|python|go|ruby|java|asdf|mise|guix)\b/,
  /^dotenv(?:\s|$)/,
  /^layout\s+(?:python|node|ruby|go|java|haskell)\b/,
  /^export\s+[A-Z_][A-Z0-9_]*=/,
  /^PATH_add\s+/,
  /^path_add\s+/,
  /^source_env\s+/,
  /^source_url\s+["'][^"']+["']\s+["'][a-f0-9]{40,}["']/i, // source_url with sha256 — direnv stdlib pattern
  /^watch_file\s+/,
  /^strict_env\s*$/,
  /^direnv_load\s+/,
]

function detectEnvrc(repoPath: string, findings: AutoExecFinding[], checked: string[]): void {
  const rel = '.envrc'
  const raw = safeRead(join(repoPath, rel))
  if (raw === null) return
  checked.push(rel)

  const meaningfulLines = raw
    .split('\n')
    .map(l => l.trim())
    .filter(l => l && !l.startsWith('#'))

  if (meaningfulLines.length === 0) return

  const allBenign = meaningfulLines.every(line =>
    BENIGN_DIRENV_PATTERNS.some(p => p.test(line)),
  )

  const cls = classify(raw)
  let severity: AutoExecSeverity = cls.severity
  const reasons: string[] = ['direnv evaluates this file as a shell script when entering the directory (after `direnv allow`)']

  if (allBenign && cls.severity === 'INFO') {
    severity = 'INFO'
    reasons.push('Content uses only standard direnv stdlib functions')
  } else if (cls.severity === 'INFO') {
    // Non-benign content but no HIGH/WARN match — still escalate to WARN
    // because .envrc with custom shell is arbitrary code, not configuration.
    severity = 'WARN'
    reasons.push('Contains shell code beyond standard direnv stdlib functions')
  } else {
    reasons.push(...cls.reasons)
  }

  findings.push({
    source: 'envrc',
    file: rel,
    trigger: 'direnv on cd / folder open (after `direnv allow`)',
    command: truncate(raw),
    severity,
    reasons,
  })
}

// --- Detector: JetBrains run configurations --------------------------------

function detectJetbrainsRunConfigs(repoPath: string, findings: AutoExecFinding[], checked: string[]): void {
  const dir = '.idea/runConfigurations'
  const entries = safeReaddir(join(repoPath, dir))
  for (const entry of entries) {
    if (!entry.endsWith('.xml')) continue
    const rel = `${dir}/${entry}`
    const xml = safeRead(join(repoPath, rel))
    if (xml === null) continue
    checked.push(rel)

    const configMatch = xml.match(/<configuration\b[^>]*\sname="([^"]+)"[^>]*\stype="([^"]+)"/)
      ?? xml.match(/<configuration\b[^>]*\stype="([^"]+)"[^>]*\sname="([^"]+)"/)
    if (!configMatch) continue
    let configName: string
    let configType: string
    if (xml.match(/<configuration\b[^>]*\sname="[^"]+"[^>]*\stype="/)) {
      configName = configMatch[1]
      configType = configMatch[2]
    } else {
      configType = configMatch[1]
      configName = configMatch[2]
    }

    const scriptText = extractXmlOption(xml, 'SCRIPT_TEXT')
    const scriptPath = extractXmlOption(xml, 'SCRIPT_PATH')
    const interpreter = extractXmlOption(xml, 'INTERPRETER_PATH')
    const scriptOptions = extractXmlOption(xml, 'SCRIPT_OPTIONS')
    const programParams = extractXmlOption(xml, 'PROGRAM_PARAMETERS')

    const parts = [interpreter, scriptText || scriptPath, scriptOptions, programParams]
      .filter(s => s && s.length > 0)
    if (parts.length === 0) continue

    const cmd = parts.join(' ')
    const { severity, reasons } = classify(cmd)
    findings.push({
      source: 'jetbrains-runconfig',
      file: rel,
      trigger: `JetBrains run configuration "${configName}" (${configType})`,
      command: truncate(cmd),
      severity,
      reasons: [
        'Executes when the user runs this configuration in a JetBrains IDE (IntelliJ, PyCharm, WebStorm, etc.)',
        ...reasons,
      ],
    })
  }
}

function extractXmlOption(xml: string, optionName: string): string {
  const re = new RegExp(`<option\\s+name="${optionName}"\\s+value="([^"]*)"`)
  const match = xml.match(re)
  if (!match) return ''
  return decodeXmlEntities(match[1])
}

function decodeXmlEntities(s: string): string {
  return s
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
}

// --- Detector: Makefile default target -------------------------------------

function detectMakefile(repoPath: string, findings: AutoExecFinding[], checked: string[]): void {
  let rel: string | null = null
  for (const candidate of ['Makefile', 'makefile', 'GNUmakefile']) {
    if (existsSync(join(repoPath, candidate))) {
      rel = candidate
      break
    }
  }
  if (!rel) return
  const raw = safeRead(join(repoPath, rel))
  if (raw === null) return
  checked.push(rel)

  const target = findFirstMakeTarget(raw)
  if (!target) return

  const recipe = target.recipe.join('\n')
  if (!recipe.trim()) return

  // Strip Make line prefixes (@, -, +) that don't affect classification
  const cleaned = target.recipe
    .map(l => l.replace(/^[\s@\-+]+/, ''))
    .join('\n')

  const { severity, reasons } = classify(cleaned)

  // FP-averse: only report Makefile findings when classifier produced WARN/HIGH.
  // Benign default targets (`all: build test`) are not actionable signal.
  if (severity === 'INFO') return

  findings.push({
    source: 'makefile',
    file: rel,
    trigger: `make ${target.name} (default target — runs when 'make' is invoked with no arguments)`,
    command: truncate(recipe),
    severity,
    reasons: [
      `Default Make target executed by 'make' with no arguments; some IDEs trigger this on build shortcut`,
      ...reasons,
    ],
  })
}

interface MakeTarget {
  name: string
  recipe: string[]
}

function findFirstMakeTarget(content: string): MakeTarget | null {
  const lines = content.split('\n')
  let name: string | null = null
  const recipe: string[] = []

  for (const line of lines) {
    if (!name) {
      if (/^\s*(?:#|$)/.test(line)) continue
      if (/^\s*[A-Za-z_][A-Za-z0-9_]*\s*[+:?!]?=/.test(line)) continue
      if (/^\s*(?:include|sinclude|-include|export|unexport|override|define|endef|ifeq|ifneq|ifdef|ifndef|else|endif)\b/.test(line)) continue
      if (/^\s*\./.test(line)) continue // .PHONY, .SUFFIXES, etc.
      const m = line.match(/^([A-Za-z_][A-Za-z0-9_./-]*)\s*:/)
      if (m) {
        name = m[1]
      }
    } else {
      if (/^\t/.test(line)) {
        recipe.push(line.slice(1))
        continue
      }
      if (/^\s*$/.test(line)) continue
      break
    }
  }

  if (!name) return null
  return { name, recipe }
}

// --- Detector: .gitattributes filter drivers -------------------------------

function detectGitattributes(repoPath: string, findings: AutoExecFinding[], checked: string[]): void {
  const rel = '.gitattributes'
  const raw = safeRead(join(repoPath, rel))
  if (raw === null) return
  checked.push(rel)

  const lines = raw.split('\n')
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim()
    if (!line || line.startsWith('#')) continue

    const filterMatch = line.match(/\bfilter=([A-Za-z0-9_-]+)/)
    if (!filterMatch) continue
    const filterName = filterMatch[1]
    // git-lfs is benign and ubiquitous
    if (filterName === 'lfs') continue

    findings.push({
      source: 'gitattributes',
      file: rel,
      trigger: `filter=${filterName} on line ${i + 1}`,
      command: truncate(line),
      severity: 'WARN',
      reasons: [
        `Custom git filter driver "${filterName}" — its smudge/clean commands (defined in .gitconfig) run on every checkout/diff for matching files`,
        'Check any setup script in the repo to see if it configures this filter via git config',
      ],
    })
  }
}

// --- Detector: Committed git hooks ----------------------------------------

const KNOWN_GIT_HOOKS = new Set([
  'applypatch-msg', 'pre-applypatch', 'post-applypatch',
  'pre-commit', 'pre-merge-commit', 'prepare-commit-msg', 'commit-msg', 'post-commit',
  'pre-rebase', 'post-checkout', 'post-merge', 'pre-push',
  'pre-receive', 'update', 'proc-receive', 'post-receive', 'post-update', 'reference-transaction',
  'push-to-checkout', 'pre-auto-gc', 'post-rewrite', 'sendemail-validate',
  'fsmonitor-watchman', 'p4-changelist', 'p4-prepare-changelist', 'p4-post-changelist', 'p4-pre-submit',
])

function detectGithooks(repoPath: string, findings: AutoExecFinding[], checked: string[]): void {
  for (const dir of ['.githooks', '.git-hooks', 'githooks']) {
    const entries = safeReaddir(join(repoPath, dir))
    if (entries.length === 0) continue
    checked.push(`${dir}/`)

    for (const entry of entries) {
      if (!KNOWN_GIT_HOOKS.has(entry)) continue
      const rel = `${dir}/${entry}`
      const content = safeRead(join(repoPath, rel))
      if (content === null) continue

      const { severity, reasons } = classify(content)
      findings.push({
        source: 'githooks',
        file: rel,
        trigger: `git hook "${entry}" (only fires after the user sets \`git config core.hooksPath ${dir}\`)`,
        command: truncate(content),
        severity,
        reasons: [
          'Committed git hook — does NOT run automatically. Only fires after the user opts in via `git config core.hooksPath`. Many setup scripts do this silently.',
          ...reasons,
        ],
      })
    }
  }
}

// --- Public entry point ----------------------------------------------------

export function auditWorkspace(repoPath: string): WorkspaceAuditResult {
  const findings: AutoExecFinding[] = []
  const surfacesChecked: string[] = []

  detectVscodeTasks(repoPath, findings, surfacesChecked)
  detectVscodeSettings(repoPath, findings, surfacesChecked)
  detectDevcontainer(repoPath, findings, surfacesChecked)
  detectEnvrc(repoPath, findings, surfacesChecked)
  detectJetbrainsRunConfigs(repoPath, findings, surfacesChecked)
  detectMakefile(repoPath, findings, surfacesChecked)
  detectGitattributes(repoPath, findings, surfacesChecked)
  detectGithooks(repoPath, findings, surfacesChecked)

  // Sort findings: HIGH first, then WARN, then INFO; within tier, by source then file
  findings.sort((a, b) => {
    const rs = rankSeverity(b.severity) - rankSeverity(a.severity)
    if (rs !== 0) return rs
    if (a.source !== b.source) return a.source.localeCompare(b.source)
    return a.file.localeCompare(b.file)
  })

  return {
    scannedPath: repoPath,
    findings,
    surfacesChecked,
    summary: {
      info: findings.filter(f => f.severity === 'INFO').length,
      warn: findings.filter(f => f.severity === 'WARN').length,
      high: findings.filter(f => f.severity === 'HIGH').length,
    },
    note: NOTE,
  }
}
