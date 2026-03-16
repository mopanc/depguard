/**
 * Analyze install scripts for suspicious patterns.
 * Checks for common supply chain attack vectors without executing anything.
 */

export interface ScriptAnalysis {
  suspicious: boolean
  risks: ScriptRisk[]
}

export interface ScriptRisk {
  script: string
  pattern: string
  severity: 'critical' | 'high' | 'moderate'
  description: string
}

interface PatternRule {
  regex: RegExp
  severity: ScriptRisk['severity']
  description: string
}

const SUSPICIOUS_PATTERNS: PatternRule[] = [
  // Network exfiltration
  {
    regex: /curl\s.*\|.*(?:sh|bash|zsh)/i,
    severity: 'critical',
    description: 'Downloads and executes remote code (curl | sh)',
  },
  {
    regex: /wget\s.*\|.*(?:sh|bash|zsh)/i,
    severity: 'critical',
    description: 'Downloads and executes remote code (wget | sh)',
  },
  {
    regex: /curl\s.*-o\s.*&&.*(?:sh|bash|chmod)/i,
    severity: 'critical',
    description: 'Downloads file and executes it',
  },
  // Typosquatting shell — ssh instead of sh
  {
    regex: /\bssh\b.*(?:install|setup|init)/i,
    severity: 'critical',
    description: 'Suspicious use of ssh in install script (possible typosquatting of sh)',
  },
  {
    regex: /\/bin\/ssh\b/,
    severity: 'critical',
    description: 'References /bin/ssh instead of /bin/sh (likely malicious)',
  },
  // Environment variable access (credential theft)
  {
    regex: /process\.env\b/,
    severity: 'high',
    description: 'Accesses environment variables (potential credential theft)',
  },
  {
    regex: /\$(?:HOME|USER|NPM_TOKEN|AWS_|GITHUB_TOKEN|API_KEY|SECRET|PASSWORD|PRIVATE_KEY)/i,
    severity: 'critical',
    description: 'Accesses sensitive environment variables',
  },
  // Encoded payloads
  {
    regex: /(?:atob|Buffer\.from)\s*\([^)]*,\s*['"]base64['"]/,
    severity: 'high',
    description: 'Decodes base64 content (possibly hiding malicious payload)',
  },
  {
    regex: /eval\s*\(\s*(?:atob|Buffer|unescape|decodeURI)/,
    severity: 'critical',
    description: 'Evaluates decoded/obfuscated code',
  },
  {
    regex: /\\x[0-9a-f]{2}(?:\\x[0-9a-f]{2}){5,}/i,
    severity: 'high',
    description: 'Contains hex-encoded strings (possible obfuscation)',
  },
  // Network calls
  {
    regex: /https?:\/\/(?!(?:registry\.npmjs\.org|github\.com|nodejs\.org))/i,
    severity: 'moderate',
    description: 'Makes network request to external URL',
  },
  {
    regex: /net\.connect|dgram|dns\.resolve|fetch\s*\(/,
    severity: 'high',
    description: 'Uses network APIs in install script',
  },
  // File system access to sensitive paths
  {
    regex: /\/etc\/(?:passwd|shadow|hosts)/,
    severity: 'critical',
    description: 'Accesses system credential files',
  },
  {
    regex: /~\/\.ssh|~\/\.aws|~\/\.npmrc|~\/\.env/,
    severity: 'critical',
    description: 'Accesses sensitive config files (SSH keys, AWS creds, npm tokens)',
  },
  {
    regex: /~\/\.gnupg|~\/\.config\/gh/,
    severity: 'critical',
    description: 'Accesses GPG or GitHub CLI credentials',
  },
  // Code execution
  {
    regex: /child_process|exec\s*\(|execSync|spawn\s*\(/,
    severity: 'high',
    description: 'Spawns child processes in install script',
  },
  {
    regex: /eval\s*\(/,
    severity: 'high',
    description: 'Uses eval() (dynamic code execution)',
  },
  // Reverse shells
  {
    regex: /\/dev\/tcp\//,
    severity: 'critical',
    description: 'Uses /dev/tcp (reverse shell pattern)',
  },
  {
    regex: /nc\s+-[a-z]*e\s/i,
    severity: 'critical',
    description: 'Uses netcat with execute flag (reverse shell)',
  },
]

const INSTALL_SCRIPT_NAMES = ['preinstall', 'install', 'postinstall']

/**
 * Analyze package scripts for suspicious patterns.
 * Does NOT execute any scripts — purely static pattern matching.
 */
export function analyzeScripts(scripts: Record<string, string> | undefined): ScriptAnalysis {
  if (!scripts) return { suspicious: false, risks: [] }

  const risks: ScriptRisk[] = []

  for (const scriptName of INSTALL_SCRIPT_NAMES) {
    const content = scripts[scriptName]
    if (!content) continue

    for (const rule of SUSPICIOUS_PATTERNS) {
      if (rule.regex.test(content)) {
        risks.push({
          script: scriptName,
          pattern: rule.regex.source.slice(0, 60),
          severity: rule.severity,
          description: rule.description,
        })
      }
    }
  }

  return {
    suspicious: risks.length > 0,
    risks,
  }
}
