import type { AdvisorOptions, Recommendation } from './types.js'
import { search } from './search.js'
import { score } from './scorer.js'

/**
 * Given a user intent (e.g. "date formatting", "http client"),
 * search for packages, audit the top results, and recommend
 * whether to install one or write from scratch.
 *
 * Thresholds:
 *   ≥60: "install"
 *   40-59: "caution"
 *   <40: "write-from-scratch"
 */
export async function shouldUse(
  intent: string,
  options: AdvisorOptions = {},
): Promise<Recommendation> {
  const {
    threshold = 60,
    targetLicense = 'MIT',
    limit = 5,
    fetcher = globalThis.fetch,
  } = options

  const results = await search(intent, { limit, fetcher })

  if (results.length === 0) {
    return {
      intent,
      action: 'write-from-scratch',
      package: null,
      score: null,
      alternatives: [],
      reasoning: 'No packages found matching this intent',
      warnings: [],
    }
  }

  // Score the top results concurrently
  const scored = await Promise.all(
    results.map(async (entry) => {
      const result = await score(entry.name, { targetLicense, fetcher })
      return { name: entry.name, score: result.total, warnings: result.warnings }
    }),
  )

  // Sort by score descending
  scored.sort((a, b) => b.score - a.score)

  const best = scored[0]
  const alternatives = scored.slice(1).map(s => ({ name: s.name, score: s.score }))
  const allWarnings = scored.flatMap(s => s.warnings)

  const action = decideAction(best.score, threshold)
  const reasoning = buildReasoning(action, best.name, best.score, threshold)

  return {
    intent,
    action,
    package: action !== 'write-from-scratch' ? best.name : null,
    score: best.score,
    alternatives,
    reasoning,
    warnings: allWarnings,
  }
}

function decideAction(
  bestScore: number,
  threshold: number,
): 'install' | 'caution' | 'write-from-scratch' {
  if (bestScore >= threshold) return 'install'
  if (bestScore >= threshold - 20) return 'caution'
  return 'write-from-scratch'
}

function buildReasoning(
  action: string,
  name: string,
  bestScore: number,
  threshold: number,
): string {
  switch (action) {
    case 'install':
      return `"${name}" scores ${bestScore}/100 (≥${threshold}) — safe to install`
    case 'caution':
      return `"${name}" scores ${bestScore}/100 — below threshold (${threshold}) but may be acceptable with review`
    case 'write-from-scratch':
      return `Best candidate "${name}" scores ${bestScore}/100 — too low, consider writing from scratch`
    default:
      return ''
  }
}
