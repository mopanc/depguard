/**
 * Token savings estimator for depguard MCP tools.
 *
 * Estimates how many tokens an LLM agent would spend doing the equivalent
 * research manually (WebSearch, WebFetch, reasoning) vs the compact JSON
 * that depguard returns.
 *
 * Estimates are conservative and based on typical Claude Code tool-call patterns.
 */

export interface TokenSavings {
  /** Tokens in the depguard response */
  responseTokens: number
  /** Estimated tokens for the equivalent manual approach */
  manualEstimate: number
  /** Tokens saved (manualEstimate - responseTokens) */
  saved: number
  /** Percentage saved */
  percentSaved: number
  /** Breakdown of what the manual approach would involve */
  manualSteps: string[]
}

/**
 * Rough token count: ~1 token per 4 characters for JSON/English text.
 */
export function estimateTokens(text: string): number {
  return Math.ceil(text.length / 4)
}

/** Average tokens per manual step, based on observed Claude Code patterns */
const MANUAL_COST = {
  webSearch: 800,       // search query + parsing results page
  webFetch: 3000,       // fetching and reading a full web page (README, npm page)
  webFetchLarge: 5000,  // fetching a large page (GitHub issues, changelogs)
  reasoning: 500,       // agent reasoning/comparison between steps
} as const

interface ManualProfile {
  steps: string[]
  tokens: number
}

/**
 * Estimate the manual cost for each depguard tool.
 */
function manualProfileFor(tool: string, argCount: number): ManualProfile {
  switch (tool) {
    case 'depguard_audit':
      return {
        steps: [
          `WebSearch: "npm {package} vulnerabilities security" (~${MANUAL_COST.webSearch} tokens)`,
          `WebFetch: npm registry page for package metadata (~${MANUAL_COST.webFetch} tokens)`,
          `WebFetch: GitHub advisories page (~${MANUAL_COST.webFetch} tokens)`,
          `WebSearch: "{package} npm license" (~${MANUAL_COST.webSearch} tokens)`,
          `WebFetch: package.json or npm page for dependency list (~${MANUAL_COST.webFetch} tokens)`,
          `Reasoning: analyze and summarize findings (~${MANUAL_COST.reasoning} tokens)`,
        ],
        tokens: MANUAL_COST.webSearch * 2 + MANUAL_COST.webFetch * 3 + MANUAL_COST.reasoning,
      }

    case 'depguard_score':
      // Score requires an internal audit + scoring computation
      return {
        steps: [
          `WebSearch: "{package} npm quality maintenance" (~${MANUAL_COST.webSearch} tokens)`,
          `WebFetch: npm registry page (~${MANUAL_COST.webFetch} tokens)`,
          `WebFetch: GitHub repo for activity/stars (~${MANUAL_COST.webFetch} tokens)`,
          `WebSearch: "{package} vulnerabilities" (~${MANUAL_COST.webSearch} tokens)`,
          `WebFetch: advisories page (~${MANUAL_COST.webFetch} tokens)`,
          `Reasoning: compute weighted score across dimensions (~${MANUAL_COST.reasoning} tokens)`,
        ],
        tokens: MANUAL_COST.webSearch * 2 + MANUAL_COST.webFetch * 3 + MANUAL_COST.reasoning,
      }

    case 'depguard_search':
      return {
        steps: [
          `WebSearch: "best npm packages for {keywords}" (~${MANUAL_COST.webSearch} tokens)`,
          `WebFetch: blog post or comparison article (~${MANUAL_COST.webFetchLarge} tokens)`,
          `WebSearch: "npm {keywords} most downloaded" (~${MANUAL_COST.webSearch} tokens)`,
          `Reasoning: filter and rank results (~${MANUAL_COST.reasoning} tokens)`,
        ],
        tokens: MANUAL_COST.webSearch * 2 + MANUAL_COST.webFetchLarge + MANUAL_COST.reasoning,
      }

    case 'depguard_should_use': {
      // shouldUse = search + score N packages + reasoning
      const candidateCount = argCount || 5
      const perCandidate = MANUAL_COST.webSearch + MANUAL_COST.webFetch * 2 + MANUAL_COST.reasoning
      return {
        steps: [
          `WebSearch: "best npm packages for {intent}" (~${MANUAL_COST.webSearch} tokens)`,
          `WebFetch: comparison article (~${MANUAL_COST.webFetchLarge} tokens)`,
          `${candidateCount}x audit per candidate: WebSearch + 2x WebFetch + reasoning each (~${perCandidate * candidateCount} tokens)`,
          `Reasoning: compare all candidates and decide install vs write-from-scratch (~${MANUAL_COST.reasoning * 2} tokens)`,
        ],
        tokens:
          MANUAL_COST.webSearch + MANUAL_COST.webFetchLarge +
          perCandidate * candidateCount +
          MANUAL_COST.reasoning * 2,
      }
    }

    default:
      return { steps: ['Unknown tool'], tokens: MANUAL_COST.webSearch }
  }
}

/**
 * Calculate token savings for a depguard tool call.
 *
 * @param tool - The tool name (e.g. "depguard_audit")
 * @param responseJson - The JSON string of the response
 * @param argCount - Number of items processed (for should_use: candidate count)
 */
export function calculateSavings(
  tool: string,
  responseJson: string,
  argCount = 5,
): TokenSavings {
  const responseTokens = estimateTokens(responseJson)
  const profile = manualProfileFor(tool, argCount)
  const saved = Math.max(0, profile.tokens - responseTokens)
  const percentSaved = profile.tokens > 0
    ? Math.round((saved / profile.tokens) * 100)
    : 0

  return {
    responseTokens,
    manualEstimate: profile.tokens,
    saved,
    percentSaved,
    manualSteps: profile.steps,
  }
}
