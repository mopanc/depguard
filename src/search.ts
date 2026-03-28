import type { SearchEntry, SearchOptions } from './types.js'
import { searchPackages } from './registry.js'

/**
 * Search npm for packages matching keywords, sorted by quality score.
 * Results can be filtered by minimum score and license compatibility.
 */
export async function search(
  keywords: string,
  options: SearchOptions = {},
): Promise<SearchEntry[]> {
  const {
    limit = 10,
    minScore = 0,
    fetcher = globalThis.fetch,
  } = options

  const result = await searchPackages(keywords, Math.min(limit * 2, 50), fetcher)

  const entries: SearchEntry[] = result.objects.map(obj => ({
    name: obj.package.name,
    version: obj.package.version,
    description: obj.package.description ?? '',
    score: Math.min(100, Math.round((obj.score.final > 1 ? obj.score.final : obj.score.final * 100))),
    keywords: obj.package.keywords ?? [],
    date: obj.package.date,
  }))

  return entries
    .filter(e => e.score >= minScore)
    .sort((a, b) => b.score - a.score)
    .slice(0, limit)
}
