import type { LicenseCompatibility } from './types.js'

/**
 * License categories from most to least permissive.
 * Permissive licenses are compatible with everything at their level or above.
 */
const LICENSE_CATEGORIES: Record<string, number> = {
  // Public domain / ultra-permissive
  'Unlicense': 0,
  'CC0-1.0': 0,
  '0BSD': 0,

  // Permissive
  'MIT': 1,
  'ISC': 1,
  'BSD-2-Clause': 1,
  'BSD-3-Clause': 1,
  'Apache-2.0': 1,
  'Zlib': 1,

  // Weak copyleft
  'LGPL-2.1': 2,
  'LGPL-2.1-only': 2,
  'LGPL-2.1-or-later': 2,
  'LGPL-3.0': 2,
  'LGPL-3.0-only': 2,
  'LGPL-3.0-or-later': 2,
  'MPL-2.0': 2,
  'EPL-2.0': 2,

  // Strong copyleft
  'GPL-2.0': 3,
  'GPL-2.0-only': 3,
  'GPL-2.0-or-later': 3,
  'GPL-3.0': 3,
  'GPL-3.0-only': 3,
  'GPL-3.0-or-later': 3,

  // Network copyleft
  'AGPL-3.0': 4,
  'AGPL-3.0-only': 4,
  'AGPL-3.0-or-later': 4,
}

/** Normalize common license strings to SPDX identifiers */
function normalizeLicense(raw: string): string {
  const trimmed = raw.trim()

  const aliases: Record<string, string> = {
    'MIT': 'MIT',
    'ISC': 'ISC',
    'BSD': 'BSD-2-Clause',
    'BSD-2': 'BSD-2-Clause',
    'BSD-3': 'BSD-3-Clause',
    'Apache 2.0': 'Apache-2.0',
    'Apache2': 'Apache-2.0',
    'Apache-2': 'Apache-2.0',
    'GPL-2': 'GPL-2.0',
    'GPL-3': 'GPL-3.0',
    'LGPL-2': 'LGPL-2.1',
    'LGPL-3': 'LGPL-3.0',
    'AGPL-3': 'AGPL-3.0',
    'MPL 2.0': 'MPL-2.0',
    'Unlicense': 'Unlicense',
    'UNLICENSED': 'UNLICENSED',
  }

  // Try direct match first (case-sensitive for SPDX)
  if (trimmed in LICENSE_CATEGORIES) return trimmed

  // Try case-insensitive alias match
  const upper = trimmed.toUpperCase()
  for (const [alias, spdx] of Object.entries(aliases)) {
    if (alias.toUpperCase() === upper) return spdx
  }

  return trimmed
}

/**
 * Check if a dependency's license is compatible with the project's target license.
 *
 * Rule: a dependency can be used if its license is equally or more permissive
 * than the target. Strong copyleft (GPL) deps cannot be used in permissive projects.
 */
export function checkLicenseCompatibility(
  depLicense: string | null | undefined,
  targetLicense: string,
): LicenseCompatibility {
  if (!depLicense) {
    return {
      compatible: false,
      license: null,
      targetLicense,
      reason: 'No license specified — cannot determine compatibility',
    }
  }

  const normalizedDep = normalizeLicense(depLicense)
  const normalizedTarget = normalizeLicense(targetLicense)

  if (normalizedDep === 'UNLICENSED') {
    return {
      compatible: false,
      license: normalizedDep,
      targetLicense: normalizedTarget,
      reason: 'Package is UNLICENSED — not safe for any project',
    }
  }

  const depCategory = LICENSE_CATEGORIES[normalizedDep]
  const targetCategory = LICENSE_CATEGORIES[normalizedTarget]

  if (depCategory === undefined) {
    return {
      compatible: false,
      license: normalizedDep,
      targetLicense: normalizedTarget,
      reason: `Unknown license "${normalizedDep}" — manual review required`,
    }
  }

  if (targetCategory === undefined) {
    return {
      compatible: false,
      license: normalizedDep,
      targetLicense: normalizedTarget,
      reason: `Unknown target license "${normalizedTarget}" — manual review required`,
    }
  }

  // Dependency must be equally or more permissive (lower or equal category)
  if (depCategory <= targetCategory) {
    return {
      compatible: true,
      license: normalizedDep,
      targetLicense: normalizedTarget,
      reason: `"${normalizedDep}" is compatible with "${normalizedTarget}"`,
    }
  }

  return {
    compatible: false,
    license: normalizedDep,
    targetLicense: normalizedTarget,
    reason: `"${normalizedDep}" is more restrictive than "${normalizedTarget}"`,
  }
}

/** Get all known license identifiers */
export function knownLicenses(): string[] {
  return Object.keys(LICENSE_CATEGORIES)
}
