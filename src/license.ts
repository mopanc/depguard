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
  'WTFPL': 0,

  // Permissive
  'MIT': 1,
  'ISC': 1,
  'BSD-2-Clause': 1,
  'BSD-3-Clause': 1,
  'Apache-2.0': 1,
  'Zlib': 1,
  'BSL-1.0': 1,   // Boost Software License
  'PSF-2.0': 1,   // Python Software Foundation
  'CC-BY-4.0': 1, // Creative Commons Attribution

  // Weak copyleft
  'LGPL-2.1': 2,
  'LGPL-2.1-only': 2,
  'LGPL-2.1-or-later': 2,
  'LGPL-3.0': 2,
  'LGPL-3.0-only': 2,
  'LGPL-3.0-or-later': 2,
  'MPL-2.0': 2,
  'EPL-2.0': 2,
  'CC-BY-SA-4.0': 2, // Creative Commons ShareAlike
  'OSL-3.0': 2,      // Open Software License

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

  // Source-available / restrictive (not open source — incompatible with most projects)
  'SSPL-1.0': 5,         // Server Side Public License (MongoDB)
  'Elastic-2.0': 5,      // Elastic License
  'BUSL-1.1': 5,         // Business Source License (HashiCorp)
  'Commons-Clause': 5,   // Commons Clause (restricts commercial use)
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

  const normalizedTarget = normalizeLicense(targetLicense)

  // Handle dual/compound licenses: "MIT OR GPL-3.0", "(MIT OR Apache-2.0)"
  const cleanLicense = depLicense.replace(/[()]/g, '').trim()
  if (cleanLicense.includes(' OR ')) {
    const options = cleanLicense.split(/\s+OR\s+/i)
    // With OR, the package offers a choice — compatible if ANY option is compatible
    for (const option of options) {
      const result = checkLicenseCompatibility(option.trim(), targetLicense)
      if (result.compatible) {
        return {
          ...result,
          license: cleanLicense,
          reason: `"${option.trim()}" (from "${cleanLicense}") is compatible with "${normalizedTarget}"`,
        }
      }
    }
    return {
      compatible: false,
      license: cleanLicense,
      targetLicense: normalizedTarget,
      reason: `None of the license options in "${cleanLicense}" are compatible with "${normalizedTarget}"`,
    }
  }

  if (cleanLicense.includes(' AND ')) {
    const parts = cleanLicense.split(/\s+AND\s+/i)
    // With AND, ALL licenses must be compatible
    for (const part of parts) {
      const result = checkLicenseCompatibility(part.trim(), targetLicense)
      if (!result.compatible) {
        return {
          ...result,
          license: cleanLicense,
          reason: `"${part.trim()}" (from "${cleanLicense}") is not compatible with "${normalizedTarget}"`,
        }
      }
    }
    return {
      compatible: true,
      license: cleanLicense,
      targetLicense: normalizedTarget,
      reason: `All licenses in "${cleanLicense}" are compatible with "${normalizedTarget}"`,
    }
  }

  const normalizedDep = normalizeLicense(depLicense)

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
