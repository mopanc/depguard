/**
 * CycloneDX 1.6 TypeScript types — subset used by depguard's SBOM generator.
 *
 * Schema: https://cyclonedx.org/docs/1.6/json/
 *
 * Hand-written to keep depguard zero-dep. Only the fields we actually emit
 * are modelled; extend as new SBOM features land.
 */

export type CycloneDXSpecVersion = '1.6'

export interface CycloneDXBom {
  bomFormat: 'CycloneDX'
  specVersion: CycloneDXSpecVersion
  serialNumber: string
  version: number
  metadata?: BomMetadata
  components?: Component[]
  dependencies?: Dependency[]
  vulnerabilities?: Vulnerability[]
}

export interface BomMetadata {
  timestamp: string
  tools?: { components: ToolComponent[] }
  component?: Component
}

export interface ToolComponent {
  type: 'application'
  name: string
  version: string
  publisher?: string
  externalReferences?: ExternalReference[]
}

export type ComponentType =
  | 'application'
  | 'library'
  | 'framework'
  | 'container'
  | 'platform'
  | 'operating-system'
  | 'device'
  | 'firmware'
  | 'file'

export type ComponentScope = 'required' | 'optional' | 'excluded'

export interface Component {
  'bom-ref': string
  type: ComponentType
  name: string
  version?: string
  scope?: ComponentScope
  purl?: string
  hashes?: Hash[]
  licenses?: License[]
  description?: string
  externalReferences?: ExternalReference[]
}

export type HashAlgorithm =
  | 'MD5'
  | 'SHA-1'
  | 'SHA-256'
  | 'SHA-384'
  | 'SHA-512'
  | 'SHA3-256'
  | 'SHA3-384'
  | 'SHA3-512'
  | 'BLAKE2b-256'
  | 'BLAKE2b-384'
  | 'BLAKE2b-512'
  | 'BLAKE3'

export interface Hash {
  alg: HashAlgorithm
  content: string
}

export interface License {
  license?: { id?: string; name?: string }
  expression?: string
}

export interface ExternalReference {
  type:
    | 'website'
    | 'issue-tracker'
    | 'vcs'
    | 'documentation'
    | 'distribution'
    | 'license'
    | 'mailing-list'
    | 'social'
    | 'chat'
    | 'support'
    | 'other'
  url: string
}

export interface Dependency {
  ref: string
  dependsOn?: string[]
}

export type VulnerabilitySeverity =
  | 'critical'
  | 'high'
  | 'medium'
  | 'low'
  | 'info'
  | 'none'
  | 'unknown'

export type VulnerabilityMethod =
  | 'CVSSv2'
  | 'CVSSv3'
  | 'CVSSv31'
  | 'CVSSv4'
  | 'OWASP'
  | 'SSVC'
  | 'other'

export interface VulnerabilityRating {
  source?: { name: string; url?: string }
  score?: number
  severity?: VulnerabilitySeverity
  method?: VulnerabilityMethod
  vector?: string
}

export type AffectedStatus = 'affected' | 'unaffected' | 'unknown'

export interface VulnerabilityAffect {
  ref: string
  versions?: Array<{ version?: string; range?: string; status?: AffectedStatus }>
}

export interface Vulnerability {
  'bom-ref'?: string
  id: string
  source?: { name: string; url?: string }
  ratings?: VulnerabilityRating[]
  cwes?: number[]
  description?: string
  recommendation?: string
  affects?: VulnerabilityAffect[]
}
