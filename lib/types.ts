export type Verdict = 'malicious' | 'suspicious' | 'safe'

export interface ScanStats {
  malicious: number
  suspicious: number
  harmless: number
  undetected: number
  timeout: number
}

export interface EngineResult {
  engine: string
  category: string
  result: string | null
}

export interface DetailItem {
  label: string
  value: string
}

export type ScanResponse =
  | { status: 'queued'; analysisId: string }
  | {
      status: 'completed'
      verdict: Verdict
      stats: ScanStats
      engines: EngineResult[]
      details: DetailItem[]
      scannedAt: string | null
      permalink: string | null
    }

export interface WhoisInfo {
  source: 'whois' | 'rdap'
  server: string | null
  registrar: string | null
  createdAt: string | null
  updatedAt: string | null
  expiresAt: string | null
  registrant: string | null
  country: string | null
  status: string[]
  nameServers: string[]
  raw: string | null
}

export interface DnsRecords {
  A: string[]
  AAAA: string[]
  CNAME: string[]
  MX: string[]
  NS: string[]
  TXT: string[]
  SOA: string[]
  CAA: string[]
}

export interface ContactInfo {
  value: string
  source: string
}

export interface ReconResponse {
  domain: string
  whois: WhoisInfo | null
  whoisError: string | null
  subdomains: string[]
  subdomainsError: string | null
  dns: DnsRecords
  contacts: ContactInfo[]
}
