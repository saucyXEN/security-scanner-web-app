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

export type Severity = 'high' | 'medium' | 'low' | 'info'

export interface Finding {
  severity: Severity
  title: string
  detail: string
}

export interface StaticAnalysis {
  status: 'completed'
  fileName: string
  size: number
  sha256: string
  md5: string
  fileType: string
  extension: string
  entropy: number
  verdict: Verdict
  score: number
  findings: Finding[]
  indicators: {
    urls: string[]
    ips: string[]
    emails: string[]
    commands: string[]
  }
  pe: {
    format: string
    machine: string
    sections: number
    packed: boolean
    subsystem: string | null
  } | null
  offline: true
}

export interface DeepScanResponse {
  analysis: StaticAnalysis
  vt: ScanResponse | null
  vtError: string | null
}

export interface OsintService {
  port: number
  transport: string
  product: string | null
  version: string | null
  banner: string | null
}

export interface OsintHost {
  ip: string
  hostnames: string[]
  org: string | null
  isp: string | null
  asn: string | null
  country: string | null
  city: string | null
  os: string | null
  ports: number[]
  services: OsintService[]
  vulns: string[]
  tags: string[]
}

export interface OsintDnsRecord {
  type: string
  value: string
  firstSeen: string | null
  lastSeen: string | null
}

export interface OsintDns {
  domain: string
  subdomains: string[]
  records: OsintDnsRecord[]
  tags: string[]
}

export interface OsintSearchMatch {
  ip: string
  port: number
  hostname: string | null
  product: string | null
  org: string | null
  country: string | null
}

export interface OsintResponse {
  target: string
  resolvedIp: string | null
  host: OsintHost | null
  dns: OsintDns | null
  search: { total: number; matches: OsintSearchMatch[]; error: string | null } | null
  errors: string[]
}

export interface PdfSection {
  heading: string
  rows?: [string, string][]
  text?: string
}

export interface PdfReportInput {
  title: string
  subtitle?: string
  sections: PdfSection[]
}
