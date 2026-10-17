import net from 'node:net'
import { promises as dns } from 'node:dns'
import type { ContactInfo, DnsRecords, WhoisInfo } from './types'

const DOMAIN_RE = /^(?=.{1,253}$)(?!-)(?:[a-z0-9-]{1,63}(?<!-)\.)+[a-z]{2,63}$/i

export function normalizeDomain(input: unknown): string | null {
  if (typeof input !== 'string') return null
  let value = input.trim().toLowerCase()
  if (!value) return null
  try {
    if (/^[a-z]+:\/\//.test(value)) value = new URL(value).hostname
  } catch {
    return null
  }
  value = value.split('/')[0].split(':')[0].replace(/^\*\./, '').replace(/^www\./, '').replace(/\.$/, '')
  return DOMAIN_RE.test(value) ? value : null
}

function whoisQuery(server: string, query: string, timeoutMs = 8000): Promise<string> {
  return new Promise((resolve, reject) => {
    let data = ''
    const socket = net.connect(43, server)
    socket.setTimeout(timeoutMs, () => {
      socket.destroy()
      reject(new Error(`WHOIS server ${server} timed out`))
    })
    socket.on('connect', () => socket.write(`${query}\r\n`))
    socket.on('data', (chunk) => {
      data += chunk.toString('utf8')
      if (data.length > 200_000) socket.destroy()
    })
    socket.on('close', () => resolve(data))
    socket.on('error', reject)
  })
}

function field(raw: string, keys: string[]): string | null {
  for (const key of keys) {
    const match = raw.match(new RegExp(`^\\s*${key}\\s*:\\s*(.+)$`, 'im'))
    const value = match?.[1]?.trim()
    if (value && !/redacted|not disclosed|data protected/i.test(value)) return value
  }
  return null
}

function fieldAll(raw: string, keys: string[]): string[] {
  const out = new Set<string>()
  for (const key of keys) {
    for (const m of raw.matchAll(new RegExp(`^\\s*${key}\\s*:\\s*(.+)$`, 'gim'))) {
      const v = m[1].trim()
      if (v) out.add(v)
    }
  }
  return [...out]
}

function parseWhois(raw: string, server: string): WhoisInfo {
  return {
    source: 'whois',
    server,
    registrar: field(raw, ['Registrar', 'Sponsoring Registrar', 'registrar name']),
    createdAt: field(raw, ['Creation Date', 'Created On', 'created', 'Registered on', 'Registration Time']),
    updatedAt: field(raw, ['Updated Date', 'Last Updated On', 'last-update', 'changed', 'Last updated']),
    expiresAt: field(raw, [
      'Registry Expiry Date',
      'Registrar Registration Expiration Date',
      'Expiration Date',
      'Expiry date',
      'paid-till',
      'expires',
    ]),
    registrant: field(raw, ['Registrant Organization', 'Registrant Name', 'Registrant', 'org']),
    country: field(raw, ['Registrant Country', 'country']),
    status: [...new Set(fieldAll(raw, ['Domain Status', 'status']).map((s) => s.split(/\s+/)[0]))].slice(0, 8),
    nameServers: [
      ...new Set(
        fieldAll(raw, ['Name Server', 'nserver', 'Nameservers'])
          .map((s) => s.split(/\s+/)[0].toLowerCase())
          .filter(Boolean),
      ),
    ].slice(0, 12),
    raw: raw.trim().slice(0, 20_000),
  }
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Json = any

async function rdapLookup(domain: string): Promise<WhoisInfo> {
  const res = await fetch(`https://rdap.org/domain/${domain}`, {
    headers: { accept: 'application/rdap+json' },
    signal: AbortSignal.timeout(10_000),
  })
  if (!res.ok) throw new Error(`RDAP lookup failed (${res.status})`)
  const data: Json = await res.json()
  const event = (action: string) => data.events?.find((e: Json) => e.eventAction === action)?.eventDate ?? null
  const entity = (role: string) => data.entities?.find((e: Json) => e.roles?.includes(role))
  const vcardValue = (ent: Json, key: string) => ent?.vcardArray?.[1]?.find((v: Json) => v[0] === key)?.[3] ?? null
  return {
    source: 'rdap',
    server: 'rdap.org',
    registrar: vcardValue(entity('registrar'), 'fn'),
    createdAt: event('registration'),
    updatedAt: event('last changed'),
    expiresAt: event('expiration'),
    registrant: vcardValue(entity('registrant'), 'org') ?? vcardValue(entity('registrant'), 'fn'),
    country: null,
    status: data.status ?? [],
    nameServers: (data.nameservers ?? []).map((n: Json) => String(n.ldhName).toLowerCase()),
    raw: JSON.stringify(data, null, 2).slice(0, 20_000),
  }
}

export async function lookupWhois(domain: string): Promise<WhoisInfo> {
  try {
    const iana = await whoisQuery('whois.iana.org', domain.split('.').pop()!)
    const tldServer = iana.match(/^\s*(?:refer|whois):\s*(\S+)/im)?.[1]
    if (!tldServer) throw new Error('No WHOIS server for TLD')

    let server = tldServer
    let raw = await whoisQuery(tldServer, tldServer.includes('verisign') ? `domain ${domain}` : domain)
    const registrarServer = raw.match(/Registrar WHOIS Server:\s*(\S+)/i)?.[1]?.replace(/^https?:\/\//, '')

    if (registrarServer && registrarServer !== tldServer) {
      const registrarRaw = await whoisQuery(registrarServer, domain).catch(() => '')
      if (registrarRaw.trim().length > 200) {
        raw = `${registrarRaw}\n\n# Registry (${tldServer})\n${raw}`
        server = registrarServer
      }
    }

    if (/no match|not found|no data found|no entries found/i.test(raw.slice(0, 500))) {
      throw new Error('Domain not found in WHOIS')
    }
    return parseWhois(raw, server)
  } catch (error) {
    try {
      return await rdapLookup(domain)
    } catch {
      throw error
    }
  }
}

export async function lookupSubdomains(domain: string): Promise<string[]> {
  const rows = await fetchCrtSh(`%.${domain}`)
  const names = new Set<string>()
  for (const row of rows) {
    for (const name of `${row.name_value ?? ''}\n${row.common_name ?? ''}`.split('\n')) {
      const clean = name.trim().toLowerCase().replace(/^\*\./, '')
      if (clean && (clean === domain || clean.endsWith(`.${domain}`)) && !clean.includes('@')) {
        names.add(clean)
      }
    }
  }
  return [...names].sort().slice(0, 1000)
}

async function fetchCrtSh(query: string): Promise<{ name_value?: string; common_name?: string }[]> {
  const attempts = 3
  let lastError: unknown
  for (let attempt = 1; attempt <= attempts; attempt++) {
    try {
      const res = await fetch(`https://crt.sh/?q=${encodeURIComponent(query)}&output=json`, {
        headers: { 'user-agent': 'security-scanner-recon/1.0' },
        signal: AbortSignal.timeout(20_000),
      })
      if (res.status === 502 || res.status === 503 || res.status === 504) {
        throw new Error(`crt.sh responded with ${res.status}`)
      }
      if (!res.ok) throw new Error(`crt.sh responded with ${res.status}`)
      return (await res.json()) as { name_value?: string; common_name?: string }[]
    } catch (error) {
      lastError = error
      if (attempt < attempts) await new Promise((r) => setTimeout(r, attempt * 2000))
    }
  }
  throw lastError instanceof Error ? lastError : new Error('crt.sh lookup failed')
}

async function safe<T>(fn: () => Promise<T>, fallback: T): Promise<T> {
  try {
    return await fn()
  } catch {
    return fallback
  }
}

export async function lookupDns(domain: string): Promise<DnsRecords> {
  const [A, AAAA, CNAME, MX, NS, TXT, SOA, CAA] = await Promise.all([
    safe(() => dns.resolve4(domain), []),
    safe(() => dns.resolve6(domain), []),
    safe(() => dns.resolveCname(domain), []),
    safe(
      async () =>
        (await dns.resolveMx(domain)).sort((a, b) => a.priority - b.priority).map((r) => `${r.priority} ${r.exchange}`),
      [],
    ),
    safe(() => dns.resolveNs(domain), []),
    safe(async () => (await dns.resolveTxt(domain)).map((parts) => parts.join('')), []),
    safe(async () => {
      const s = await dns.resolveSoa(domain)
      return [`${s.nsname} ${s.hostmaster} (serial ${s.serial})`]
    }, []),
    safe(
      async () =>
        (await dns.resolveCaa(domain)).map((r) => {
          const [tag, value] = Object.entries(r).find(([k]) => k !== 'critical') ?? ['', '']
          return `${r.critical} ${tag} "${value}"`
        }),
      [],
    ),
  ])
  return { A, AAAA, CNAME, MX, NS, TXT, SOA, CAA }
}

const EMAIL_RE = /[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/gi
const PHONE_RE = /^\s*(Registrant|Admin|Tech|Registrar Abuse Contact)\s*Phone\s*:\s*(\+?[\d.\s-]{6,})$/gim

export function extractContacts(whois: WhoisInfo | null, dnsRecords: DnsRecords): ContactInfo[] {
  const contacts = new Map<string, ContactInfo>()
  const add = (value: string, source: string) => {
    const v = value.trim().replace(/[.,;]+$/, '')
    if (v && !contacts.has(v.toLowerCase())) contacts.set(v.toLowerCase(), { value: v, source })
  }

  if (whois?.source === 'whois' && whois.raw) {
    for (const line of whois.raw.split('\n')) {
      if (/redacted|privacy|proxy|whoisguard|please query|select request/i.test(line)) continue
      const label = line.split(':')[0]?.trim() || 'WHOIS'
      for (const email of line.match(EMAIL_RE) ?? []) add(email, `WHOIS · ${label.slice(0, 40)}`)
    }
    for (const m of whois.raw.matchAll(PHONE_RE)) add(m[2], `WHOIS · ${m[1]} phone`)
  }

  for (const soa of dnsRecords.SOA) {
    const hostmaster = soa.split(' ')[1]
    if (hostmaster) {
      const [local, ...rest] = hostmaster.split('.')
      if (rest.length) add(`${local}@${rest.join('.')}`, 'DNS · SOA hostmaster')
    }
  }

  for (const txt of dnsRecords.TXT) {
    for (const email of txt.match(EMAIL_RE) ?? []) add(email, 'DNS · TXT record')
  }

  return [...contacts.values()]
}

export async function lookupDmarcContacts(domain: string): Promise<ContactInfo[]> {
  const records = await safe(async () => (await dns.resolveTxt(`_dmarc.${domain}`)).map((p) => p.join('')), [])
  const out: ContactInfo[] = []
  for (const record of records) {
    for (const m of record.matchAll(/mailto:([^,;\s!]+)/gi)) {
      out.push({ value: m[1], source: 'DNS · DMARC report' })
    }
  }
  return out
}
