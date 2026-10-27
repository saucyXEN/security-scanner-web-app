import { promises as dns } from 'node:dns'
import net from 'node:net'
import type { OsintDns, OsintHost, OsintResponse, OsintSearchMatch, OsintService } from './types'

const SHODAN_BASE = 'https://api.shodan.io'

export class OsintError extends Error {
  constructor(
    message: string,
    public status: number,
  ) {
    super(message)
  }
}

export function shodanKey() {
  return process.env.SHODAN_API_KEY?.trim() || null
}

export function normalizeTarget(input: unknown): { kind: 'ip' | 'domain'; value: string } | null {
  if (typeof input !== 'string') return null
  const value = input.trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0].split(':')[0]
  if (!value) return null
  if (net.isIP(value)) return { kind: 'ip', value }
  if (/^(?=.{1,253}$)(?!-)(?:[a-z0-9-]{1,63}(?<!-)\.)+[a-z]{2,63}$/.test(value)) return { kind: 'domain', value }
  return null
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Json = any

async function shodanFetch<T>(path: string): Promise<T> {
  const key = shodanKey()
  if (!key) {
    throw new OsintError('Shodan API key is not configured on the server (SHODAN_API_KEY).', 500)
  }

  let response: Response
  try {
    response = await fetch(`${SHODAN_BASE}${path}${path.includes('?') ? '&' : '?'}key=${encodeURIComponent(key)}`, {
      headers: { accept: 'application/json' },
      cache: 'no-store',
      signal: AbortSignal.timeout(20_000),
    })
  } catch {
    throw new OsintError('Could not reach Shodan. Check the server network connection.', 502)
  }

  const body = (await response.json().catch(() => null)) as Json
  if (response.ok) return body as T

  if (response.status === 401) throw new OsintError('Shodan rejected the API key.', 502)
  if (response.status === 403) {
    throw new OsintError(body?.error ?? 'This Shodan endpoint needs a paid API plan.', 403)
  }
  if (response.status === 404) throw new OsintError('Shodan has no information for this target.', 404)
  if (response.status === 429) throw new OsintError('Shodan rate limit reached. Try again in a minute.', 429)
  throw new OsintError(body?.error ?? `Shodan request failed (${response.status}).`, 502)
}

function hostFrom(body: Json, fallbackIp: string): OsintHost {
  const services: OsintService[] = Array.isArray(body?.data)
    ? body.data.slice(0, 50).map((entry: Json) => ({
        port: entry?.port ?? 0,
        transport: entry?.transport ?? 'tcp',
        product: entry?.product ?? null,
        version: entry?.version ?? null,
        banner: typeof entry?.data === 'string' ? entry.data.replace(/\s+/g, ' ').trim().slice(0, 300) : null,
      }))
    : []

  return {
    ip: body?.ip_str ?? fallbackIp,
    hostnames: body?.hostnames ?? [],
    org: body?.org ?? null,
    isp: body?.isp ?? null,
    asn: body?.asn ?? null,
    country: body?.country_name ?? null,
    city: body?.city ?? null,
    os: body?.os ?? null,
    ports: [...new Set<number>(body?.ports ?? services.map((s) => s.port))].sort((a, b) => a - b),
    services,
    vulns: Object.keys(body?.vulns ?? {}).slice(0, 50),
    tags: body?.tags ?? [],
  }
}

function dnsFrom(body: Json, domain: string): OsintDns {
  const rows: Json[] = Array.isArray(body?.data) ? body.data : []
  return {
    domain: body?.domain ?? domain,
    subdomains: [...new Set<string>(rows.map((row) => String(row?.subdomain ?? '')).filter(Boolean))].sort().slice(0, 500),
    records: rows.slice(0, 500).map((row) => ({
      type: String(row?.type ?? ''),
      value: String(row?.value ?? ''),
      firstSeen: row?.first_seen ?? null,
      lastSeen: row?.last_seen ?? null,
    })),
    tags: body?.tags ?? [],
  }
}

async function searchShodan(
  target: { kind: 'ip' | 'domain'; value: string },
): Promise<OsintResponse['search']> {
  const query = target.kind === 'ip' ? `ip:${target.value}` : `hostname:${target.value}`
  try {
    const body = await shodanFetch<Json>(
      `/shodan/host/search?query=${encodeURIComponent(query)}&minify=true`,
    )
    const matches: OsintSearchMatch[] = (Array.isArray(body?.matches) ? body.matches : [])
      .slice(0, 25)
      .map((match: Json) => ({
        ip: String(match?.ip_str ?? ''),
        port: Number(match?.port ?? 0),
        hostname: match?.hostnames?.[0] ?? null,
        product: match?.product ?? null,
        org: match?.org ?? null,
        country: match?.location?.country_name ?? null,
      }))
    return { total: Number(body?.total ?? matches.length), matches, error: null }
  } catch (error) {
    return {
      total: 0,
      matches: [],
      error: error instanceof Error ? error.message : 'Shodan deep search failed.',
    }
  }
}

export async function deepSearch(target: { kind: 'ip' | 'domain'; value: string }): Promise<OsintResponse> {
  const errors: string[] = []
  let ip: string | null = target.kind === 'ip' ? target.value : null

  if (target.kind === 'domain') {
    try {
      ip = (await dns.lookup(target.value, { family: 4 })).address
    } catch {
      errors.push(`Could not resolve ${target.value} to an IPv4 address.`)
    }
  }

  const message = (error: unknown) => (error instanceof Error ? error.message : 'Lookup failed')

  const [host, dnsInfo, search] = await Promise.all([
    ip
      ? shodanFetch<Json>(`/shodan/host/${encodeURIComponent(ip)}`)
          .then((body) => hostFrom(body, ip as string))
          .catch((error) => {
            errors.push(message(error))
            return null
          })
      : Promise.resolve(null),
    target.kind === 'domain'
      ? shodanFetch<Json>(`/dns/domain/${encodeURIComponent(target.value)}`)
          .then((body) => dnsFrom(body, target.value))
          .catch((error) => {
            errors.push(message(error))
            return null
          })
      : Promise.resolve(null),
    searchShodan(target),
  ])

  return { target: target.value, resolvedIp: ip, host, dns: dnsInfo, search, errors }
}
