import { extractContacts, lookupDmarcContacts, lookupDns, lookupSubdomains, lookupWhois, normalizeDomain } from '@/lib/recon'
import type { ReconResponse } from '@/lib/types'

export const runtime = 'nodejs'
export const maxDuration = 60

function message(reason: unknown) {
  return reason instanceof Error ? reason.message : 'Lookup failed'
}

export async function POST(request: Request) {
  const body = await request.json().catch(() => ({}))
  const domain = normalizeDomain(body?.domain)
  if (!domain) {
    return Response.json({ error: 'Please enter a valid domain, e.g. example.com' }, { status: 400 })
  }

  const [whois, subdomains, dns, dmarc] = await Promise.allSettled([
    lookupWhois(domain),
    lookupSubdomains(domain),
    lookupDns(domain),
    lookupDmarcContacts(domain),
  ])

  const whoisValue = whois.status === 'fulfilled' ? whois.value : null
  const dnsValue =
    dns.status === 'fulfilled' ? dns.value : { A: [], AAAA: [], CNAME: [], MX: [], NS: [], TXT: [], SOA: [], CAA: [] }

  const contacts = extractContacts(whoisValue, dnsValue)
  if (dmarc.status === 'fulfilled') {
    for (const c of dmarc.value) {
      if (!contacts.some((x) => x.value.toLowerCase() === c.value.toLowerCase())) contacts.push(c)
    }
  }

  const response: ReconResponse = {
    domain,
    whois: whoisValue,
    whoisError: whois.status === 'rejected' ? message(whois.reason) : null,
    subdomains: subdomains.status === 'fulfilled' ? subdomains.value : [],
    subdomainsError: subdomains.status === 'rejected' ? message(subdomains.reason) : null,
    dns: dnsValue,
    contacts,
  }
  return Response.json(response)
}
