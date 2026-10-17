'use client'

import { useMemo, useState, type FormEvent } from 'react'
import useSWRMutation from 'swr/mutation'
import { AtSign, Copy, Check, Fingerprint, Globe2, Loader2, Network, Radar, Server } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Skeleton } from '@/components/ui/skeleton'
import { postJson } from '@/lib/api-client'
import type { DnsRecords, ReconResponse, WhoisInfo } from '@/lib/types'
import { EmptyState, ErrorState } from './status-states'

export function ReconPanel() {
  const [domain, setDomain] = useState('')
  const { trigger, data, error, isMutating } = useSWRMutation('/api/recon', postJson<ReconResponse>)

  const onSubmit = (e: FormEvent) => {
    e.preventDefault()
    if (domain.trim()) trigger({ domain: domain.trim() }).catch(() => {})
  }

  return (
    <div className="flex flex-col gap-6">
      <form onSubmit={onSubmit} className="flex flex-col gap-3 sm:flex-row">
        <label htmlFor="domain-input" className="sr-only">
          Domain
        </label>
        <div className="relative flex-1">
          <Globe2 className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" aria-hidden="true" />
          <Input
            id="domain-input"
            type="text"
            autoComplete="off"
            spellCheck={false}
            placeholder="example.com"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            className="h-11 pl-9 font-mono text-sm"
          />
        </div>
        <Button type="submit" className="h-11 px-5 font-mono text-xs uppercase tracking-[0.2em] shadow-hard-sm transition-transform hover:-translate-y-0.5" disabled={isMutating || !domain.trim()}>
          {isMutating ? <Loader2 className="animate-spin" /> : <Radar />}
          Run recon
        </Button>
      </form>

      {error ? (
        <ErrorState message={error.message} />
      ) : isMutating ? (
        <ReconSkeleton />
      ) : data ? (
        <ReconResults data={data} />
      ) : (
        <EmptyState
          icon={Radar}
          title="Map a domain's attack surface"
          description="Enter a domain to pull WHOIS registration data, certificate-transparency subdomains from crt.sh, DNS records and public contacts."
        />
      )}
    </div>
  )
}

function ReconSkeleton() {
  return (
    <div className="grid gap-4 lg:grid-cols-2" role="status" aria-label="Running recon">
      {[0, 1, 2, 3].map((i) => (
        <Card key={i}>
          <CardHeader>
            <Skeleton className="h-4 w-32" />
          </CardHeader>
          <CardContent className="flex flex-col gap-2">
            <Skeleton className="h-3 w-full" />
            <Skeleton className="h-3 w-4/5" />
            <Skeleton className="h-3 w-3/5" />
          </CardContent>
        </Card>
      ))}
    </div>
  )
}

function ReconResults({ data }: { data: ReconResponse }) {
  return (
    <div className="flex flex-col gap-4">
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <Metric label="Domain" value={data.domain} mono />
        <Metric label="Subdomains" value={String(data.subdomains.length)} />
        <Metric label="IPv4 addresses" value={String(data.dns.A.length)} />
        <Metric label="Contacts found" value={String(data.contacts.length)} />
      </div>
      <div className="grid gap-4 lg:grid-cols-2">
        <WhoisCard whois={data.whois} error={data.whoisError} />
        <ContactsCard contacts={data.contacts} />
        <DnsCard dns={data.dns} />
        <SubdomainsCard subdomains={data.subdomains} error={data.subdomainsError} />
      </div>
    </div>
  )
}

function Metric({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <Card size="sm">
      <CardContent className="flex min-w-0 flex-col gap-1">
        <span className="text-xs uppercase tracking-wide text-muted-foreground">{label}</span>
        <span className={mono ? 'truncate font-mono text-base font-semibold' : 'font-mono text-2xl font-semibold tabular-nums'}>
          {value}
        </span>
      </CardContent>
    </Card>
  )
}

function SectionTitle({ icon: Icon, children }: { icon: typeof Server; children: React.ReactNode }) {
  return (
    <CardTitle className="flex items-center gap-2">
      <Icon className="size-4 text-primary" aria-hidden="true" />
      {children}
    </CardTitle>
  )
}

function formatDate(value: string | null) {
  if (!value) return null
  const d = new Date(value)
  return Number.isNaN(d.getTime()) ? value : d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' })
}

function WhoisCard({ whois, error }: { whois: WhoisInfo | null; error: string | null }) {
  const [showRaw, setShowRaw] = useState(false)
  const rows = whois
    ? [
        ['Registrar', whois.registrar],
        ['Registrant', whois.registrant],
        ['Country', whois.country],
        ['Created', formatDate(whois.createdAt)],
        ['Updated', formatDate(whois.updatedAt)],
        ['Expires', formatDate(whois.expiresAt)],
      ].filter((r): r is [string, string] => !!r[1])
    : []

  return (
    <Card>
      <CardHeader>
        <SectionTitle icon={Fingerprint}>WHOIS</SectionTitle>
        {whois?.server && (
          <CardDescription>
            via {whois.source.toUpperCase()} · {whois.server}
          </CardDescription>
        )}
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        {!whois ? (
          <p className="text-sm text-muted-foreground">{error ?? 'No WHOIS data available.'}</p>
        ) : (
          <>
            <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-2 text-sm">
              {rows.map(([k, v]) => (
                <div key={k} className="contents">
                  <dt className="text-muted-foreground">{k}</dt>
                  <dd className="break-words">{v}</dd>
                </div>
              ))}
            </dl>
            {whois.nameServers.length > 0 && <TagGroup label="Name servers" items={whois.nameServers} />}
            {whois.status.length > 0 && <TagGroup label="Status" items={whois.status} />}
            {whois.raw && (
              <div>
                <Button variant="ghost" size="sm" onClick={() => setShowRaw((v) => !v)} aria-expanded={showRaw}>
                  {showRaw ? 'Hide raw record' : 'Show raw record'}
                </Button>
                {showRaw && (
                  <pre className="mt-2 max-h-72 overflow-auto rounded-lg bg-background p-3 font-mono text-xs leading-relaxed text-muted-foreground">
                    {whois.raw}
                  </pre>
                )}
              </div>
            )}
          </>
        )}
      </CardContent>
    </Card>
  )
}

function TagGroup({ label, items }: { label: string; items: string[] }) {
  return (
    <div className="flex flex-col gap-1.5">
      <span className="text-xs uppercase tracking-wide text-muted-foreground">{label}</span>
      <div className="flex flex-wrap gap-1.5">
        {items.map((i) => (
          <span key={i} className="rounded-md bg-secondary px-2 py-0.5 font-mono text-xs">
            {i}
          </span>
        ))}
      </div>
    </div>
  )
}

function ContactsCard({ contacts }: { contacts: ReconResponse['contacts'] }) {
  return (
    <Card>
      <CardHeader>
        <SectionTitle icon={AtSign}>Email & contacts</SectionTitle>
        <CardDescription>Extracted from WHOIS, SOA and DMARC/TXT records</CardDescription>
      </CardHeader>
      <CardContent>
        {contacts.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            No public contacts found. The registrant is likely using WHOIS privacy protection.
          </p>
        ) : (
          <ul className="flex flex-col divide-y divide-border">
            {contacts.map((c) => (
              <li key={c.value} className="flex items-center justify-between gap-3 py-2">
                <div className="min-w-0">
                  <p className="truncate font-mono text-sm">{c.value}</p>
                  <p className="text-xs text-muted-foreground">{c.source}</p>
                </div>
                <CopyButton value={c.value} />
              </li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  )
}

const DNS_ORDER: (keyof DnsRecords)[] = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'CAA']

function DnsCard({ dns }: { dns: DnsRecords }) {
  const populated = DNS_ORDER.filter((t) => dns[t].length > 0)
  return (
    <Card>
      <CardHeader>
        <SectionTitle icon={Server}>DNS records</SectionTitle>
      </CardHeader>
      <CardContent>
        {populated.length === 0 ? (
          <p className="text-sm text-muted-foreground">No DNS records resolved for this domain.</p>
        ) : (
          <div className="flex flex-col gap-3">
            {populated.map((type) => (
              <div key={type} className="grid grid-cols-[3.5rem_1fr] gap-3">
                <span className="mt-0.5 h-fit rounded-md bg-primary/10 px-1.5 py-0.5 text-center font-mono text-xs font-semibold text-primary">
                  {type}
                </span>
                <ul className="flex min-w-0 flex-col gap-1">
                  {dns[type].map((v, idx) => (
                    <li key={`${idx}-${v}`} className="break-all font-mono text-xs leading-relaxed">
                      {v}
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  )
}

function SubdomainsCard({ subdomains, error }: { subdomains: string[]; error: string | null }) {
  const [filter, setFilter] = useState('')
  const filtered = useMemo(() => {
    const q = filter.trim().toLowerCase()
    return q ? subdomains.filter((s) => s.includes(q)) : subdomains
  }, [filter, subdomains])

  return (
    <Card>
      <CardHeader>
        <SectionTitle icon={Network}>Subdomains</SectionTitle>
        <CardDescription>From certificate transparency logs (crt.sh)</CardDescription>
        {subdomains.length > 0 && (
          <CardAction>
            <CopyButton value={subdomains.join('\n')} label="Copy all subdomains" />
          </CardAction>
        )}
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        {error && subdomains.length === 0 ? (
          <p className="text-sm text-muted-foreground">crt.sh lookup failed: {error}. crt.sh is often overloaded — try again shortly.</p>
        ) : subdomains.length === 0 ? (
          <p className="text-sm text-muted-foreground">No subdomains found in certificate logs.</p>
        ) : (
          <>
            <label htmlFor="subdomain-filter" className="sr-only">
              Filter subdomains
            </label>
            <Input
              id="subdomain-filter"
              placeholder={`Filter ${subdomains.length} subdomains…`}
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              className="font-mono text-xs"
            />
            <ul className="max-h-80 overflow-auto rounded-lg bg-background p-2">
              {filtered.map((s) => (
                <li key={s} className="truncate rounded px-2 py-1 font-mono text-xs hover:bg-secondary">
                  {s}
                </li>
              ))}
              {filtered.length === 0 && <li className="px-2 py-1 text-xs text-muted-foreground">No matches</li>}
            </ul>
          </>
        )}
      </CardContent>
    </Card>
  )
}

function CopyButton({ value, label = 'Copy' }: { value: string; label?: string }) {
  const [copied, setCopied] = useState(false)
  return (
    <Button
      variant="ghost"
      size="icon"
      aria-label={label}
      onClick={() => {
        navigator.clipboard.writeText(value).then(() => {
          setCopied(true)
          setTimeout(() => setCopied(false), 1500)
        })
      }}
    >
      {copied ? <Check className="text-safe" /> : <Copy />}
    </Button>
  )
}
