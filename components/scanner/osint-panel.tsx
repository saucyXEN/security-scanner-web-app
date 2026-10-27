'use client'

import { useState, type FormEvent } from 'react'
import useSWRMutation from 'swr/mutation'
import {
  AlertTriangle,
  Crosshair,
  ExternalLink,
  Globe2,
  Loader2,
  Network,
  Radar,
  ScanSearch,
  Server,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardAction, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { cn } from '@/lib/utils'
import { postJson } from '@/lib/api-client'
import { osintPdfReport } from '@/lib/report'
import type { OsintResponse } from '@/lib/types'
import { PdfButton } from './pdf-button'
import { EmptyState, ErrorState, PendingState } from './status-states'

export function OsintPanel() {
  const [target, setTarget] = useState('')
  const [lastTarget, setLastTarget] = useState('')
  const { trigger, data, error, isMutating } = useSWRMutation('/api/osint', postJson<OsintResponse>)

  const onSubmit = (event: FormEvent) => {
    event.preventDefault()
    const value = target.trim()
    if (!value) return
    setLastTarget(value)
    trigger({ target: value }).catch(() => {})
  }

  return (
    <div className="flex flex-col gap-6">
      <form onSubmit={onSubmit} className="flex flex-col gap-3 sm:flex-row">
        <label htmlFor="osint-input" className="sr-only">
          IP address or domain
        </label>
        <div className="relative flex-1">
          <Crosshair
            className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground"
            aria-hidden="true"
          />
          <Input
            id="osint-input"
            type="text"
            autoComplete="off"
            spellCheck={false}
            placeholder="8.8.8.8 or example.com"
            value={target}
            onChange={(event) => setTarget(event.target.value)}
            className="h-11 pl-9 font-mono text-sm"
          />
        </div>
        <Button
          type="submit"
          className="h-11 px-5 font-mono text-xs uppercase tracking-[0.2em] shadow-hard-sm transition-transform hover:-translate-y-0.5"
          disabled={isMutating || !target.trim()}
        >
          {isMutating ? <Loader2 className="animate-spin" /> : <ScanSearch />}
          Deep search
        </Button>
      </form>

      {error ? (
        <ErrorState message={error.message} />
      ) : isMutating ? (
        <PendingState
          title="Querying Shodan…"
          description="Host intelligence, DNS records, subdomains and the deep-search index are fetched in parallel."
        />
      ) : data ? (
        <OsintResults data={data} target={lastTarget} />
      ) : (
        <EmptyState
          icon={Radar}
          title="Shodan-powered OSINT"
          description="Look up any IP or domain for open ports, exposed services, known CVEs, subdomains and matching services across the internet."
        />
      )}
    </div>
  )
}

function OsintResults({ data, target }: { data: OsintResponse; target: string }) {
  const host = data.host
  const dns = data.dns
  const search = data.search
  const shodanHost = host?.ip ?? data.resolvedIp

  return (
    <div className="flex flex-col gap-4">
      <Card>
        <CardHeader>
          <CardTitle className="flex flex-wrap items-center gap-2">
            <Globe2 className="size-4 text-muted-foreground" aria-hidden="true" />
            {data.target}
            {data.resolvedIp && data.resolvedIp !== data.target && (
              <span className="font-mono text-xs font-normal text-muted-foreground">→ {data.resolvedIp}</span>
            )}
          </CardTitle>
          <CardAction>
            <div className="flex flex-wrap items-center justify-end gap-2">
              {shodanHost && (
                <Button
                  variant="ghost"
                  size="sm"
                  nativeButton={false}
                  render={
                    <a
                      href={`https://www.shodan.io/host/${encodeURIComponent(shodanHost)}`}
                      target="_blank"
                      rel="noopener noreferrer"
                    />
                  }
                >
                  <ExternalLink />
                  Shodan
                </Button>
              )}
              <PdfButton report={osintPdfReport(data)} fileName={`hackerade-osint-${target || data.target}.pdf`} />
            </div>
          </CardAction>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          {host ? (
            <>
              <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
                <Field label="Organisation" value={host.org ?? 'unknown'} />
                <Field label="ISP" value={host.isp ?? 'unknown'} />
                <Field label="ASN" value={host.asn ?? 'unknown'} />
                <Field label="Location" value={[host.city, host.country].filter(Boolean).join(', ') || 'unknown'} />
              </div>
              <div className="flex flex-col gap-2">
                <p className="text-[10px] uppercase tracking-[0.12em] text-muted-foreground">
                  Open ports ({host.ports.length})
                </p>
                <div className="flex flex-wrap gap-1.5">
                  {host.ports.slice(0, 40).map((port) => (
                    <span key={port} className="rounded-sm bg-secondary px-2 py-1 font-mono text-xs">
                      {port}
                    </span>
                  ))}
                  {host.ports.length === 0 && <span className="text-sm text-muted-foreground">No open ports reported.</span>}
                </div>
              </div>
              {host.vulns.length > 0 && (
                <div className="flex flex-col gap-2">
                  <p className="flex items-center gap-1.5 text-[10px] uppercase tracking-[0.12em] text-malicious">
                    <AlertTriangle className="size-3.5" aria-hidden="true" />
                    Known CVEs ({host.vulns.length})
                  </p>
                  <div className="flex flex-wrap gap-1.5">
                    {host.vulns.slice(0, 24).map((vuln) => (
                      <a
                        key={vuln}
                        href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(vuln)}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="rounded-sm bg-malicious/10 px-2 py-1 font-mono text-xs text-malicious ring-1 ring-malicious/30 hover:bg-malicious/20"
                      >
                        {vuln}
                      </a>
                    ))}
                  </div>
                </div>
              )}
              {host.tags.length > 0 && (
                <div className="flex flex-wrap gap-1.5">
                  {host.tags.slice(0, 16).map((tag) => (
                    <span
                      key={tag}
                      className="rounded-full border border-border px-2 py-0.5 font-mono text-[10px] uppercase tracking-wide text-muted-foreground"
                    >
                      {tag}
                    </span>
                  ))}
                </div>
              )}
            </>
          ) : (
            <p className="text-sm text-muted-foreground">No host record returned by Shodan for this target.</p>
          )}
        </CardContent>
      </Card>

      {host && host.services.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Server className="size-4 text-muted-foreground" aria-hidden="true" />
              Exposed services ({host.services.length})
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="overflow-x-auto">
              <table className="w-full min-w-[36rem] text-left text-sm">
                <thead>
                  <tr className="border-b border-border text-[10px] uppercase tracking-[0.12em] text-muted-foreground">
                    <th className="py-2 pr-3 font-normal">Port</th>
                    <th className="py-2 pr-3 font-normal">Product</th>
                    <th className="py-2 pr-3 font-normal">Banner</th>
                  </tr>
                </thead>
                <tbody>
                  {host.services.map((service, index) => (
                    <tr key={`${service.port}-${index}`} className="border-b border-border/60 last:border-0">
                      <td className="whitespace-nowrap py-2 pr-3 font-mono text-xs">
                        {service.port}/{service.transport}
                      </td>
                      <td className="py-2 pr-3 text-xs">
                        {[service.product, service.version].filter(Boolean).join(' ') || 'unknown'}
                      </td>
                      <td className="max-w-md py-2 pr-3 font-mono text-[11px] text-muted-foreground">
                        <span className="line-clamp-2 break-all">{service.banner ?? ''}</span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      )}

      {dns && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Network className="size-4 text-muted-foreground" aria-hidden="true" />
              DNS intel {dns.subdomains.length > 0 && `· ${dns.subdomains.length} subdomains`}
            </CardTitle>
          </CardHeader>
          <CardContent className="flex flex-col gap-4">
            {dns.subdomains.length > 0 && (
              <div className="flex flex-wrap gap-1.5">
                {dns.subdomains.slice(0, 30).map((subdomain) => (
                  <span key={subdomain} className="rounded-sm bg-secondary px-2 py-1 font-mono text-xs">
                    {subdomain}
                  </span>
                ))}
                {dns.subdomains.length > 30 && (
                  <span className="px-2 py-1 text-xs text-muted-foreground">
                    +{dns.subdomains.length - 30} more in the PDF
                  </span>
                )}
              </div>
            )}
            {dns.records.length > 0 ? (
              <div className="overflow-x-auto">
                <table className="w-full min-w-[30rem] text-left text-sm">
                  <thead>
                    <tr className="border-b border-border text-[10px] uppercase tracking-[0.12em] text-muted-foreground">
                      <th className="py-2 pr-3 font-normal">Type</th>
                      <th className="py-2 pr-3 font-normal">Value</th>
                      <th className="py-2 font-normal">Last seen</th>
                    </tr>
                  </thead>
                  <tbody>
                    {dns.records.slice(0, 40).map((record, index) => (
                      <tr key={`${record.type}-${record.value}-${index}`} className="border-b border-border/60 last:border-0">
                        <td className="whitespace-nowrap py-2 pr-3 font-mono text-xs text-muted-foreground">{record.type}</td>
                        <td className="break-all py-2 pr-3 font-mono text-xs">{record.value}</td>
                        <td className="whitespace-nowrap py-2 text-xs text-muted-foreground">{record.lastSeen ?? '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {dns.records.length > 40 && (
                  <p className="pt-2 text-xs text-muted-foreground">+{dns.records.length - 40} more records in the PDF.</p>
                )}
              </div>
            ) : (
              <p className="text-sm text-muted-foreground">No DNS records returned.</p>
            )}
          </CardContent>
        </Card>
      )}

      {search && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <ScanSearch className="size-4 text-muted-foreground" aria-hidden="true" />
              Deep search {search.error ? '' : `· ${search.total} matches`}
            </CardTitle>
          </CardHeader>
          <CardContent>
            {search.error ? (
              <p className="text-sm text-muted-foreground">{search.error}</p>
            ) : search.matches.length === 0 ? (
              <p className="text-sm text-muted-foreground">No matching services found.</p>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full min-w-[34rem] text-left text-sm">
                  <thead>
                    <tr className="border-b border-border text-[10px] uppercase tracking-[0.12em] text-muted-foreground">
                      <th className="py-2 pr-3 font-normal">Endpoint</th>
                      <th className="py-2 pr-3 font-normal">Product</th>
                      <th className="py-2 pr-3 font-normal">Organisation</th>
                      <th className="py-2 font-normal">Country</th>
                    </tr>
                  </thead>
                  <tbody>
                    {search.matches.map((match, index) => (
                      <tr key={`${match.ip}-${match.port}-${index}`} className="border-b border-border/60 last:border-0">
                        <td className="whitespace-nowrap py-2 pr-3 font-mono text-xs">
                          {match.ip}:{match.port}
                        </td>
                        <td className="py-2 pr-3 text-xs">{match.product ?? 'unknown'}</td>
                        <td className="py-2 pr-3 text-xs text-muted-foreground">{match.org ?? 'unknown'}</td>
                        <td className="whitespace-nowrap py-2 text-xs text-muted-foreground">{match.country ?? '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {data.errors.length > 0 && (
        <Card className="ring-suspicious/30">
          <CardContent className="flex items-start gap-3 py-4">
            <AlertTriangle className="mt-0.5 size-4 shrink-0 text-suspicious" aria-hidden="true" />
            <div className="flex flex-col gap-1">
              <p className="text-sm font-medium">Some lookups did not complete</p>
              <ul className="flex list-disc flex-col gap-0.5 pl-4 text-xs text-muted-foreground">
                {data.errors.map((message) => (
                  <li key={message}>{message}</li>
                ))}
              </ul>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  )
}

function Field({ label, value, className }: { label: string; value: string; className?: string }) {
  return (
    <div className="flex flex-col gap-0.5">
      <p className="text-[10px] uppercase tracking-[0.12em] text-muted-foreground">{label}</p>
      <p className={cn('break-words text-sm', className)}>{value}</p>
    </div>
  )
}
