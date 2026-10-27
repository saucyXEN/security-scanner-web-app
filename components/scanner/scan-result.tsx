'use client'

import { useMemo, useState } from 'react'
import { ExternalLink, Loader2, RefreshCw } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { cn } from '@/lib/utils'
import type { EngineResult, PdfReportInput, ScanResponse } from '@/lib/types'
import { VERDICT_META, VerdictBadge } from './verdict-badge'
import { PdfButton } from './pdf-button'

type Completed = Extract<ScanResponse, { status: 'completed' }>

const VERDICT_COPY = {
  malicious: 'One or more security vendors flagged this as malicious.',
  suspicious: 'Some vendors flagged this as suspicious. Proceed with caution.',
  safe: 'No security vendors flagged this as malicious.',
}

export function ScanResult({
  result,
  onRescan,
  rescanning,
  pdfReport,
  pdfFileName,
}: {
  result: Completed
  onRescan?: () => void
  rescanning?: boolean
  pdfReport?: PdfReportInput
  pdfFileName?: string
}) {
  const meta = VERDICT_META[result.verdict]
  const Icon = meta.icon
  const { stats } = result
  const total = stats.malicious + stats.suspicious + stats.harmless + stats.undetected
  const flagged = stats.malicious + stats.suspicious

  return (
    <div className="flex flex-col gap-4">
      <Card className={cn('ring-1', meta.ring)}>
        <CardContent className="flex flex-col gap-6 md:flex-row md:items-center">
          <div className="flex items-center gap-4">
            <div className={cn('flex size-16 shrink-0 items-center justify-center rounded-2xl ring-1', meta.bg, meta.ring)}>
              <Icon className={cn('size-8', meta.text)} aria-hidden="true" />
            </div>
            <div className="flex flex-col gap-1.5">
              <VerdictBadge verdict={result.verdict} className="self-start" />
              <p className="text-pretty text-sm text-muted-foreground">{VERDICT_COPY[result.verdict]}</p>
              {result.scannedAt && (
                <p className="text-xs text-muted-foreground">
                  Last analysis: {new Date(result.scannedAt).toLocaleString()}
                </p>
              )}
            </div>
          </div>

          <div className="flex items-center gap-6 md:ml-auto">
            <div className="text-center">
              <p className={cn('font-mono text-4xl font-semibold tabular-nums', meta.text)}>
                {flagged}
                <span className="text-xl text-muted-foreground">/{total}</span>
              </p>
              <p className="text-xs uppercase tracking-wide text-muted-foreground">Engines flagged</p>
            </div>
            <div className="flex flex-col gap-2">
              {onRescan && (
                <Button variant="outline" size="sm" onClick={onRescan} disabled={rescanning}>
                  {rescanning ? <Loader2 className="animate-spin" /> : <RefreshCw />}
                  Rescan
                </Button>
              )}
              {pdfReport && (
                <PdfButton report={pdfReport} fileName={pdfFileName ?? 'hackerade-report.pdf'} />
              )}
              {result.permalink && (
                <Button
                  variant="ghost"
                  size="sm"
                  nativeButton={false}
                  render={<a href={result.permalink} target="_blank" rel="noopener noreferrer" />}
                >
                  <ExternalLink />
                  VirusTotal
                </Button>
              )}
            </div>
          </div>
        </CardContent>
      </Card>

      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <StatCard label="Malicious" value={stats.malicious} className="text-malicious" />
        <StatCard label="Suspicious" value={stats.suspicious} className="text-suspicious" />
        <StatCard label="Harmless" value={stats.harmless} className="text-safe" />
        <StatCard label="Undetected" value={stats.undetected} className="text-muted-foreground" />
      </div>

      <div className="grid gap-4 lg:grid-cols-5">
        {result.details.length > 0 && (
          <Card className="lg:col-span-2">
            <CardHeader>
              <CardTitle>Details</CardTitle>
            </CardHeader>
            <CardContent>
              <dl className="flex flex-col gap-3">
                {result.details.map((d) => (
                  <div key={d.label} className="flex flex-col gap-0.5">
                    <dt className="text-xs uppercase tracking-wide text-muted-foreground">{d.label}</dt>
                    <dd className="break-all font-mono text-xs">{d.value}</dd>
                  </div>
                ))}
              </dl>
            </CardContent>
          </Card>
        )}
        <EngineTable engines={result.engines} className={result.details.length > 0 ? 'lg:col-span-3' : 'lg:col-span-5'} />
      </div>
    </div>
  )
}

function StatCard({ label, value, className }: { label: string; value: number; className?: string }) {
  return (
    <Card size="sm">
      <CardContent className="flex flex-col gap-1">
        <span className="text-xs uppercase tracking-wide text-muted-foreground">{label}</span>
        <span className={cn('font-mono text-2xl font-semibold tabular-nums', className)}>{value}</span>
      </CardContent>
    </Card>
  )
}

const CATEGORY_STYLE: Record<string, string> = {
  malicious: 'text-malicious',
  suspicious: 'text-suspicious',
  harmless: 'text-safe',
  undetected: 'text-muted-foreground',
}

function EngineTable({ engines, className }: { engines: EngineResult[]; className?: string }) {
  const [showAll, setShowAll] = useState(false)
  const visible = useMemo(() => (showAll ? engines : engines.slice(0, 16)), [engines, showAll])

  return (
    <Card className={className}>
      <CardHeader>
        <CardTitle>Security vendors ({engines.length})</CardTitle>
      </CardHeader>
      <CardContent>
        {engines.length === 0 ? (
          <p className="text-sm text-muted-foreground">No per-engine results available.</p>
        ) : (
          <>
            <ul className="grid gap-x-6 sm:grid-cols-2">
              {visible.map((e) => (
                <li
                  key={e.engine}
                  className="flex items-center justify-between gap-3 border-b border-border py-2 text-sm last:border-0 sm:[&:nth-last-child(2):nth-child(odd)]:border-0"
                >
                  <span className="truncate">{e.engine}</span>
                  <span className={cn('shrink-0 truncate text-right text-xs font-medium', CATEGORY_STYLE[e.category] ?? 'text-muted-foreground')}>
                    {e.result && e.category !== 'harmless' && e.category !== 'undetected' ? e.result : e.category}
                  </span>
                </li>
              ))}
            </ul>
            {engines.length > 16 && (
              <Button variant="ghost" size="sm" className="mt-3" onClick={() => setShowAll((v) => !v)}>
                {showAll ? 'Show less' : `Show all ${engines.length} vendors`}
              </Button>
            )}
          </>
        )}
      </CardContent>
    </Card>
  )
}
