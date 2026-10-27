'use client'

import { Bot, Cpu, Fingerprint, Network, ShieldAlert } from 'lucide-react'
import { Card, CardAction, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { cn } from '@/lib/utils'
import type { DeepScanResponse, ScanResponse, Severity } from '@/lib/types'
import { deepAiContext, deepPdfReport, formatBytes } from '@/lib/report'
import { VERDICT_META, VerdictBadge } from './verdict-badge'
import { AiInsight } from './ai-insight'
import { PdfButton } from './pdf-button'
import { ScanResult } from './scan-result'
import { PendingState } from './status-states'

const SEVERITY_STYLE: Record<Severity, string> = {
  high: 'text-malicious',
  medium: 'text-suspicious',
  low: 'text-neutral-300',
  info: 'text-muted-foreground',
}

export function DeepResult({
  data,
  vt,
  vtError,
  vtPending,
}: {
  data: DeepScanResponse
  vt: ScanResponse | null
  vtError: string | null
  vtPending: boolean
}) {
  const { analysis } = data
  const meta = VERDICT_META[analysis.verdict]
  const Icon = meta.icon
  const report = deepPdfReport({ ...data, vt, vtError })
  const fileName = `hackerade-${analysis.fileName.replace(/[^a-z0-9._-]+/gi, '_').slice(-60) || 'file'}.pdf`

  return (
    <div className="flex flex-col gap-4">
      <Card className={cn('ring-1', meta.ring)}>
        <CardHeader>
          <CardTitle className="flex flex-wrap items-center gap-2">
            <Cpu className="size-4 text-muted-foreground" aria-hidden="true" />
            Local static analysis
            <span className="rounded-sm bg-secondary px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-[0.16em] text-muted-foreground">
              offline · nothing executed
            </span>
          </CardTitle>
          <CardAction>
            <PdfButton report={report} fileName={fileName} label="Download report" />
          </CardAction>
        </CardHeader>
        <CardContent className="flex flex-col gap-6 md:flex-row md:items-center">
          <div className="flex min-w-0 items-center gap-4">
            <div className={cn('flex size-16 shrink-0 items-center justify-center rounded-2xl ring-1', meta.bg, meta.ring)}>
              <Icon className={cn('size-8', meta.text)} aria-hidden="true" />
            </div>
            <div className="flex min-w-0 flex-col gap-1.5">
              <VerdictBadge verdict={analysis.verdict} className="self-start" />
              <p className="break-all font-mono text-sm">{analysis.fileName}</p>
              <p className="text-xs text-muted-foreground">
                {analysis.fileType} · {formatBytes(analysis.size)}
                {analysis.pe ? ` · ${analysis.pe.machine}` : ''}
              </p>
            </div>
          </div>

          <div className="grid grid-cols-3 gap-3 md:ml-auto md:min-w-72">
            <Metric label="Risk score" value={String(analysis.score)} className={meta.text} />
            <Metric label="Findings" value={String(analysis.findings.length)} />
            <Metric label="Entropy" value={`${analysis.entropy}`} hint="/ 8" />
          </div>
        </CardContent>
      </Card>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <ShieldAlert className="size-4 text-muted-foreground" aria-hidden="true" />
              Findings ({analysis.findings.length})
            </CardTitle>
          </CardHeader>
          <CardContent>
            {analysis.findings.length === 0 ? (
              <p className="text-sm text-muted-foreground">
                No suspicious patterns matched. Unknown or brand-new files can still be harmful, so keep your guard up.
              </p>
            ) : (
              <ul className="flex flex-col divide-y divide-border">
                {analysis.findings.map((finding) => (
                  <li key={`${finding.severity}-${finding.title}`} className="flex flex-col gap-0.5 py-2 first:pt-0 last:pb-0">
                    <div className="flex items-center gap-2">
                      <span
                        className={cn(
                          'font-mono text-[10px] font-bold uppercase tracking-[0.14em]',
                          SEVERITY_STYLE[finding.severity],
                        )}
                      >
                        {finding.severity}
                      </span>
                      <span className="text-sm font-medium">{finding.title}</span>
                    </div>
                    <p className="text-xs text-muted-foreground">{finding.detail}</p>
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Fingerprint className="size-4 text-muted-foreground" aria-hidden="true" />
              Hashes &amp; structure
            </CardTitle>
          </CardHeader>
          <CardContent>
            <dl className="flex flex-col gap-3">
              <Detail label="SHA-256" value={analysis.sha256} />
              <Detail label="MD5" value={analysis.md5} />
              {analysis.pe && (
                <>
                  <Detail label="PE format" value={`${analysis.pe.format} · ${analysis.pe.machine}`} />
                  <Detail
                    label="Sections"
                    value={`${analysis.pe.sections}${analysis.pe.packed ? ' · packed' : ' · not packed'}`}
                  />
                  <Detail label="Subsystem" value={analysis.pe.subsystem ?? 'unknown'} />
                </>
              )}
              <Detail label="Analysis mode" value="Offline static analysis — the file was never executed" />
            </dl>
          </CardContent>
        </Card>
      </div>

      <IndicatorCard data={data} />

      <section className="flex flex-col gap-3">
        <p className="eyebrow">
          <span className="text-white">{'//'}</span> VirusTotal multi-engine scan
        </p>
        {vt?.status === 'completed' ? (
          <ScanResult result={vt} />
        ) : vtPending ? (
          <PendingState
            title="VirusTotal analysis queued"
            description="The file was uploaded and security vendors are scanning it. New files usually take 1–3 minutes."
          />
        ) : vtError ? (
          <Card>
            <CardContent className="flex items-start gap-3 py-4">
              <Bot className="mt-0.5 size-4 shrink-0 text-muted-foreground" aria-hidden="true" />
              <p className="text-sm text-muted-foreground">{vtError}</p>
            </CardContent>
          </Card>
        ) : null}
      </section>

      <AiInsight context={deepAiContext({ ...data, vt, vtError })} />
    </div>
  )
}

function Metric({ label, value, hint, className }: { label: string; value: string; hint?: string; className?: string }) {
  return (
    <div className="rounded-lg bg-secondary/50 px-3 py-2">
      <p className="text-[10px] uppercase tracking-[0.12em] text-muted-foreground">{label}</p>
      <p className={cn('font-mono text-2xl font-semibold tabular-nums', className)}>
        {value}
        {hint && <span className="ml-1 text-xs text-muted-foreground">{hint}</span>}
      </p>
    </div>
  )
}

function Detail({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex flex-col gap-0.5">
      <dt className="text-[10px] uppercase tracking-[0.12em] text-muted-foreground">{label}</dt>
      <dd className="break-all font-mono text-xs">{value}</dd>
    </div>
  )
}

function IndicatorCard({ data }: { data: DeepScanResponse }) {
  const { urls, ips, emails, commands } = data.analysis.indicators
  const groups = [
    { label: 'URLs', items: urls, icon: Network },
    { label: 'IP addresses', items: ips, icon: Network },
    { label: 'Email addresses', items: emails, icon: Network },
    { label: 'Commands', items: commands, icon: Network },
  ].filter((group) => group.items.length > 0)

  if (groups.length === 0) return null

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Network className="size-4 text-muted-foreground" aria-hidden="true" />
          Extracted indicators
        </CardTitle>
      </CardHeader>
      <CardContent className="grid gap-4 md:grid-cols-2">
        {groups.map(({ label, items }) => (
          <div key={label} className="flex flex-col gap-1.5">
            <p className="text-[10px] uppercase tracking-[0.12em] text-muted-foreground">
              {label} ({items.length})
            </p>
            <ul className="flex flex-col gap-1">
              {items.slice(0, 8).map((item) => (
                <li key={item} className="break-all font-mono text-xs text-neutral-300">
                  {item}
                </li>
              ))}
              {items.length > 8 && <li className="text-xs text-muted-foreground">+{items.length - 8} more in the PDF</li>}
            </ul>
          </div>
        ))}
      </CardContent>
    </Card>
  )
}
