'use client'

import { FileSearch, Link2, Radar, ScanSearch } from 'lucide-react'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { UrlScan } from './url-scan'
import { FileScan } from './file-scan'
import { OsintPanel } from './osint-panel'
import { ReconPanel } from './recon-panel'

const TABS = [
  { value: 'url', label: 'URL Scan', icon: Link2, description: 'Check a link against antivirus engines and blocklists.' },
  {
    value: 'file',
    label: 'File Scan',
    icon: FileSearch,
    description: 'Offline static analysis for files up to 200 MB, plus VirusTotal engines when configured.',
  },
  {
    value: 'osint',
    label: 'OSINT',
    icon: ScanSearch,
    description: 'Shodan host intel: open ports, services, CVEs, DNS and deep search for an IP or domain.',
  },
  { value: 'recon', label: 'Recon', icon: Radar, description: 'WHOIS, subdomains, DNS records and contacts for a domain.' },
] as const

export function ScannerDashboard() {
  return (
    <div className="relative min-h-dvh">
      <div
        aria-hidden="true"
        className="pointer-events-none absolute inset-x-0 top-0 h-[480px] bg-[radial-gradient(ellipse_at_top,rgb(38_38_38/0.6),transparent_70%)]"
      />

      <header className="sticky top-0 z-30 border-b border-border bg-background/90 backdrop-blur-md">
        <div className="mx-auto flex h-16 max-w-6xl items-center justify-between gap-4 px-4 md:px-6">
          <a href="#top" className="flex items-center gap-3 font-mono text-base font-extrabold tracking-tight text-white sm:text-lg">
            <span className="flex size-9 items-center justify-center border border-white text-sm" aria-hidden="true">
              HK
            </span>
            <span className="text-muted-foreground">
              <span className="text-white">HACKERADE</span>
              <span className="hidden sm:inline">_scanner()</span>
            </span>
          </a>
          <div className="hidden items-center gap-6 font-mono text-[11px] uppercase tracking-[0.2em] text-muted-foreground md:flex">
            <Legend className="bg-safe" label="Safe" />
            <Legend className="bg-suspicious" label="Suspicious" />
            <Legend className="bg-malicious" label="Malicious" />
          </div>
        </div>
      </header>

      <main id="top" className="relative mx-auto flex max-w-6xl flex-col gap-10 px-4 py-12 md:px-6 md:py-16">
        <div className="flex flex-col gap-6">
          <p className="eyebrow">
            <span className="text-white">$</span> ./scan --target
            <span className="ml-1 inline-block h-3.5 w-2 translate-y-0.5 animate-pulse bg-white" aria-hidden="true" />
          </p>
          <h1 className="text-balance font-mono text-4xl font-black leading-[0.95] tracking-tight text-white md:text-6xl">
            Analyze threats.
            <span className="block text-muted-foreground">URLs, files & domains.</span>
          </h1>
          <p className="max-w-2xl text-pretty leading-relaxed text-neutral-300 md:text-lg">
            POWERED BY HACKERADE
          </p>
          <span className="block h-px w-16 bg-neutral-400" aria-hidden="true" />
        </div>

        <Tabs defaultValue="url" className="gap-6">
          <TabsList
            variant="line"
            className="h-auto! w-full justify-start gap-6 overflow-x-auto rounded-none border-b border-border p-0"
          >
            {TABS.map(({ value, label, icon: Icon }, index) => (
              <TabsTrigger
                key={value}
                value={value}
                className="h-11 flex-none rounded-none px-0 font-mono text-xs uppercase tracking-[0.2em] text-neutral-400 data-[state=active]:text-white"
              >
                <span className="text-neutral-600">{`0${index + 1}.`}</span>
                <Icon aria-hidden="true" />
                {label}
              </TabsTrigger>
            ))}
          </TabsList>

          {TABS.map(({ value, description }) => (
            <TabsContent key={value} value={value} className="flex flex-col gap-4">
              <p className="eyebrow tracking-[0.2em]">
                <span className="text-white">{'//'}</span> {description}
              </p>
              {value === 'url' && <UrlScan />}
              {value === 'file' && <FileScan />}
              {value === 'osint' && <OsintPanel />}
              {value === 'recon' && <ReconPanel />}
            </TabsContent>
          ))}
        </Tabs>
      </main>

      <footer className="border-t border-border">
        <div className="mx-auto flex max-w-6xl flex-col gap-2 px-4 py-6 font-mono text-[11px] uppercase tracking-[0.2em] text-neutral-500 sm:flex-row sm:items-center sm:justify-between md:px-6">
          <span>
            <span className="text-white">HACKERADE</span> {'// threat intelligence console'}
          </span>
          <span>SAUCY</span>
        </div>
      </footer>
    </div>
  )
}

function Legend({ className, label }: { className: string; label: string }) {
  return (
    <span className="flex items-center gap-2">
      <span className={`size-2 ${className}`} aria-hidden="true" />
      {label}
    </span>
  )
}
