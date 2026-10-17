'use client'

import { useState, type FormEvent } from 'react'
import useSWRMutation from 'swr/mutation'
import { Globe, Link2, Loader2, Search } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { postJson, useAnalysis } from '@/lib/api-client'
import type { ScanResponse } from '@/lib/types'
import { ScanResult } from './scan-result'
import { EmptyState, ErrorState, PendingState } from './status-states'

export function UrlScan() {
  const [url, setUrl] = useState('')
  const [lastUrl, setLastUrl] = useState('')
  const { trigger, data, error, isMutating, reset } = useSWRMutation('/api/scan/url', postJson<ScanResponse>)
  const analysisId = data?.status === 'queued' ? data.analysisId : null
  const { analysis, analysisError } = useAnalysis(analysisId)

  const result = data?.status === 'completed' ? data : analysis?.status === 'completed' ? analysis : null
  const pending = isMutating || (!!analysisId && !result && !analysisError)

  const scan = (target: string, rescan = false) => {
    setLastUrl(target)
    trigger({ url: target, rescan }).catch(() => {})
  }

  const onSubmit = (e: FormEvent) => {
    e.preventDefault()
    if (!url.trim()) return
    reset()
    scan(url.trim())
  }

  return (
    <div className="flex flex-col gap-6">
      <form onSubmit={onSubmit} className="flex flex-col gap-3 sm:flex-row">
        <label htmlFor="url-input" className="sr-only">
          URL to scan
        </label>
        <div className="relative flex-1">
          <Link2 className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" aria-hidden="true" />
          <Input
            id="url-input"
            type="text"
            inputMode="url"
            autoComplete="off"
            spellCheck={false}
            placeholder="https://example.com/login"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            className="h-11 pl-9 font-mono text-sm"
          />
        </div>
        <Button type="submit" className="h-11 px-5 font-mono text-xs uppercase tracking-[0.2em] shadow-hard-sm transition-transform hover:-translate-y-0.5" disabled={pending || !url.trim()}>
          {pending ? <Loader2 className="animate-spin" /> : <Search />}
          Scan URL
        </Button>
      </form>

      {error ? (
        <ErrorState message={error.message} />
      ) : analysisError ? (
        <ErrorState message={analysisError.message} />
      ) : result ? (
        <ScanResult result={result} onRescan={() => scan(lastUrl, true)} rescanning={pending} />
      ) : pending ? (
        <PendingState
          title={isMutating ? 'Submitting URL to VirusTotal…' : 'Analysis in progress'}
          description="Security vendors are analyzing the URL. This usually takes 15–60 seconds."
        />
      ) : (
        <EmptyState
          icon={Globe}
          title="Check any link before you click it"
          description="Paste a URL to check it against 70+ antivirus engines and URL/domain blocklisting services."
        />
      )}
    </div>
  )
}
