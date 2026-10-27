'use client'

import { useRef, useState, type DragEvent } from 'react'
import useSWRMutation from 'swr/mutation'
import { FileSearch, FileUp, Loader2, ShieldCheck, X } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { cn } from '@/lib/utils'
import { parseJson, useAnalysis } from '@/lib/api-client'
import type { DeepScanResponse } from '@/lib/types'
import { formatBytes } from '@/lib/report'
import { DeepResult } from './deep-result'
import { EmptyState, ErrorState, PendingState } from './status-states'

// The local analysis runs on our own server, so any file size works. VirusTotal
// adds multi-engine results when a key is configured.
const MAX_BYTES = 200 * 1024 * 1024
const LARGE_BYTES = 32 * 1024 * 1024

async function deepScan(_key: string, { arg }: { arg: { file: File; vt: boolean } }): Promise<DeepScanResponse> {
  if (arg.file.size > MAX_BYTES) throw new Error('File is larger than the 200 MB analysis limit.')

  const form = new FormData()
  form.append('file', arg.file)
  form.append('vt', arg.vt ? 'on' : 'off')
  return parseJson<DeepScanResponse>(await fetch('/api/scan/deep', { method: 'POST', body: form }))
}

export function FileScan() {
  const inputRef = useRef<HTMLInputElement>(null)
  const [file, setFile] = useState<File | null>(null)
  const [dragging, setDragging] = useState(false)
  const [submitToVirusTotal, setSubmitToVirusTotal] = useState(true)
  const { trigger, data, error, isMutating, reset } = useSWRMutation('/api/scan/deep', deepScan)

  const queuedId = data?.vt?.status === 'queued' ? data.vt.analysisId : null
  const { analysis: polledVt, analysisError, rateLimited } = useAnalysis(queuedId)

  const vt = polledVt?.status === 'completed' ? polledVt : (data?.vt ?? null)
  const vtPending = vt?.status === 'queued'
  const vtError = data?.vtError ?? (analysisError ? analysisError.message : null)

  const select = (next: File | undefined) => {
    if (!next) return
    reset()
    setFile(next)
  }

  const onDrop = (event: DragEvent) => {
    event.preventDefault()
    setDragging(false)
    select(event.dataTransfer.files?.[0])
  }

  const clear = () => {
    reset()
    setFile(null)
    if (inputRef.current) inputRef.current.value = ''
  }

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-col gap-3">
        <label
          htmlFor="file-input"
          onDragOver={(event) => {
            event.preventDefault()
            setDragging(true)
          }}
          onDragLeave={() => setDragging(false)}
          onDrop={onDrop}
          className={cn(
            'flex cursor-pointer flex-col items-center justify-center gap-3 rounded-xl border border-dashed px-6 py-10 text-center transition-colors focus-within:ring-2 focus-within:ring-ring',
            dragging ? 'border-white bg-white/5' : 'border-neutral-700 bg-card/40 hover:border-neutral-400 hover:bg-card',
          )}
        >
          <div className="flex size-12 items-center justify-center rounded-xl bg-primary/10 ring-1 ring-primary/30">
            <FileUp className="size-6 text-primary" aria-hidden="true" />
          </div>
          <div className="flex flex-col gap-1">
            <p className="font-medium">Drop a file here or click to browse</p>
            <p className="text-sm text-muted-foreground">
              Up to 200 MB — including files over the 32 MB VirusTotal limit.
            </p>
            <p className="flex items-center justify-center gap-1.5 text-xs text-muted-foreground">
              <ShieldCheck className="size-3.5" aria-hidden="true" />
              Offline static analysis: the file is never executed, and no API key is needed.
            </p>
          </div>
          <input
            ref={inputRef}
            id="file-input"
            type="file"
            className="sr-only"
            onChange={(event) => select(event.target.files?.[0])}
          />
        </label>

        {file && (
          <div className="flex flex-col gap-3 rounded-xl bg-card p-3 ring-1 ring-foreground/10 sm:flex-row sm:items-center">
            <div className="flex min-w-0 flex-1 items-center gap-3">
              <FileSearch className="size-5 shrink-0 text-muted-foreground" aria-hidden="true" />
              <div className="min-w-0">
                <p className="truncate text-sm font-medium">{file.name}</p>
                <p className="text-xs text-muted-foreground">
                  {formatBytes(file.size)}
                  {file.size > LARGE_BYTES && ' · large file: offline analysis always runs'}
                </p>
              </div>
            </div>
            <div className="flex flex-wrap items-center gap-3">
              <label className="flex cursor-pointer items-center gap-2 text-xs text-muted-foreground">
                <input
                  type="checkbox"
                  checked={submitToVirusTotal}
                  onChange={(event) => setSubmitToVirusTotal(event.target.checked)}
                  disabled={isMutating}
                  className="size-3.5 accent-white"
                />
                Submit to VirusTotal
              </label>
              <div className="flex gap-2">
                <Button variant="ghost" size="sm" onClick={clear} disabled={isMutating}>
                  <X />
                  Remove
                </Button>
                <Button
                  size="sm"
                  onClick={() => trigger({ file, vt: submitToVirusTotal }).catch(() => {})}
                  disabled={isMutating}
                >
                  {isMutating ? <Loader2 className="animate-spin" /> : <FileSearch />}
                  Scan file
                </Button>
              </div>
            </div>
          </div>
        )}
      </div>

      {error ? (
        <ErrorState message={error.message} />
      ) : isMutating ? (
        <PendingState
          title={file && file.size > LARGE_BYTES ? 'Analyzing large file locally…' : 'Analyzing file locally…'}
          description="Hashes, entropy, embedded commands and file structure are checked on this server. Nothing is executed and no internet is required."
        />
      ) : data ? (
        <DeepResult data={data} vt={vt} vtError={vtError} vtPending={vtPending} />
      ) : (
        !file && (
          <EmptyState
            icon={FileSearch}
            title="Scan a suspicious file"
            description="Any executable, document, script or archive up to 200 MB. The local engine works offline; VirusTotal adds 70+ antivirus engines when configured."
          />
        )
      )}

      {rateLimited && data && (
        <p className="text-xs text-muted-foreground">
          VirusTotal rate limit reached — the local analysis above is already complete, and the multi-engine result will
          keep retrying automatically.
        </p>
      )}
    </div>
  )
}
