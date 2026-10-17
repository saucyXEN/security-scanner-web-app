'use client'

import { useRef, useState, type DragEvent } from 'react'
import useSWRMutation from 'swr/mutation'
import { FileSearch, FileUp, Loader2, X } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { cn } from '@/lib/utils'
import { parseJson, sha256Hex, useAnalysis } from '@/lib/api-client'
import type { ScanResponse } from '@/lib/types'
import { ScanResult } from './scan-result'
import { EmptyState, ErrorState, PendingState } from './status-states'

const MAX_BYTES = 32 * 1024 * 1024

async function scanFile(_key: string, { arg: file }: { arg: File }): Promise<ScanResponse> {
  if (file.size > MAX_BYTES) throw new Error('File is larger than the 32 MB upload limit.')

  const hash = await sha256Hex(file)
  const known = await parseJson<ScanResponse | { status: 'unknown' }>(await fetch(`/api/scan/file?hash=${hash}`))
  if (known.status === 'completed') return known

  const form = new FormData()
  form.append('file', file)
  return parseJson<ScanResponse>(await fetch('/api/scan/file', { method: 'POST', body: form }))
}

function formatSize(bytes: number) {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / 1024 / 1024).toFixed(2)} MB`
}

export function FileScan() {
  const inputRef = useRef<HTMLInputElement>(null)
  const [file, setFile] = useState<File | null>(null)
  const [dragging, setDragging] = useState(false)
  const { trigger, data, error, isMutating, reset } = useSWRMutation('/api/scan/file', scanFile)
  const analysisId = data?.status === 'queued' ? data.analysisId : null
  const { analysis, analysisError } = useAnalysis(analysisId)

  const result = data?.status === 'completed' ? data : analysis?.status === 'completed' ? analysis : null
  const pending = isMutating || (!!analysisId && !result && !analysisError)

  const select = (f: File | undefined) => {
    if (!f) return
    reset()
    setFile(f)
  }

  const onDrop = (e: DragEvent) => {
    e.preventDefault()
    setDragging(false)
    select(e.dataTransfer.files?.[0])
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
          onDragOver={(e) => {
            e.preventDefault()
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
          <div>
            <p className="font-medium">Drop a file here or click to browse</p>
            <p className="text-sm text-muted-foreground">Max 32 MB. Files are hashed first — known files are not re-uploaded.</p>
          </div>
          <input
            ref={inputRef}
            id="file-input"
            type="file"
            className="sr-only"
            onChange={(e) => select(e.target.files?.[0])}
          />
        </label>

        {file && (
          <div className="flex flex-col gap-3 rounded-xl bg-card p-3 ring-1 ring-foreground/10 sm:flex-row sm:items-center">
            <div className="flex min-w-0 flex-1 items-center gap-3">
              <FileSearch className="size-5 shrink-0 text-muted-foreground" aria-hidden="true" />
              <div className="min-w-0">
                <p className="truncate text-sm font-medium">{file.name}</p>
                <p className="text-xs text-muted-foreground">{formatSize(file.size)}</p>
              </div>
            </div>
            <div className="flex gap-2">
              <Button variant="ghost" size="sm" onClick={clear} disabled={isMutating}>
                <X />
                Remove
              </Button>
              <Button size="sm" onClick={() => trigger(file).catch(() => {})} disabled={pending}>
                {pending ? <Loader2 className="animate-spin" /> : <FileSearch />}
                Scan file
              </Button>
            </div>
          </div>
        )}
      </div>

      {error ? (
        <ErrorState message={error.message} />
      ) : analysisError ? (
        <ErrorState message={analysisError.message} />
      ) : result ? (
        <ScanResult result={result} />
      ) : pending ? (
        <PendingState
          title={isMutating ? 'Hashing and uploading file…' : 'Analysis in progress'}
          description="Security vendors are scanning the file. New files can take 1–3 minutes."
        />
      ) : (
        !file && (
          <EmptyState
            icon={FileSearch}
            title="Scan a suspicious file"
            description="Upload an executable, document or archive to check it against 70+ antivirus engines."
          />
        )
      )}
    </div>
  )
}
