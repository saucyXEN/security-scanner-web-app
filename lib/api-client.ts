'use client'

import { useEffect, useRef, useState } from 'react'
import useSWR from 'swr'
import type { ScanResponse } from './types'

export class ApiError extends Error {
  constructor(
    message: string,
    public status: number,
  ) {
    super(message)
    this.name = 'ApiError'
  }
}

export async function parseJson<T>(res: Response): Promise<T> {
  const data = await res.json().catch(() => ({}))
  if (!res.ok) throw new ApiError(data?.error ?? `Request failed (${res.status})`, res.status)
  return data as T
}

export async function postJson<T>(url: string, { arg }: { arg: unknown }): Promise<T> {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(arg),
  })
  return parseJson<T>(res)
}

const getJson = async (url: string) => parseJson<ScanResponse>(await fetch(url))

// VirusTotal's public API allows only 4 requests/minute, so polling every few
// seconds burns the whole quota and gets us throttled. Check once at 10s (many
// analyses are ready by then) and then every 20s.
const FIRST_POLL_MS = 10_000
const NEXT_POLL_MS = 20_000
const RATE_LIMIT_RETRY_MS = 25_000
const MAX_RATE_LIMIT_RETRIES = 15

export function useAnalysis(analysisId: string | null) {
  const startedAt = useRef(0)
  const [exhausted, setExhausted] = useState(false)

  useEffect(() => {
    startedAt.current = analysisId ? Date.now() : 0
    setExhausted(false)
  }, [analysisId])

  const { data, error } = useSWR(analysisId ? `/api/scan/analysis/${encodeURIComponent(analysisId)}` : null, getJson, {
    refreshInterval: (latest) => {
      if (latest?.status === 'completed') return 0
      const elapsed = startedAt.current ? Date.now() - startedAt.current : 0
      return elapsed < FIRST_POLL_MS ? FIRST_POLL_MS : NEXT_POLL_MS
    },
    // A 429 means "wait", not "fail" — keep polling so the result still arrives.
    shouldRetryOnError: (err) => (err as ApiError)?.status === 429,
    onErrorRetry: (_err, _key, _config, revalidate, opts) => {
      if (opts.retryCount > MAX_RATE_LIMIT_RETRIES) {
        setExhausted(true)
        return
      }
      setTimeout(() => revalidate({ retryCount: opts.retryCount + 1 }), RATE_LIMIT_RETRY_MS)
    },
    revalidateOnFocus: false,
  })

  const apiError = error as ApiError | undefined
  const rateLimited = apiError?.status === 429 && !exhausted

  return {
    analysis: data,
    analysisError: rateLimited ? undefined : (apiError as Error | undefined),
    rateLimited,
  }
}

export async function sha256Hex(file: File) {
  const digest = await crypto.subtle.digest('SHA-256', await file.arrayBuffer())
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}
