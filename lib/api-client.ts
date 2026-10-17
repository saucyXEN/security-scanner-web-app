'use client'

import useSWR from 'swr'
import type { ScanResponse } from './types'

export async function parseJson<T>(res: Response): Promise<T> {
  const data = await res.json().catch(() => ({}))
  if (!res.ok) throw new Error(data?.error ?? `Request failed (${res.status})`)
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

export function useAnalysis(analysisId: string | null) {
  const { data, error } = useSWR(analysisId ? `/api/scan/analysis/${encodeURIComponent(analysisId)}` : null, getJson, {
    refreshInterval: (latest) => (latest?.status === 'completed' ? 0 : 5000),
    revalidateOnFocus: false,
    shouldRetryOnError: false,
  })
  return { analysis: data, analysisError: error as Error | undefined }
}

export async function sha256Hex(file: File) {
  const digest = await crypto.subtle.digest('SHA-256', await file.arrayBuffer())
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}
