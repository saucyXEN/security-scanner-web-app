import { errorResponse, reportFromObject, urlId, vtFetch } from '@/lib/virustotal'
import type { ScanResponse } from '@/lib/types'

export const runtime = 'nodejs'

function normalizeUrl(input: unknown): string | null {
  if (typeof input !== 'string') return null
  const trimmed = input.trim()
  if (!trimmed || trimmed.length > 2048) return null
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed) ? trimmed : `http://${trimmed}`
  try {
    const parsed = new URL(withScheme)
    if (!['http:', 'https:'].includes(parsed.protocol) || !parsed.hostname.includes('.')) return null
    return parsed.toString()
  } catch {
    return null
  }
}

export async function POST(request: Request) {
  try {
    const body = await request.json().catch(() => ({}))
    const url = normalizeUrl(body?.url)
    if (!url) {
      return Response.json({ error: 'Please enter a valid http(s) URL.' }, { status: 400 })
    }

    const rescan = body?.rescan === true
    if (!rescan) {
      const existing = await vtFetch(`/urls/${urlId(url)}`)
      if (existing?.data?.attributes?.last_analysis_date) {
        return Response.json(reportFromObject(existing.data, 'url') satisfies ScanResponse)
      }
    }

    const submitted = await vtFetch('/urls', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ url }).toString(),
    })
    return Response.json({ status: 'queued', analysisId: submitted?.data?.id } satisfies ScanResponse)
  } catch (error) {
    return errorResponse(error)
  }
}
