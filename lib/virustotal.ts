import type { DetailItem, EngineResult, ScanResponse, ScanStats, Verdict } from './types'

const VT_BASE = 'https://www.virustotal.com/api/v3'

export class VTError extends Error {
  constructor(
    message: string,
    public status: number,
  ) {
    super(message)
  }
}

function apiKey() {
  const key = process.env.VIRUSTOTAL_API_KEY
  if (!key) {
    throw new VTError('VirusTotal API key is not configured on the server (VIRUSTOTAL_API_KEY).', 500)
  }
  return key
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Json = any

export async function vtFetch(path: string, init: RequestInit = {}): Promise<Json | null> {
  const res = await fetch(`${VT_BASE}${path}`, {
    ...init,
    headers: { 'x-apikey': apiKey(), accept: 'application/json', ...init.headers },
    cache: 'no-store',
  })

  if (res.status === 404) return null

  const body = await res.json().catch(() => null)
  if (!res.ok) {
    if (res.status === 429) {
      throw new VTError('VirusTotal rate limit reached. Please wait a minute and try again.', 429)
    }
    if (res.status === 401) {
      throw new VTError('VirusTotal rejected the server API key.', 502)
    }
    throw new VTError(body?.error?.message ?? `VirusTotal request failed (${res.status}).`, 502)
  }
  return body
}

export function urlId(url: string) {
  return Buffer.from(url).toString('base64url')
}

function normalizeStats(raw: Json): ScanStats {
  return {
    malicious: raw?.malicious ?? 0,
    suspicious: raw?.suspicious ?? 0,
    harmless: raw?.harmless ?? 0,
    undetected: raw?.undetected ?? 0,
    timeout: raw?.timeout ?? 0,
  }
}

function verdictFrom(stats: ScanStats): Verdict {
  // A single engine flag is common noise on popular sites; require consensus before calling it malicious.
  if (stats.malicious >= 3) return 'malicious'
  if (stats.malicious > 0 || stats.suspicious > 0) return 'suspicious'
  return 'safe'
}

const CATEGORY_ORDER: Record<string, number> = {
  malicious: 0,
  suspicious: 1,
  harmless: 2,
  undetected: 3,
}

function normalizeEngines(raw: Json): EngineResult[] {
  if (!raw || typeof raw !== 'object') return []
  return Object.entries(raw as Record<string, Json>)
    .map(([name, r]) => ({
      engine: r?.engine_name ?? name,
      category: r?.category ?? 'undetected',
      result: r?.result ?? null,
    }))
    .sort(
      (a, b) =>
        (CATEGORY_ORDER[a.category] ?? 9) - (CATEGORY_ORDER[b.category] ?? 9) ||
        a.engine.localeCompare(b.engine),
    )
}

function toIso(unixSeconds: number | undefined) {
  return unixSeconds ? new Date(unixSeconds * 1000).toISOString() : null
}

function formatBytes(bytes: number) {
  if (!bytes) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB']
  const i = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1)
  return `${(bytes / 1024 ** i).toFixed(i === 0 ? 0 : 1)} ${units[i]}`
}

function compact(items: (DetailItem | null)[]): DetailItem[] {
  return items.filter((i): i is DetailItem => !!i && !!i.value)
}

function urlDetails(a: Json): DetailItem[] {
  const categories = a?.categories ? Array.from(new Set(Object.values(a.categories) as string[])).join(', ') : ''
  return compact([
    { label: 'URL', value: a?.url ?? '' },
    a?.last_final_url && a.last_final_url !== a.url ? { label: 'Final URL', value: a.last_final_url } : null,
    { label: 'Page title', value: a?.title ?? '' },
    a?.last_http_response_code ? { label: 'HTTP status', value: String(a.last_http_response_code) } : null,
    { label: 'Categories', value: categories },
    typeof a?.reputation === 'number' ? { label: 'Community reputation', value: String(a.reputation) } : null,
  ])
}

function fileDetails(a: Json): DetailItem[] {
  return compact([
    { label: 'Name', value: a?.meaningful_name ?? a?.names?.[0] ?? '' },
    { label: 'Type', value: a?.type_description ?? a?.magic ?? '' },
    typeof a?.size === 'number' ? { label: 'Size', value: formatBytes(a.size) } : null,
    { label: 'SHA-256', value: a?.sha256 ?? '' },
    { label: 'MD5', value: a?.md5 ?? '' },
    { label: 'Threat label', value: a?.popular_threat_classification?.suggested_threat_label ?? '' },
  ])
}

export function reportFromObject(data: Json, kind: 'url' | 'file'): ScanResponse {
  const a = data?.attributes ?? {}
  const stats = normalizeStats(a.last_analysis_stats)
  return {
    status: 'completed',
    verdict: verdictFrom(stats),
    stats,
    engines: normalizeEngines(a.last_analysis_results),
    details: kind === 'url' ? urlDetails(a) : fileDetails(a),
    scannedAt: toIso(a.last_analysis_date),
    permalink: `https://www.virustotal.com/gui/${kind}/${data?.id}`,
  }
}

export function reportFromAnalysis(body: Json): ScanResponse {
  const a = body?.data?.attributes ?? {}
  if (a.status !== 'completed') {
    return { status: 'queued', analysisId: body?.data?.id }
  }
  const stats = normalizeStats(a.stats)
  const fileInfo = body?.meta?.file_info
  const urlInfo = body?.meta?.url_info
  const details = fileInfo
    ? fileDetails({ ...fileInfo })
    : compact([{ label: 'URL', value: urlInfo?.url ?? '' }])
  const permalink = fileInfo?.sha256
    ? `https://www.virustotal.com/gui/file/${fileInfo.sha256}`
    : urlInfo?.id
      ? `https://www.virustotal.com/gui/url/${urlInfo.id}`
      : null

  return {
    status: 'completed',
    verdict: verdictFrom(stats),
    stats,
    engines: normalizeEngines(a.results),
    details,
    scannedAt: toIso(a.date),
    permalink,
  }
}

export function errorResponse(error: unknown) {
  if (error instanceof VTError) {
    return Response.json({ error: error.message }, { status: error.status })
  }
  console.error('[scanner] unexpected error', error)
  return Response.json({ error: 'Unexpected server error.' }, { status: 500 })
}
