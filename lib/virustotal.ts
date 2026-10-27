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

export async function vtFetch(path: string, init: RequestInit = {}, timeoutMs = 30_000): Promise<Json | null> {
  let res: Response
  try {
    res = await fetch(`${VT_BASE}${path}`, {
      ...init,
      headers: { 'x-apikey': apiKey(), accept: 'application/json', ...init.headers },
      cache: 'no-store',
      signal: init.signal ?? AbortSignal.timeout(timeoutMs),
    })
  } catch (error) {
    if (error instanceof Error && (error.name === 'TimeoutError' || error.name === 'AbortError')) {
      throw new VTError('VirusTotal did not respond in time. Please try again.', 504)
    }
    throw new VTError('Could not reach VirusTotal. Check the server network connection.', 502)
  }

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

// VirusTotal's standard /files endpoint accepts files up to 32 MB. Larger
// samples must go through /files/upload_url (premium API plans).
const DIRECT_UPLOAD_BYTES = 32 * 1024 * 1024

export async function lookupFileReport(sha256: string): Promise<ScanResponse | null> {
  const existing = await vtFetch(`/files/${sha256}`)
  if (!existing?.data?.attributes?.last_analysis_date) return null
  return reportFromObject(existing.data, 'file')
}

export async function submitFile(buffer: Buffer, fileName: string): Promise<ScanResponse> {
  const form = new FormData()
  form.append('file', new Blob([buffer]), fileName || 'upload.bin')

  if (buffer.length <= DIRECT_UPLOAD_BYTES) {
    const submitted = await vtFetch('/files', { method: 'POST', body: form }, 300_000)
    if (!submitted?.data?.id) throw new VTError('VirusTotal did not accept the file.', 502)
    return { status: 'queued', analysisId: submitted.data.id }
  }

  const slot = await vtFetch('/files/upload_url')
  const uploadUrl = typeof slot?.data === 'string' ? slot.data : null
  if (!uploadUrl) {
    throw new VTError('VirusTotal did not return an upload URL for this large file.', 502)
  }

  let res: Response
  try {
    // Even the pre-signed large-file URL still requires the API key header.
    res = await fetch(uploadUrl, {
      method: 'POST',
      headers: { 'x-apikey': apiKey() },
      body: form,
      signal: AbortSignal.timeout(600_000),
    })
  } catch {
    throw new VTError('Could not upload the large file to VirusTotal.', 502)
  }
  const body = await res.json().catch(() => null)
  if (!res.ok) {
    throw new VTError(
      body?.error?.message ??
        body?.errors?.[0]?.detail ??
        `VirusTotal large-file upload failed (${res.status}).`,
      502,
    )
  }
  const analysisId = body?.data?.id
  if (!analysisId) throw new VTError('VirusTotal did not return an analysis id.', 502)
  return { status: 'queued', analysisId }
}

export function errorResponse(error: unknown) {
  if (error instanceof VTError) {
    return Response.json({ error: error.message }, { status: error.status })
  }
  console.error('[scanner] unexpected error', error)
  return Response.json({ error: 'Unexpected server error.' }, { status: 500 })
}
