import { createHash } from 'node:crypto'
import { errorResponse, reportFromObject, vtFetch } from '@/lib/virustotal'
import type { ScanResponse } from '@/lib/types'

export const runtime = 'nodejs'

// VirusTotal's public API accepts files up to 32 MB.
const MAX_UPLOAD_BYTES = 32 * 1024 * 1024
const HASH_RE = /^[a-f0-9]{64}$/i

export async function GET(request: Request) {
  try {
    const hash = new URL(request.url).searchParams.get('hash') ?? ''
    if (!HASH_RE.test(hash)) {
      return Response.json({ error: 'Invalid SHA-256 hash.' }, { status: 400 })
    }
    const existing = await vtFetch(`/files/${hash.toLowerCase()}`)
    if (!existing?.data?.attributes?.last_analysis_date) {
      return Response.json({ status: 'unknown' })
    }
    return Response.json(reportFromObject(existing.data, 'file') satisfies ScanResponse)
  } catch (error) {
    return errorResponse(error)
  }
}

export async function POST(request: Request) {
  try {
    const form = await request.formData().catch(() => null)
    const file = form?.get('file')
    if (!(file instanceof File) || file.size === 0) {
      return Response.json({ error: 'Please choose a non-empty file.' }, { status: 400 })
    }
    if (file.size > MAX_UPLOAD_BYTES) {
      return Response.json({ error: 'File is larger than the 32 MB upload limit.' }, { status: 413 })
    }

    const buffer = Buffer.from(await file.arrayBuffer())
    const sha256 = createHash('sha256').update(buffer).digest('hex')

    const existing = await vtFetch(`/files/${sha256}`)
    if (existing?.data?.attributes?.last_analysis_date) {
      return Response.json(reportFromObject(existing.data, 'file') satisfies ScanResponse)
    }

    const upload = new FormData()
    upload.append('file', new Blob([buffer]), file.name || 'upload.bin')
    const submitted = await vtFetch('/files', { method: 'POST', body: upload })
    return Response.json({ status: 'queued', analysisId: submitted?.data?.id } satisfies ScanResponse)
  } catch (error) {
    return errorResponse(error)
  }
}
