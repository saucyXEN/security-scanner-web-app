import { analyzeBuffer } from '@/lib/static-analysis'
import { lookupFileReport, submitFile } from '@/lib/virustotal'
import type { DeepScanResponse } from '@/lib/types'

export const runtime = 'nodejs'
export const maxDuration = 300

// Above 32 MB VirusTotal needs a premium large-file upload, but the local
// static analysis works for every size. 200 MB keeps memory use sane.
const MAX_UPLOAD_BYTES = 200 * 1024 * 1024

export async function POST(request: Request) {
  const form = await request.formData().catch(() => null)
  const file = form?.get('file')
  if (!(file instanceof File) || file.size === 0) {
    return Response.json({ error: 'Please choose a non-empty file.' }, { status: 400 })
  }
  if (file.size > MAX_UPLOAD_BYTES) {
    return Response.json({ error: 'File is larger than the 200 MB analysis limit.' }, { status: 413 })
  }

  const buffer = Buffer.from(await file.arrayBuffer())
  const analysis = analyzeBuffer(buffer, file.name || 'upload.bin')

  let vt: DeepScanResponse['vt'] = null
  let vtError: string | null = null

  if (form?.get('vt') === 'off') {
    vtError = 'VirusTotal was skipped for this scan. The offline analysis below is complete on its own.'
  } else if (!process.env.VIRUSTOTAL_API_KEY?.trim()) {
    vtError = 'VirusTotal is not configured on this server. The offline analysis below is complete on its own.'
  } else {
    try {
      // A hash lookup is free and covers files seen by VirusTotal before.
      vt = await lookupFileReport(analysis.sha256)
      if (!vt) vt = await submitFile(buffer, analysis.fileName)
    } catch (error) {
      vtError =
        error instanceof Error
          ? error.message
          : 'VirusTotal lookup failed. The offline analysis below is still valid.'
    }
  }

  return Response.json({ analysis, vt, vtError } satisfies DeepScanResponse)
}
