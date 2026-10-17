import { errorResponse, reportFromAnalysis, vtFetch } from '@/lib/virustotal'

export const runtime = 'nodejs'

const ANALYSIS_ID_RE = /^[A-Za-z0-9_=-]{8,200}$/

export async function GET(_request: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params
    if (!ANALYSIS_ID_RE.test(id)) {
      return Response.json({ error: 'Invalid analysis id.' }, { status: 400 })
    }
    const body = await vtFetch(`/analyses/${encodeURIComponent(id)}`)
    if (!body) {
      return Response.json({ error: 'Analysis not found.' }, { status: 404 })
    }
    return Response.json(reportFromAnalysis(body))
  } catch (error) {
    return errorResponse(error)
  }
}
