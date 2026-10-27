import { buildPdf } from '@/lib/pdf'
import type { PdfReportInput, PdfSection } from '@/lib/types'

export const runtime = 'nodejs'

const MAX_SECTIONS = 80
const MAX_ROWS = 400
const MAX_TEXT = 20_000

function asText(value: unknown, limit: number) {
  return typeof value === 'string' ? value.slice(0, limit) : null
}

function normalize(input: unknown): PdfReportInput | null {
  if (!input || typeof input !== 'object') return null
  const raw = input as Record<string, unknown>
  const title = asText(raw.title, 300)?.trim()
  if (!title) return null

  const subtitle = asText(raw.subtitle, 800)?.trim() || undefined
  const sections: PdfSection[] = []

  if (Array.isArray(raw.sections)) {
    for (const entry of raw.sections.slice(0, MAX_SECTIONS)) {
      if (!entry || typeof entry !== 'object') continue
      const section = entry as Record<string, unknown>
      const heading = asText(section.heading, 300)?.trim()
      if (!heading) continue

      const rows: [string, string][] = []
      if (Array.isArray(section.rows)) {
        for (const row of section.rows.slice(0, MAX_ROWS)) {
          if (!Array.isArray(row) || row.length < 2) continue
          const label = asText(row[0], 300)
          const value = asText(row[1], 4_000)
          if (label === null || value === null) continue
          rows.push([label, value])
        }
      }

      const text = asText(section.text, MAX_TEXT) ?? undefined
      if (!text && rows.length === 0) continue
      sections.push({ heading, rows, text })
    }
  }

  if (sections.length === 0) return null
  return { title, subtitle, sections }
}

export async function POST(request: Request) {
  const body = await request.json().catch(() => null)
  const input = normalize(body)
  if (!input) {
    return Response.json({ error: 'A report title and at least one section are required.' }, { status: 400 })
  }

  try {
    const pdf = await buildPdf(input)
    return new Response(new Uint8Array(pdf), {
      headers: {
        'content-type': 'application/pdf',
        'content-disposition': 'attachment; filename="hackerade-report.pdf"',
        'cache-control': 'no-store',
      },
    })
  } catch (error) {
    console.error('[pdf] generation failed', error)
    return Response.json({ error: 'Could not generate the PDF report.' }, { status: 500 })
  }
}
