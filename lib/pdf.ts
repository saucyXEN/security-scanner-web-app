import { PDFDocument, StandardFonts, rgb, type PDFFont } from 'pdf-lib'
import type { PdfReportInput, PdfSection } from './types'

const PAGE_WIDTH = 595.28
const PAGE_HEIGHT = 841.89
const MARGIN = 48
const CONTENT_WIDTH = PAGE_WIDTH - MARGIN * 2
const BOTTOM = MARGIN + 20
const LABEL_WIDTH = 140
const VALUE_X = MARGIN + LABEL_WIDTH + 10
const VALUE_WIDTH = CONTENT_WIDTH - LABEL_WIDTH - 10

const INK = rgb(0.09, 0.09, 0.09)
const GRAY = rgb(0.42, 0.42, 0.42)
const RULE = rgb(0.82, 0.82, 0.82)

// Standard PDF fonts only support WinAnsi, so replace anything else with "?".
function clean(value: string) {
  return value
    .replace(/\r\n?/g, '\n')
    .replace(/\t/g, '  ')
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g, ' ')
    .replace(/[^\n\x20-\x7e\u00a0-\u00ff]/g, '?')
}

function wrap(text: string, font: PDFFont, size: number, width: number): string[] {
  const lines: string[] = []

  for (const rawLine of clean(text).split('\n')) {
    const words = rawLine.split(/\s+/).filter(Boolean)
    if (words.length === 0) {
      lines.push('')
      continue
    }

    let current = ''
    for (const word of words) {
      const candidate = current ? `${current} ${word}` : word
      if (font.widthOfTextAtSize(candidate, size) <= width) {
        current = candidate
        continue
      }
      if (current) lines.push(current)

      let rest = word
      while (font.widthOfTextAtSize(rest, size) > width) {
        let cut = Math.max(1, Math.floor((rest.length * width) / font.widthOfTextAtSize(rest, size)))
        while (cut > 1 && font.widthOfTextAtSize(rest.slice(0, cut), size) > width) cut -= 1
        lines.push(rest.slice(0, cut))
        rest = rest.slice(cut)
      }
      current = rest
    }
    if (current) lines.push(current)
  }

  return lines
}

function toRows(section: PdfSection) {
  return (section.rows ?? []).filter((row): row is [string, string] => Array.isArray(row) && row.length === 2)
}

export async function buildPdf(input: PdfReportInput): Promise<Uint8Array> {
  const doc = await PDFDocument.create()
  doc.setTitle(clean(input.title))
  doc.setCreator('HACKERADE scanner')
  doc.setProducer('HACKERADE scanner')
  doc.setCreationDate(new Date())

  const font = await doc.embedFont(StandardFonts.Helvetica)
  const bold = await doc.embedFont(StandardFonts.HelveticaBold)

  let page = doc.addPage([PAGE_WIDTH, PAGE_HEIGHT])
  let y = PAGE_HEIGHT - MARGIN

  const newPage = () => {
    page = doc.addPage([PAGE_WIDTH, PAGE_HEIGHT])
    y = PAGE_HEIGHT - MARGIN
  }

  const ensure = (needed: number) => {
    if (y - needed < BOTTOM) newPage()
  }

  const paragraph = (
    text: string,
    options: {
      font: PDFFont
      size: number
      color: ReturnType<typeof rgb>
      lineHeight: number
      x?: number
      width?: number
      gapAfter?: number
    },
  ) => {
    const x = options.x ?? MARGIN
    const width = options.width ?? CONTENT_WIDTH
    for (const line of wrap(text, options.font, options.size, width)) {
      ensure(options.lineHeight)
      if (line) {
        page.drawText(line, {
          x,
          y: y - options.size,
          size: options.size,
          font: options.font,
          color: options.color,
        })
      }
      y -= options.lineHeight
    }
    y -= options.gapAfter ?? 0
  }

  paragraph(input.title, { font: bold, size: 19, color: INK, lineHeight: 24, gapAfter: 4 })
  if (input.subtitle) {
    paragraph(input.subtitle, { font, size: 10, color: GRAY, lineHeight: 14, gapAfter: 2 })
  }
  paragraph(`Generated ${new Date().toUTCString()}`, { font, size: 8.5, color: GRAY, lineHeight: 12, gapAfter: 10 })

  ensure(1)
  page.drawLine({ start: { x: MARGIN, y }, end: { x: PAGE_WIDTH - MARGIN, y }, thickness: 0.8, color: RULE })
  y -= 18

  for (const section of input.sections) {
    const rows = toRows(section)
    if (!section.text && rows.length === 0) continue

    ensure(46)
    paragraph(section.heading, { font: bold, size: 11.5, color: INK, lineHeight: 16, gapAfter: 5 })

    if (section.text) {
      paragraph(section.text, { font, size: 9.5, color: INK, lineHeight: 13, gapAfter: 6 })
    }

    for (const [label, value] of rows) {
      const labelLines = wrap(label, bold, 8.5, LABEL_WIDTH)
      const valueLines = wrap(value, font, 9, VALUE_WIDTH)
      const height = Math.max(labelLines.length, valueLines.length) * 12.5 + 4
      ensure(height)

      const top = y
      labelLines.forEach((line, index) => {
        page.drawText(line, {
          x: MARGIN,
          y: top - 8.5 - index * 12.5,
          size: 8.5,
          font: bold,
          color: GRAY,
        })
      })
      valueLines.forEach((line, index) => {
        page.drawText(line, {
          x: VALUE_X,
          y: top - 9 - index * 12.5,
          size: 9,
          font,
          color: INK,
        })
      })
      y = top - height
    }

    y -= 10
  }

  const pages = doc.getPages()
  pages.forEach((current, index) => {
    current.drawLine({
      start: { x: MARGIN, y: 30 },
      end: { x: PAGE_WIDTH - MARGIN, y: 30 },
      thickness: 0.6,
      color: RULE,
    })
    current.drawText('HACKERADE // security report', { x: MARGIN, y: 18, size: 7.5, font, color: GRAY })
    const label = `Page ${index + 1} of ${pages.length}`
    current.drawText(label, {
      x: PAGE_WIDTH - MARGIN - font.widthOfTextAtSize(label, 7.5),
      y: 18,
      size: 7.5,
      font,
      color: GRAY,
    })
  })

  return doc.save()
}
