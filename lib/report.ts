import type { DeepScanResponse, OsintResponse, PdfReportInput, PdfSection, ScanResponse, StaticAnalysis } from './types'

type Completed = Extract<ScanResponse, { status: 'completed' }>

const VERDICT_LABEL: Record<string, string> = {
  malicious: 'Malicious',
  suspicious: 'Suspicious',
  safe: 'Safe',
}

export function formatBytes(bytes: number) {
  if (!bytes) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB']
  const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1)
  return `${(bytes / 1024 ** index).toFixed(index === 0 ? 0 : 1)} ${units[index]}`
}

function statsRows(result: Completed): [string, string][] {
  const flagged = result.stats.malicious + result.stats.suspicious
  const total =
    result.stats.malicious + result.stats.suspicious + result.stats.harmless + result.stats.undetected
  return [
    ['Verdict', VERDICT_LABEL[result.verdict] ?? result.verdict],
    ['Engines flagged', `${flagged} of ${total}`],
    ['Malicious', String(result.stats.malicious)],
    ['Suspicious', String(result.stats.suspicious)],
    ['Harmless', String(result.stats.harmless)],
    ['Undetected', String(result.stats.undetected)],
    ['Last analysis', result.scannedAt ? new Date(result.scannedAt).toLocaleString() : 'unknown'],
  ]
}

function engineSection(result: Completed): PdfSection {
  const flagged = result.engines.filter((engine) => engine.category === 'malicious' || engine.category === 'suspicious')
  if (flagged.length === 0) {
    return {
      heading: 'VirusTotal engines',
      text: `No engine flagged this target. ${result.engines.length} engines reported a clean result.`,
    }
  }
  return {
    heading: `Flagged engines (${flagged.length})`,
    rows: flagged.slice(0, 200).map((engine) => [
      engine.engine,
      `${engine.result ?? engine.category} (${engine.category})`,
    ]),
  }
}

export function scanPdfReport(
  kind: 'url' | 'file',
  target: string,
  result: Completed,
): PdfReportInput {
  const sections: PdfSection[] = [
    { heading: 'Target', rows: [[kind === 'url' ? 'URL' : 'File', target]] },
    { heading: 'Verdict', rows: statsRows(result) },
    { heading: 'Details', rows: result.details.map((detail) => [detail.label, detail.value]) },
    engineSection(result),
  ]

  if (result.permalink) {
    sections.push({ heading: 'References', rows: [['VirusTotal report', result.permalink]] })
  }

  return {
    title: kind === 'url' ? 'URL scan report' : 'File scan report',
    subtitle: target,
    sections,
  }
}

function analysisSections(analysis: StaticAnalysis): PdfSection[] {
  const findings = analysis.findings.length
    ? analysis.findings.map<[string, string]>((finding) => [
        `${finding.title} (${finding.severity})`,
        finding.detail,
      ])
    : undefined

  return [
    {
      heading: 'Summary',
      text:
        analysis.verdict === 'malicious'
          ? 'Multiple malicious indicators were found. Treat this file as dangerous: do not open or run it.'
          : analysis.verdict === 'suspicious'
            ? 'Some suspicious behaviour was detected. Only open this file if you trust the sender and you can verify it.'
            : 'Static analysis found no obvious malicious indicators. This is not proof of safety — unsigned or new files can still be harmful.',
    },
    {
      heading: 'Static analysis',
      rows: [
        ['Verdict', VERDICT_LABEL[analysis.verdict] ?? analysis.verdict],
        ['Risk score', String(analysis.score)],
        ['File name', analysis.fileName],
        ['File type', analysis.fileType],
        ['Size', formatBytes(analysis.size)],
        ['Entropy', `${analysis.entropy} / 8`],
        ['Analysis mode', 'Offline static analysis (no code executed)'],
      ],
    },
    {
      heading: 'Hashes',
      rows: [
        ['SHA-256', analysis.sha256],
        ['MD5', analysis.md5],
      ],
    },
    { heading: `Findings (${analysis.findings.length})`, rows: findings, text: findings ? undefined : 'No suspicious patterns matched.' },
  ]
}

function indicatorSection(analysis: StaticAnalysis): PdfSection | null {
  const { urls, ips, emails, commands } = analysis.indicators
  const rows: [string, string][] = []
  if (urls.length) rows.push(['URLs', urls.slice(0, 30).join('\n')])
  if (ips.length) rows.push(['IP addresses', ips.slice(0, 30).join('\n')])
  if (emails.length) rows.push(['Email addresses', emails.slice(0, 30).join('\n')])
  if (commands.length) rows.push(['Commands', commands.slice(0, 20).join('\n')])
  return rows.length ? { heading: 'Indicators of compromise', rows } : null
}

function peSection(analysis: StaticAnalysis): PdfSection | null {
  if (!analysis.pe) return null
  return {
    heading: 'Portable Executable (PE)',
    rows: [
      ['Format', analysis.pe.format],
      ['Architecture', analysis.pe.machine],
      ['Sections', String(analysis.pe.sections)],
      ['Subsystem', analysis.pe.subsystem ?? 'unknown'],
      ['Packer detected', analysis.pe.packed ? 'Yes' : 'No'],
    ],
  }
}

function vtSection(vt: ScanResponse | null, vtError: string | null): PdfSection {
  if (vt?.status === 'completed') {
    const rows: [string, string][] = statsRows(vt)
    if (vt.permalink) rows.push(['Report link', vt.permalink])
    const flagged = vt.engines.filter(
      (engine) => engine.category === 'malicious' || engine.category === 'suspicious',
    )
    if (flagged.length) {
      rows.push(['Flagged engines', flagged.map((engine) => `${engine.engine}: ${engine.result ?? engine.category}`).join('\n')])
    }
    return { heading: 'VirusTotal multi-engine scan', rows }
  }
  if (vt?.status === 'queued') {
    return {
      heading: 'VirusTotal multi-engine scan',
      text: 'The file was submitted to VirusTotal but the analysis was still queued when this report was generated.',
    }
  }
  return {
    heading: 'VirusTotal multi-engine scan',
    text: vtError ?? 'VirusTotal results are not available for this file. The offline analysis above is complete.',
  }
}

export function deepPdfReport(data: DeepScanResponse): PdfReportInput {
  const sections = [...analysisSections(data.analysis)]
  const indicators = indicatorSection(data.analysis)
  if (indicators) sections.push(indicators)
  const pe = peSection(data.analysis)
  if (pe) sections.push(pe)
  sections.push(vtSection(data.vt, data.vtError))

  return {
    title: 'File analysis report',
    subtitle: `${data.analysis.fileName} — HACKERADE static analysis`,
    sections,
  }
}

export function osintPdfReport(data: OsintResponse): PdfReportInput {
  const sections: PdfSection[] = [
    {
      heading: 'Target',
      rows: [
        ['Target', data.target],
        ['Resolved IP', data.resolvedIp ?? 'unknown'],
      ],
    },
  ]

  if (data.host) {
    sections.push({
      heading: 'Host intelligence',
      rows: [
        ['IP', data.host.ip],
        ['Hostnames', data.host.hostnames.join(', ') || 'none'],
        ['Organisation', data.host.org ?? 'unknown'],
        ['ISP', data.host.isp ?? 'unknown'],
        ['ASN', data.host.asn ?? 'unknown'],
        ['Location', [data.host.city, data.host.country].filter(Boolean).join(', ') || 'unknown'],
        ['Operating system', data.host.os ?? 'unknown'],
        ['Open ports', data.host.ports.join(', ') || 'none'],
        ['Known vulnerabilities', data.host.vulns.join(', ') || 'none'],
      ],
    })

    if (data.host.services.length) {
      sections.push({
        heading: 'Exposed services',
        rows: data.host.services.slice(0, 100).map((service) => [
          `${service.port}/${service.transport}`,
          [service.product, service.version].filter(Boolean).join(' ') || service.banner || 'unknown',
        ]),
      })
    }
  }

  if (data.dns) {
    sections.push({
      heading: 'Subdomains',
      text: data.dns.subdomains.join(', ') || 'No subdomains found.',
    })
    if (data.dns.records.length) {
      sections.push({
        heading: 'DNS records',
        rows: data.dns.records.slice(0, 200).map((record) => [
          record.type,
          `${record.value}${record.lastSeen ? ` (last seen ${record.lastSeen})` : ''}`,
        ]),
      })
    }
  }

  if (data.search) {
    sections.push({
      heading: 'Shodan deep search',
      text: data.search.error
        ? `Search failed: ${data.search.error}`
        : `${data.search.total} matching services found.`,
      rows: data.search.matches.slice(0, 100).map((match) => [
        `${match.ip}:${match.port}`,
        [match.product, match.org, match.country, match.hostname].filter(Boolean).join(' | ') || 'unknown',
      ]),
    })
  }

  if (data.errors.length) {
    sections.push({ heading: 'Lookup notes', text: data.errors.join('\n') })
  }

  return { title: 'OSINT report', subtitle: data.target, sections }
}

export function deepAiContext(data: DeepScanResponse): string {
  const { analysis } = data
  const lines = [
    `File: ${analysis.fileName} (${formatBytes(analysis.size)}, ${analysis.fileType})`,
    `SHA-256: ${analysis.sha256}`,
    `Static verdict: ${analysis.verdict} (score ${analysis.score})`,
    `Entropy: ${analysis.entropy}/8`,
  ]

  if (analysis.pe) {
    lines.push(
      `PE: ${analysis.pe.format}, ${analysis.pe.machine}, ${analysis.pe.sections} sections, packed=${analysis.pe.packed ? 'yes' : 'no'}`,
    )
  }

  lines.push(
    `Findings: ${
      analysis.findings.length
        ? analysis.findings.map((finding) => `${finding.severity.toUpperCase()} ${finding.title} — ${finding.detail}`).join('; ')
        : 'none'
    }`,
  )

  const { urls, ips, emails, commands } = analysis.indicators
  if (urls.length) lines.push(`URLs: ${urls.slice(0, 12).join(', ')}`)
  if (ips.length) lines.push(`IPs: ${ips.slice(0, 12).join(', ')}`)
  if (emails.length) lines.push(`Emails: ${emails.slice(0, 8).join(', ')}`)
  if (commands.length) lines.push(`Commands: ${commands.slice(0, 8).join(' | ')}`)

  if (data.vt?.status === 'completed') {
    const { vt } = data
    lines.push(
      `VirusTotal: ${vt.stats.malicious} malicious, ${vt.stats.suspicious} suspicious, ${vt.stats.harmless} harmless, ${vt.stats.undetected} undetected engines.`,
    )
    const flagged = vt.engines
      .filter((engine) => engine.category === 'malicious' || engine.category === 'suspicious')
      .slice(0, 12)
      .map((engine) => `${engine.engine}: ${engine.result ?? engine.category}`)
    if (flagged.length) lines.push(`Flagged by: ${flagged.join('; ')}`)
  } else if (data.vtError) {
    lines.push(`VirusTotal unavailable: ${data.vtError}`)
  } else if (data.vt?.status === 'queued') {
    lines.push('VirusTotal analysis was still pending when the report was created.')
  }

  lines.push('No code was executed; this is static analysis of the file contents.')
  return lines.join('\n')
}
