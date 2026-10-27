import { createHash } from 'node:crypto'
import type { Finding, Severity, StaticAnalysis, Verdict } from './types'

const EICAR = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'

const TEXT_EXTENSIONS = new Set([
  'txt', 'log', 'csv', 'json', 'xml', 'html', 'htm', 'css', 'md', 'yml', 'yaml', 'ini', 'conf',
  'js', 'mjs', 'cjs', 'ts', 'jsx', 'tsx', 'py', 'rb', 'php', 'sh', 'bash', 'zsh', 'bat', 'cmd',
  'ps1', 'vbs', 'vbe', 'wsf', 'hta', 'pl', 'lua', 'sql', 'java', 'c', 'cpp', 'h', 'cs', 'go', 'rs',
])

const SCRIPT_EXTENSIONS = new Set(['bat', 'cmd', 'ps1', 'vbs', 'vbe', 'wsf', 'hta', 'sh', 'bash', 'js', 'py', 'pl'])

const DOUBLE_EXTENSION = /\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|csv|zip|rar|7z|mp3|mp4)\.(exe|scr|com|pif|bat|cmd|js|jse|vbs|vbe|wsf|hta|ps1|msi|lnk)$/i

const SUSPICIOUS_PATTERNS: { pattern: RegExp; title: string; severity: Severity; detail: string; points: number }[] = [
  {
    pattern: /powershell(?:\.exe)?[^\r\n]{0,80}(?:-enc|-encodedcommand|-e\s|bypass|hidden|noprofile)/i,
    title: 'Obfuscated PowerShell command',
    severity: 'high',
    detail: 'Encoded or hidden PowerShell is a common malware launcher.',
    points: 4,
  },
  {
    pattern: /\b(?:Invoke-Expression|IEX)\s*[\(\s]/i,
    title: 'PowerShell Invoke-Expression',
    severity: 'medium',
    detail: 'Executes a string as code, often used to hide the real payload.',
    points: 3,
  },
  {
    pattern: /\b(?:mshta|regsvr32|rundll32|wscript|cscript)\b/i,
    title: 'Living-off-the-land binary referenced',
    severity: 'medium',
    detail: 'Windows tools that malware abuses to execute code without dropping an EXE.',
    points: 2,
  },
  {
    pattern: /\b(?:VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|SetWindowsHookEx|QueueUserAPC)\b/,
    title: 'Process injection APIs',
    severity: 'high',
    detail: 'The sample references APIs commonly used to inject code into other processes.',
    points: 4,
  },
  {
    pattern: /\b(?:URLDownloadToFile|InternetOpenUrl|WinHttpOpen|curl\s+-[a-zA-Z]*O|wget\s+http)/i,
    title: 'Downloads a remote payload',
    severity: 'medium',
    detail: 'The sample can fetch additional content from the internet.',
    points: 3,
  },
  {
    pattern: /(?:schtasks(?:\.exe)?\s+\/create|reg\s+add[^\r\n]{0,80}\\\\?Run)/i,
    title: 'Persistence mechanism',
    severity: 'high',
    detail: 'Creates a scheduled task or Run key so it survives a reboot.',
    points: 4,
  },
  {
    pattern: /\/etc\/(?:passwd|shadow)|\/bin\/(?:ba)?sh\b|chmod\s+\+x/i,
    title: 'Suspicious Linux commands',
    severity: 'medium',
    detail: 'Credential files or shell execution patterns found in the sample.',
    points: 3,
  },
  {
    pattern: /(?:base64\s*,?\s*|FromBase64String\s*\(\s*['"])[A-Za-z0-9+/]{200,}/i,
    title: 'Large base64 blob',
    severity: 'medium',
    detail: 'A long encoded blob can hide a second-stage payload.',
    points: 3,
  },
  {
    pattern: /\beval\s*\(\s*(?:atob|base64_decode|String\.fromCharCode)/i,
    title: 'Encoded script execution',
    severity: 'high',
    detail: 'Decodes and executes embedded code at runtime.',
    points: 4,
  },
  {
    pattern: /\b(?:ransom|bitcoin wallet|decryptor|your files (?:are|have been) encrypted)\b/i,
    title: 'Ransomware wording',
    severity: 'medium',
    detail: 'Text associated with ransomware notes or payment instructions.',
    points: 3,
  },
  {
    pattern: /\b(?:AutoOpen|Document_Open|Workbook_Open)\s*\(/,
    title: 'Office macro auto-run',
    severity: 'high',
    detail: 'A macro that runs as soon as the document is opened.',
    points: 4,
  },
]

const URL_RE = /https?:\/\/[^\s"'<>()]{4,200}/gi
const IPV4_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g
const EMAIL_RE = /[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/gi

function entropy(buffer: Buffer) {
  const sample = buffer.subarray(0, Math.min(buffer.length, 4 * 1024 * 1024))
  if (!sample.length) return 0
  const counts = new Array<number>(256).fill(0)
  for (const byte of sample) counts[byte] += 1
  let result = 0
  for (const count of counts) {
    if (!count) continue
    const p = count / sample.length
    result -= p * Math.log2(p)
  }
  return Math.round(result * 100) / 100
}

function extensionOf(name: string) {
  const index = name.lastIndexOf('.')
  return index >= 0 ? name.slice(index + 1).toLowerCase() : ''
}

function detectType(buffer: Buffer, extension: string): string {
  const ascii = buffer.subarray(0, 8).toString('latin1')
  if (buffer.length >= 2 && buffer.readUInt16LE(0) === 0x5a4d) return 'Windows executable (MZ/PE)'
  if (ascii.startsWith('\x7fELF')) return 'Linux executable (ELF)'
  if (/^\xfe\xed\xfa[\xce\xcf]|^\xcf\xfa\xed\xfe/.test(ascii)) return 'macOS executable (Mach-O)'
  if (ascii.startsWith('%PDF')) return 'PDF document'
  if (ascii.startsWith('PK\x03\x04')) {
    if (buffer.includes('vbaProject.bin')) return 'Office document with macros (OOXML)'
    return 'ZIP archive or Office document'
  }
  if (ascii.startsWith('Rar!')) return 'RAR archive'
  if (ascii.startsWith('7z\xbc\xaf')) return '7-Zip archive'
  if (ascii.startsWith('\xd0\xcf\x11\xe0')) return 'Legacy Office document (OLE)'
  if (ascii.startsWith('\x89PNG')) return 'PNG image'
  if (ascii.startsWith('\xff\xd8\xff')) return 'JPEG image'
  if (ascii.startsWith('GIF8')) return 'GIF image'
  if (ascii.startsWith('#!')) return 'Script with shebang'
  if (SCRIPT_EXTENSIONS.has(extension)) return `Script (.${extension})`
  if (TEXT_EXTENSIONS.has(extension)) return `Text (.${extension})`
  if (!buffer.subarray(0, 512).includes(0)) return 'Unrecognised text-like file'
  return 'Unknown binary'
}

function collectStrings(buffer: Buffer) {
  // Only scan a bounded window so huge files stay fast.
  const window = buffer.subarray(0, Math.min(buffer.length, 8 * 1024 * 1024))
  const ascii = window.toString('latin1').match(/[\x20-\x7e]{4,}/g) ?? []
  const wide = window.toString('utf16le').match(/[\x20-\x7e]{6,}/g) ?? []
  return [...ascii, ...wide]
}

type PeInfo = NonNullable<StaticAnalysis['pe']>

function analysePe(buffer: Buffer): PeInfo | null {
  try {
    if (buffer.length < 64 || buffer.readUInt16LE(0) !== 0x5a4d) return null
    const peOffset = buffer.readUInt32LE(0x3c)
    if (peOffset + 24 > buffer.length || buffer.readUInt32LE(peOffset) !== 0x00004550) return null

    const machineId = buffer.readUInt16LE(peOffset + 4)
    const machine =
      ({ 0x14c: 'x86 (32-bit)', 0x8664: 'x64', 0x1c0: 'ARM', 0xaa64: 'ARM64' } as Record<number, string>)[machineId] ??
      `unknown (0x${machineId.toString(16)})`
    const sectionCount = buffer.readUInt16LE(peOffset + 6)
    const optionalOffset = peOffset + 24
    const optionalMagic = buffer.readUInt16LE(optionalOffset)
    const subsystem =
      ({ 1: 'native', 2: 'GUI', 3: 'console' } as Record<number, string>)[buffer.readUInt16LE(optionalOffset + 68)] ?? null
    const sectionTable = optionalOffset + buffer.readUInt16LE(peOffset + 20)

    const sections: string[] = []
    for (let index = 0; index < sectionCount; index += 1) {
      const start = sectionTable + index * 40
      if (start + 8 > buffer.length) break
      sections.push(buffer.toString('latin1', start, start + 8).replace(/\0.*$/, '').trim())
    }

    return {
      format: optionalMagic === 0x20b ? 'PE32+' : 'PE32',
      machine,
      sections: sectionCount,
      packed: sections.some((name) => /^(upx|aspack|mpress|pecompact|themida|vmprotect)/i.test(name)),
      subsystem,
    }
  } catch {
    return null
  }
}

function severityRank(severity: Severity) {
  return { high: 0, medium: 1, low: 2, info: 3 }[severity]
}

export function analyzeBuffer(buffer: Buffer, fileName: string): StaticAnalysis {
  const extension = extensionOf(fileName)
  const fileType = detectType(buffer, extension)
  const strings = collectStrings(buffer)
  const joined = strings.join('\n')
  const entropyValue = entropy(buffer)
  const findings: Finding[] = []
  let score = 0

  const add = (severity: Severity, title: string, detail: string, points = 0) => {
    findings.push({ severity, title, detail })
    score += points
  }

  const pe = analysePe(buffer)

  if (buffer.includes(EICAR)) {
    add('high', 'EICAR test signature', 'This is the standard antivirus test file. It is harmless by design.', 12)
  }

  if (DOUBLE_EXTENSION.test(fileName)) {
    add('high', 'Double file extension', `The name "${fileName}" hides an executable behind a document-looking extension.`, 5)
  }

  for (const rule of SUSPICIOUS_PATTERNS) {
    if (rule.pattern.test(joined)) add(rule.severity, rule.title, rule.detail, rule.points)
  }

  if (pe?.packed) {
    add('high', 'Packed executable', 'A packer section (UPX/ASPack/Themida…) was found. Packing hides the real code.', 4)
  }

  if (entropyValue >= 7.5 && (pe || /executable|archive/i.test(fileType))) {
    add('medium', 'Very high entropy', `Entropy ${entropyValue}/8 suggests encryption or packing.`, 2)
  }

  if (fileType.includes('macros')) {
    add('high', 'Macros embedded', 'The document contains a VBA macro project and can run code on open.', 4)
  }

  const commands = strings.filter((line) =>
    /\b(?:powershell|cmd(?:\.exe)?\s*\/c|wscript|cscript|mshta|rundll32|regsvr32|curl|wget|schtasks|reg\s+add)\b/i.test(line),
  )
  const urls = [...new Set(joined.match(URL_RE) ?? [])].slice(0, 20)
  const ips = [...new Set(joined.match(IPV4_RE) ?? [])]
    .filter((ip) => !ip.startsWith('0.') && ip !== '127.0.0.1')
    .slice(0, 20)
  const emails = [...new Set(joined.match(EMAIL_RE) ?? [])].slice(0, 20)

  if (urls.length >= 5 && /script|executable/i.test(fileType)) {
    add('low', 'Many embedded URLs', `${urls.length} URLs found, which is unusual for a ${fileType.toLowerCase()}.`, 1)
  }

  if (!findings.some((finding) => finding.severity === 'high') && pe) {
    add('info', 'Native executable', `${fileType}, ${pe.machine}, ${pe.sections} sections. Only code signing and behaviour can confirm safety.`, 0)
  }

  const verdict: Verdict = score >= 10 ? 'malicious' : score >= 3 ? 'suspicious' : 'safe'
  findings.sort((a, b) => severityRank(a.severity) - severityRank(b.severity))

  return {
    status: 'completed',
    fileName,
    size: buffer.length,
    sha256: createHash('sha256').update(buffer).digest('hex'),
    md5: createHash('md5').update(buffer).digest('hex'),
    fileType,
    extension,
    entropy: entropyValue,
    verdict,
    score,
    findings,
    indicators: { urls, ips, emails, commands: commands.slice(0, 15) },
    pe,
    offline: true,
  }
}
