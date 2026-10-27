'use client'

import { useState } from 'react'
import { FileDown, Loader2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { downloadPdf } from '@/lib/pdf-client'
import type { PdfReportInput } from '@/lib/types'

export function PdfButton({
  report,
  fileName,
  label = 'Download PDF',
  variant = 'outline',
  size = 'sm',
  className,
}: {
  report: PdfReportInput
  fileName: string
  label?: string
  variant?: 'default' | 'outline' | 'secondary' | 'ghost'
  size?: 'default' | 'sm' | 'lg'
  className?: string
}) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const onClick = async () => {
    setBusy(true)
    setError(null)
    try {
      await downloadPdf(report, fileName)
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Could not download the PDF.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className={className}>
      <Button variant={variant} size={size} onClick={onClick} disabled={busy}>
        {busy ? <Loader2 className="animate-spin" /> : <FileDown />}
        {busy ? 'Preparing…' : label}
      </Button>
      {error && (
        <p className="mt-1 max-w-56 text-xs text-malicious" role="alert">
          {error}
        </p>
      )}
    </div>
  )
}
