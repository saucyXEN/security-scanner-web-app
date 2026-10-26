'use client'

import { useEffect, useState } from 'react'
import { AlertTriangle, Loader2, type LucideIcon } from 'lucide-react'
import { Card, CardContent } from '@/components/ui/card'

function useElapsedSeconds() {
  const [seconds, setSeconds] = useState(0)
  useEffect(() => {
    const id = window.setInterval(() => setSeconds((s) => s + 1), 1000)
    return () => window.clearInterval(id)
  }, [])
  return seconds
}

function formatElapsed(seconds: number) {
  return `${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, '0')}`
}

export function PendingState({ title, description }: { title: string; description: string }) {
  const elapsed = useElapsedSeconds()
  return (
    <Card>
      <CardContent className="flex items-center gap-4 py-6" role="status" aria-live="polite">
        <div className="flex size-12 shrink-0 items-center justify-center rounded-xl bg-primary/10 ring-1 ring-primary/30">
          <Loader2 className="size-6 animate-spin text-primary" aria-hidden="true" />
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex items-baseline justify-between gap-4">
            <p className="font-medium">{title}</p>
            <span className="font-mono text-xs tabular-nums text-muted-foreground" aria-hidden="true">
              {formatElapsed(elapsed)}
            </span>
          </div>
          <p className="text-sm text-muted-foreground">{description}</p>
        </div>
      </CardContent>
    </Card>
  )
}

export function ErrorState({ message }: { message: string }) {
  return (
    <Card className="ring-malicious/35">
      <CardContent className="flex items-start gap-3" role="alert">
        <AlertTriangle className="mt-0.5 size-5 shrink-0 text-malicious" aria-hidden="true" />
        <p className="text-sm">{message}</p>
      </CardContent>
    </Card>
  )
}

export function EmptyState({ icon: Icon, title, description }: { icon: LucideIcon; title: string; description: string }) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 rounded-xl border border-dashed border-border px-6 py-16 text-center">
      <div className="flex size-12 items-center justify-center rounded-xl bg-secondary">
        <Icon className="size-6 text-muted-foreground" aria-hidden="true" />
      </div>
      <p className="font-medium">{title}</p>
      <p className="max-w-md text-pretty text-sm text-muted-foreground">{description}</p>
    </div>
  )
}
