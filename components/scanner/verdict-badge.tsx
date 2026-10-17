import { ShieldAlert, ShieldCheck, ShieldQuestion } from 'lucide-react'
import { cn } from '@/lib/utils'
import type { Verdict } from '@/lib/types'

export const VERDICT_META: Record<
  Verdict,
  { label: string; text: string; bg: string; ring: string; icon: typeof ShieldCheck }
> = {
  malicious: {
    label: 'Malicious',
    text: 'text-malicious',
    bg: 'bg-malicious/12',
    ring: 'ring-malicious/35',
    icon: ShieldAlert,
  },
  suspicious: {
    label: 'Suspicious',
    text: 'text-suspicious',
    bg: 'bg-suspicious/12',
    ring: 'ring-suspicious/35',
    icon: ShieldQuestion,
  },
  safe: {
    label: 'Safe',
    text: 'text-safe',
    bg: 'bg-safe/12',
    ring: 'ring-safe/35',
    icon: ShieldCheck,
  },
}

export function VerdictBadge({ verdict, className }: { verdict: Verdict; className?: string }) {
  const meta = VERDICT_META[verdict]
  const Icon = meta.icon
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 rounded-sm px-2.5 py-1 font-mono text-[11px] font-bold uppercase tracking-[0.15em] ring-1',
        meta.text,
        meta.bg,
        meta.ring,
        className,
      )}
    >
      <Icon className="size-3.5" aria-hidden="true" />
      {meta.label}
    </span>
  )
}
