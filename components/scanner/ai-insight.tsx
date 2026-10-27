'use client'

import { useState, type KeyboardEvent } from 'react'
import useSWR from 'swr'
import { Bot, Loader2, Send, Sparkles, WifiOff } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { cn } from '@/lib/utils'
import { parseJson } from '@/lib/api-client'
import type { OllamaStatus } from '@/lib/ollama'

type Answer = { answer: string; model: string }

const SUGGESTIONS = [
  'Is this file harmful? Explain why.',
  'What is the biggest risk here?',
  'Explain the findings in simple words.',
  'Hinglish me samjhao — khatra hai ya nahi?',
]

async function fetchStatus(url: string) {
  return parseJson<OllamaStatus>(await fetch(url))
}

function statusBadge(status: OllamaStatus | undefined) {
  if (!status) {
    return { label: 'Checking Ollama…', className: 'text-muted-foreground ring-border' }
  }
  if (!status.reachable) {
    return { label: 'Ollama offline', className: 'text-muted-foreground ring-border' }
  }
  if (!status.modelInstalled) {
    return { label: `Missing model: ${status.model}`, className: 'text-suspicious ring-suspicious/40' }
  }
  return { label: `${status.model} ready`, className: 'text-safe ring-safe/40' }
}

export function AiInsight({ context }: { context: string }) {
  const { data: status } = useSWR('/api/ai/analyze', fetchStatus, {
    revalidateOnFocus: false,
    shouldRetryOnError: false,
  })
  const [question, setQuestion] = useState('Is this file harmful? Explain the main risks.')
  const [answer, setAnswer] = useState<Answer | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  const badge = statusBadge(status)

  const ask = async () => {
    const prompt = question.trim()
    if (!prompt || loading) return
    setLoading(true)
    setError(null)
    try {
      const response = await fetch('/api/ai/analyze', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          prompt: `Scan report:\n${context}\n\nUser question: ${prompt}`,
        }),
      })
      setAnswer(await parseJson<Answer>(response))
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'The AI request failed.')
      setAnswer(null)
    } finally {
      setLoading(false)
    }
  }

  const onKeyDown = (event: KeyboardEvent<HTMLTextAreaElement>) => {
    if ((event.metaKey || event.ctrlKey) && event.key === 'Enter') {
      event.preventDefault()
      void ask()
    }
  }

  return (
    <Card className="ring-primary/25">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Bot className="size-4 text-primary" aria-hidden="true" />
          Ask the AI analyst
        </CardTitle>
        <CardDescription>
          Runs locally with Ollama. The scan report is sent only to your own Ollama server, never to a cloud API.
        </CardDescription>
        <CardAction>
          <span
            className={cn(
              'inline-flex items-center gap-1.5 rounded-sm px-2 py-1 font-mono text-[10px] uppercase tracking-[0.14em] ring-1',
              badge.className,
            )}
          >
            {status?.reachable ? <Sparkles className="size-3" /> : <WifiOff className="size-3" />}
            {badge.label}
          </span>
        </CardAction>
      </CardHeader>

      <CardContent className="flex flex-col gap-3">
        <div className="flex flex-wrap gap-2">
          {SUGGESTIONS.map((suggestion) => (
            <button
              key={suggestion}
              type="button"
              onClick={() => setQuestion(suggestion)}
              className="rounded-full border border-border px-3 py-1 text-xs text-muted-foreground transition-colors hover:border-neutral-400 hover:text-foreground"
            >
              {suggestion}
            </button>
          ))}
        </div>

        <label htmlFor="ai-question" className="sr-only">
          Ask about this scan
        </label>
        <textarea
          id="ai-question"
          value={question}
          onChange={(event) => setQuestion(event.target.value)}
          onKeyDown={onKeyDown}
          rows={3}
          spellCheck={false}
          placeholder="Ask whether this file is harmful, what the findings mean, or what to do next…"
          className="w-full resize-y rounded-lg border border-input bg-transparent px-3 py-2 text-sm outline-none transition-colors placeholder:text-muted-foreground focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50"
        />

        <div className="flex flex-wrap items-center justify-between gap-2">
          <p className="text-xs text-muted-foreground">Ctrl/⌘ + Enter to send. First answer can take a few seconds.</p>
          <Button size="sm" onClick={ask} disabled={loading || !question.trim()}>
            {loading ? <Loader2 className="animate-spin" /> : <Send />}
            {loading ? 'Thinking…' : 'Ask AI'}
          </Button>
        </div>

        {error && (
          <div className="rounded-lg border border-suspicious/40 bg-suspicious/10 p-3 text-sm" role="alert">
            <p className="font-medium">AI unavailable</p>
            <p className="mt-1 text-muted-foreground">{error}</p>
          </div>
        )}

        {answer && (
          <div className="rounded-lg bg-secondary/60 p-4">
            <p className="mb-2 font-mono text-[10px] uppercase tracking-[0.16em] text-muted-foreground">
              {answer.model} / local
            </p>
            <div className="whitespace-pre-wrap text-sm leading-relaxed">{answer.answer}</div>
          </div>
        )}

        <p className="text-xs text-muted-foreground">
          AI answers are advisory. Static analysis can miss behaviour, so never open a suspicious file just because the
          model says it is safe.
        </p>
      </CardContent>
    </Card>
  )
}
