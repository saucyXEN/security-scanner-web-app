import { askOllama, OllamaError, ollamaStatus } from '@/lib/ollama'

export const runtime = 'nodejs'
export const maxDuration = 120

const MAX_PROMPT_CHARS = 16_000

export async function GET() {
  return Response.json(await ollamaStatus())
}

export async function POST(request: Request) {
  const body = await request.json().catch(() => null)
  const prompt = typeof body?.prompt === 'string' ? body.prompt.trim() : ''
  if (!prompt) {
    return Response.json({ error: 'Ask a question about the scan first.' }, { status: 400 })
  }

  try {
    const result = await askOllama(prompt.slice(0, MAX_PROMPT_CHARS))
    return Response.json(result)
  } catch (error) {
    if (error instanceof OllamaError) {
      return Response.json({ error: error.message }, { status: error.status })
    }
    console.error('[ai] unexpected error', error)
    return Response.json({ error: 'The AI request failed unexpectedly.' }, { status: 500 })
  }
}
