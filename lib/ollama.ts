const DEFAULT_URL = 'http://127.0.0.1:11434'
const DEFAULT_MODEL = 'llama3.2'

export class OllamaError extends Error {
  constructor(
    message: string,
    public status: number,
  ) {
    super(message)
  }
}

export function ollamaConfig() {
  return {
    url: (process.env.OLLAMA_URL?.trim() || DEFAULT_URL).replace(/\/+$/, ''),
    model: process.env.OLLAMA_MODEL?.trim() || DEFAULT_MODEL,
  }
}

export interface OllamaStatus {
  reachable: boolean
  url: string
  model: string
  models: string[]
  modelInstalled: boolean
  error: string | null
}

export async function ollamaStatus(): Promise<OllamaStatus> {
  const { url, model } = ollamaConfig()
  try {
    const response = await fetch(`${url}/api/tags`, {
      headers: { accept: 'application/json' },
      cache: 'no-store',
      signal: AbortSignal.timeout(4_000),
    })
    if (!response.ok) {
      return { reachable: false, url, model, models: [], modelInstalled: false, error: `Ollama answered ${response.status}.` }
    }
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const body: any = await response.json().catch(() => null)
    const models: string[] = Array.isArray(body?.models)
      ? body.models.map((entry: { name?: string }) => String(entry?.name ?? '')).filter(Boolean)
      : []
    const modelInstalled = models.some((name) => name === model || name === `${model}:latest`)
    return {
      reachable: true,
      url,
      model,
      models,
      modelInstalled,
      error: modelInstalled ? null : `Model "${model}" is not pulled yet. Run "ollama pull ${model}".`,
    }
  } catch {
    return {
      reachable: false,
      url,
      model,
      models: [],
      modelInstalled: false,
      error: `Ollama is not running at ${url}. Start it with "ollama serve".`,
    }
  }
}

export const ANALYST_SYSTEM_PROMPT = [
  'You are a malware analyst assistant inside a security scanner.',
  'You get a scan report and must judge how dangerous the target is.',
  'Be concise: 3-6 short bullet points, then one line starting with "Verdict:" using safe, suspicious or malicious.',
  'Explain the reasoning in plain language and say what the user should do next.',
  'Static heuristics are not proof: never promise that a file is 100% safe, and flag when evidence is weak.',
  'Answer in the language the user asked in (English or Hindi/Hinglish are both fine).',
].join(' ')

export async function askOllama(prompt: string): Promise<{ answer: string; model: string }> {
  const { url, model } = ollamaConfig()

  let response: Response
  try {
    response = await fetch(`${url}/api/chat`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        model,
        stream: false,
        messages: [
          { role: 'system', content: ANALYST_SYSTEM_PROMPT },
          { role: 'user', content: prompt },
        ],
        options: { temperature: 0.2 },
      }),
      cache: 'no-store',
      signal: AbortSignal.timeout(120_000),
    })
  } catch {
    throw new OllamaError(
      `Ollama is not reachable at ${url}. Start it with "ollama serve" and pull a model, e.g. "ollama pull ${model}".`,
      503,
    )
  }

  const body = await response.json().catch(() => null)
  if (!response.ok) {
    if (response.status === 404) {
      throw new OllamaError(`Ollama model "${model}" is not installed. Run "ollama pull ${model}".`, 503)
    }
    throw new OllamaError(
      body?.error ?? `Ollama request failed (${response.status}).`,
      response.status === 429 ? 429 : 502,
    )
  }

  const answer = body?.message?.content
  if (typeof answer !== 'string' || !answer.trim()) {
    throw new OllamaError('Ollama returned an empty answer.', 502)
  }

  return { answer: answer.trim(), model }
}
