import { deepSearch, normalizeTarget, shodanKey } from '@/lib/osint'

export const runtime = 'nodejs'
export const maxDuration = 60

export async function POST(request: Request) {
  const body = await request.json().catch(() => null)
  const target = normalizeTarget(body?.target)
  if (!target) {
    return Response.json({ error: 'Enter a valid IP address or domain, e.g. 8.8.8.8 or example.com' }, { status: 400 })
  }
  if (!shodanKey()) {
    return Response.json(
      {
        error:
          'Shodan is not configured on this server. Add SHODAN_API_KEY to .env.local and restart the app.',
      },
      { status: 503 },
    )
  }

  try {
    const result = await deepSearch(target)
    return Response.json(result)
  } catch (error) {
    console.error('[osint] unexpected error', error)
    return Response.json({ error: 'Shodan lookup failed unexpectedly.' }, { status: 500 })
  }
}
