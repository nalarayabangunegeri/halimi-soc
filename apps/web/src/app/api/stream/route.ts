import { config } from '@/lib/config'
import { readSession } from '@/lib/session'

// The realtime feed, proxied through this server.
//
// Why proxy rather than let the browser connect to the API directly:
//
//  * the browser does not hold the API session, so it could not authenticate;
//  * it keeps the API unreachable from the browser, so no CORS policy is needed;
//  * it keeps the high-level stream endpoint on the same origin as the page, so
//    the page's Content-Security-Policy can stay `connect-src 'self'`.
//
// The route does not buffer. It forwards each chunk as it arrives, which is the
// only way server-sent events work: buffering would hold every event until the
// connection closed, and the connection never closes.

// A long-lived response must not be cached or optimised by the framework.
export const dynamic = 'force-dynamic'
export const fetchCache = 'force-no-store'
export const runtime = 'nodejs'

export async function GET(request: Request): Promise<Response> {
  const session = await readSession()
  if (!session) {
    return new Response(JSON.stringify({ error: { code: 'UNAUTHORIZED', message: 'Not signed in.' } }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' },
    })
  }

  // The upstream connection is tied to the downstream one: when the browser goes
  // away, `request.signal` fires and the API connection is torn down. Without
  // that, a closed tab would leave a server-side stream open until the API's own
  // idle timeout noticed.
  const upstream = new AbortController()
  request.signal.addEventListener('abort', () => upstream.abort(), { once: true })

  let response: Response
  try {
    response = await fetch(`${config.apiUrl}/api/v1/stream`, {
      headers: {
        Accept: 'text/event-stream',
        Cookie: `${config.apiCookieName}=${session.apiSession}`,
      },
      cache: 'no-store',
      signal: upstream.signal,
    })
  } catch {
    return new Response(
      JSON.stringify({ error: { code: 'API_UNREACHABLE', message: 'The realtime feed is unavailable.' } }),
      { status: 503, headers: { 'Content-Type': 'application/json' } },
    )
  }

  if (!response.ok || !response.body) {
    // The API's own status is preserved: a 503 there means the connection cap was
    // reached, and the browser should back off rather than immediately retry.
    return new Response(
      JSON.stringify({ error: { code: 'STREAM_UNAVAILABLE', message: 'The realtime feed is unavailable.' } }),
      { status: response.status === 200 ? 502 : response.status, headers: { 'Content-Type': 'application/json' } },
    )
  }

  return new Response(response.body, {
    status: 200,
    headers: {
      'Content-Type': 'text/event-stream; charset=utf-8',
      'Cache-Control': 'no-store, no-transform',
      Connection: 'keep-alive',
      // Defends against a proxy between this app and the browser deciding to
      // buffer the stream, which would make it useless.
      'X-Accel-Buffering': 'no',
    },
  })
}
