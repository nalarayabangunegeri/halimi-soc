'use client'

import { createContext, useContext, useEffect, useMemo, useRef, useState } from 'react'
import { useRouter } from 'next/navigation'
import type { ReactNode } from 'react'

// Client-side realtime connection.
//
// The connection is opened once, at the top of the app, and shared through
// context. Opening one per page would multiply the server's connection count by
// the number of open tabs and make the connection cap meaningless.
//
// The stream is a hint, never a source of truth. On a relevant event the app
// re-renders from the server, so the data a user actually sees always comes from an
// authenticated, authorized request that passed through the same code path as a
// manual reload. A stream payload is never rendered directly: doing so would mean
// the UI's authorization surface included the stream's, which is a strictly weaker
// contract.

export type ConnectionState = 'connecting' | 'connected' | 'disconnected'

export interface RealtimeEvent {
  type: string
  data: unknown
  receivedAt: number
}

interface RealtimeContextValue {
  state: ConnectionState
  lastEvent: RealtimeEvent | null
  received: number
}

const RealtimeContext = createContext<RealtimeContextValue>({
  state: 'connecting',
  lastEvent: null,
  received: 0,
})

export function useRealtime(): RealtimeContextValue {
  return useContext(RealtimeContext)
}

const BACKOFF_MS = [1_000, 2_000, 5_000, 10_000, 20_000, 30_000]

// Events that change what is on screen. The periodic platform metric is excluded:
// it arrives on a timer and refreshing the page for it would be pure churn.
const REFRESH_EVENTS = new Set([
  'alert.created',
  'incident.created',
  'incident.updated',
  'agent.status_changed',
])

// A burst of events (a brute force produces several alerts in a second) must
// cause one re-render, not one per event.
const REFRESH_DEBOUNCE_MS = 400

export function RealtimeProvider({ children }: { children: ReactNode }) {
  const router = useRouter()
  const [state, setState] = useState<ConnectionState>('connecting')
  const [lastEvent, setLastEvent] = useState<RealtimeEvent | null>(null)
  const [received, setReceived] = useState(0)

  // The debounce timer and the router are held in refs so that a re-render does
  // not restart the connection or lose a pending refresh.
  const refreshTimer = useRef<ReturnType<typeof setTimeout> | null>(null)
  const routerRef = useRef(router)
  routerRef.current = router

  useEffect(() => {
    let source: EventSource | null = null
    let attempt = 0
    let stopped = false
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null

    const scheduleRefresh = () => {
      if (refreshTimer.current) clearTimeout(refreshTimer.current)
      refreshTimer.current = setTimeout(() => {
        refreshTimer.current = null
        // Re-render the current route from the server. This re-runs the page's
        // server component, so authorization and data are re-evaluated rather than
        // patched from a stream payload.
        routerRef.current.refresh()
      }, REFRESH_DEBOUNCE_MS)
    }

    const handleFrame = (event: Event) => {
      const message = event as MessageEvent
      let data: unknown = null
      try {
        data = JSON.parse(message.data)
      } catch {
        // The server guarantees JSON, so a parse failure means a protocol
        // mismatch. Ignoring the frame is better than tearing down a working
        // connection over one bad message.
        return
      }

      const type = message.type || 'message'
      setReceived((n) => n + 1)
      setLastEvent({ type, data, receivedAt: Date.now() })

      if (REFRESH_EVENTS.has(type)) scheduleRefresh()
    }

    const connect = () => {
      if (stopped) return
      setState('connecting')

      // EventSource sends the same-origin session cookie, which is what
      // authenticates this request. No token appears in the URL: a token in a query
      // string leaks into access logs, proxy logs and browser history.
      source = new EventSource('/api/stream')

      source.onopen = () => {
        attempt = 0
        setState('connected')
      }

      // Named events need explicit listeners; `onmessage` fires only for the
      // default event type.
      for (const name of [
        'alert.created',
        'incident.created',
        'incident.updated',
        'agent.status_changed',
        'platform.metric',
      ]) {
        source.addEventListener(name, handleFrame)
      }

      source.addEventListener('session.revoked', () => {
        // The session is gone, so reconnecting would loop against a 401. The
        // stream is closed and the operator is sent to sign in again.
        stopped = true
        source?.close()
        setState('disconnected')
        window.location.assign('/login')
      })

      source.onerror = () => {
        // EventSource retries on its own, but with no backoff and no jitter. It is
        // closed here and reconnected on a schedule instead, so several tabs
        // recovering from one outage do not reconnect in lockstep.
        source?.close()
        source = null
        setState('disconnected')
        if (stopped) return

        const base = BACKOFF_MS[Math.min(attempt, BACKOFF_MS.length - 1)] ?? 30_000
        attempt++
        reconnectTimer = setTimeout(connect, base + Math.random() * base * 0.2)
      }
    }

    connect()

    return () => {
      stopped = true
      if (reconnectTimer) clearTimeout(reconnectTimer)
      if (refreshTimer.current) clearTimeout(refreshTimer.current)
      source?.close()
    }
  }, [])

  const value = useMemo(() => ({ state, lastEvent, received }), [state, lastEvent, received])
  return <RealtimeContext.Provider value={value}>{children}</RealtimeContext.Provider>
}

export function ConnectionIndicator() {
  const { state, received } = useRealtime()
  const label = state === 'connected' ? 'live' : state === 'connecting' ? 'connecting' : 'disconnected'
  return (
    <span className={`live live-${state}`} title={`${received} realtime event(s) received`}>
      <span className="live-dot" aria-hidden="true" />
      <span>{label}</span>
    </span>
  )
}
