# ADR-003 — Server-Sent Events for realtime updates

**Status:** Accepted (implemented: `internal/events/stream`, consumed by `apps/web`)
**Date:** 2026-09-27

## Context

The dashboard must show new alerts and incident changes without the operator
refreshing the page.

## Decision

Use Server-Sent Events on `GET /api/v1/stream`, authenticated by the same
session cookie as the rest of the API, and re-authorised on every event.

## Alternatives considered

- **WebSockets.** Rejected for the MVP: the traffic is strictly server-to-client,
  and WebSockets add a framing protocol, an upgrade handshake to secure, and
  client-side reconnection logic that the browser already implements for SSE.
- **Polling.** Rejected as the primary mechanism: it either adds latency or
  wastes requests. It remains an acceptable fallback and is what the current UI
  would use if SSE is unavailable.

## Consequences

- The stream is a long-lived request, so the server bounds concurrent
  connections and terminates a stream when its session is revoked.
- The event payload is a projection of the alert or incident, not the full
  record, so a stream cannot become a bulk data-export path.

## Security impact

SSE inherits the session's authorization. Revocation must terminate an already
open stream, which is why authorization is revalidated per event rather than
only at connection time.

## Revisit conditions

Revisit if the product needs client-to-server realtime messaging, or if SSE
connection limits become the binding constraint.
