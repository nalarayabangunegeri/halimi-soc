'use client'

import { useState } from 'react'
import type { Event } from '@/lib/types'
import { formatTime } from '@/lib/format'

// Raw evidence inspector.
//
// Raw evidence is the highest-fidelity record and also the most sensitive, so it is
// shown on demand rather than inline. The value is rendered as text in a <pre>:
// React escapes it, and there is no HTML injection path from a log line into the
// page.
export function EventDetail({ events }: { events: Event[] }) {
  const [selected, setSelected] = useState<Event | null>(null)

  if (events.length === 0) return null

  return (
    <div className="card">
      <div className="card-header">
        <h2 className="card-title">Raw evidence</h2>
        <select
          aria-label="Select an event"
          value={selected?.id ?? ''}
          onChange={(e) => setSelected(events.find((ev) => ev.id === e.target.value) ?? null)}
          style={{ maxWidth: 380 }}
        >
          <option value="">Select an event…</option>
          {events.map((event) => (
            <option key={event.id} value={event.id}>
              {formatTime(event.time)} · {event.type} · {event.host}
            </option>
          ))}
        </select>
      </div>
      <div style={{ padding: 16 }}>
        {!selected ? (
          <p className="muted" style={{ margin: 0 }}>
            Select an event to inspect its retained raw line. Raw evidence expires before the structured
            event, so an expired record is marked rather than shown as an empty line.
          </p>
        ) : (
          <>
            <div style={{ display: 'flex', gap: 32, flexWrap: 'wrap', marginBottom: 12 }}>
              <Field label="Received" value={formatTime(selected.received_at)} />
              <Field label="Observed" value={formatTime(selected.observed_at)} />
              <Field label="Source" value={`${selected.source}${selected.source_path ? ` · ${selected.source_path}` : ''}`} />
              <Field label="Agent" value={selected.agent_id || '—'} />
            </div>

            {selected.attributes && Object.keys(selected.attributes).length > 0 ? (
              <div style={{ marginBottom: 12 }}>
                <div className="stat-label">Attributes</div>
                <div className="mono" style={{ fontSize: 12 }}>
                  {Object.entries(selected.attributes).map(([key, value]) => (
                    <div key={key}>
                      <span className="dim">{key}:</span> {value}
                    </div>
                  ))}
                </div>
              </div>
            ) : null}

            <div className="stat-label" style={{ marginBottom: 4 }}>
              Raw line
            </div>
            {selected.raw ? (
              <pre className="analysis">{selected.raw}</pre>
            ) : selected.attributes?.['raw_expired'] === 'true' ? (
              <div className="notice notice-warn" style={{ margin: 0 }}>
                The raw evidence for this event has expired under the retention policy. The structured
                event is retained, so this event remains usable in detection and correlation history.
              </div>
            ) : (
              <p className="muted" style={{ margin: 0 }}>
                No raw evidence was recorded for this event.
              </p>
            )}
          </>
        )}
      </div>
    </div>
  )
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="stat-label">{label}</div>
      <div className="mono" style={{ fontSize: 12 }}>
        {value}
      </div>
    </div>
  )
}
