'use client'

import { useState, useTransition } from 'react'
import { useRouter } from 'next/navigation'
import { mutate } from '@/lib/browser'
import type { Analysis } from '@/lib/types'

// The advisory analysis panel.
//
// Three properties are surfaced deliberately, because the value of this feature
// depends on an analyst being able to judge it:
//
//  * the mode, so a computed summary is never mistaken for a model's narrative;
//  * whether it is grounded, so an unverifiable narrative is never read as a
//    finding;
//  * the evidence it was built from, so every claim can be checked.
//
// The panel is a button rather than an automatic call. AI never runs unasked.
export function AnalysisPanel({ incidentId }: { incidentId: string }) {
  const router = useRouter()
  const [pending, startTransition] = useTransition()
  const [busy, setBusy] = useState(false)
  const [analysis, setAnalysis] = useState<Analysis | null>(null)
  const [error, setError] = useState<string | null>(null)

  async function run() {
    setBusy(true)
    setError(null)
    const result = await mutate<Analysis>('incident.analyze', incidentId)
    setBusy(false)

    if (!result.ok) {
      setError(result.message)
      return
    }
    setAnalysis(result.data)
    startTransition(() => router.refresh())
  }

  return (
    <div className="card">
      <div className="card-header">
        <h2 className="card-title">Analysis</h2>
        <div className="button-row">
          {analysis ? (
            <span
              className={`badge ${analysis.mode === 'PROVIDER' ? 'badge-medium' : 'badge-status'}`}
              title={
                analysis.mode === 'PROVIDER'
                  ? 'Produced by a configured AI provider. Not verified claim by claim.'
                  : analysis.mode === 'DISABLED'
                    ? 'Computed from stored records. No AI provider was used.'
                    : 'The provider failed, so the computed summary is shown instead.'
              }
            >
              {analysis.mode === 'DISABLED' ? 'computed' : analysis.mode.toLowerCase()}
            </span>
          ) : null}
          <button type="button" className="small primary" onClick={run} disabled={busy || pending}>
            {busy ? 'Analysing…' : analysis ? 'Re-run' : 'Explain this incident'}
          </button>
        </div>
      </div>

      <div style={{ padding: 16 }}>
        {error ? <div className="error-banner">{error}</div> : null}

        {!analysis && !error ? (
          <p className="muted" style={{ margin: 0 }}>
            Ask for an explanation of what the evidence shows. This is advisory only: it cannot change
            severity, status or any action, and detection never depends on it.
          </p>
        ) : null}

        {analysis ? (
          <>
            <div className="notice notice-warn" style={{ marginBottom: 12 }}>
              <strong>Advisory.</strong> This analysis did not influence detection, severity or any
              automated action.
              {analysis.grounded
                ? ' It is computed directly from stored records.'
                : analysis.mode === 'PROVIDER'
                  ? ' It was written by a model and has not been verified claim by claim; check it against the evidence below.'
                  : ' The provider did not return a usable response, so the computed summary is shown.'}
            </div>

            <pre className="analysis">{analysis.analysis}</pre>

            <details style={{ marginTop: 16 }}>
              <summary className="muted" style={{ cursor: 'pointer', fontSize: 13 }}>
                Evidence supplied to the analysis ({analysis.evidence.length})
              </summary>
              <div className="table-scroll" style={{ marginTop: 8 }}>
                <table>
                  <thead>
                    <tr>
                      <th>Kind</th>
                      <th>Id</th>
                      <th>Time</th>
                      <th>Summary</th>
                    </tr>
                  </thead>
                  <tbody>
                    {analysis.evidence.map((item) => (
                      <tr key={`${item.kind}-${item.id}`}>
                        <td className="nowrap">{item.kind}</td>
                        <td className="mono nowrap">{item.id}</td>
                        <td className="nowrap dim">{new Date(item.timestamp).toLocaleString()}</td>
                        <td>{item.summary}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </details>
          </>
        ) : null}
      </div>
    </div>
  )
}
