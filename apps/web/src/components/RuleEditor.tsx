'use client'

import { useState } from 'react'
import { useRouter } from 'next/navigation'
import { mutate } from '@/lib/browser'

// Rule authoring form.
//
// The flow is validate, then save, then reload — three explicit steps rather
// than one "deploy" button, because each step answers a different question:
// is the document valid, is it stored, and is it active. The server is the
// authority at every step: a rejection is displayed, never assumed away.
export function RuleEditor({ initialId, initialYaml }: { initialId?: string; initialYaml?: string }) {
  const router = useRouter()
  const [id, setId] = useState(initialId ?? '')
  const [yaml, setYaml] = useState(initialYaml ?? TEMPLATE)
  const [notice, setNotice] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState<string | null>(null)

  const fixedId = initialId !== undefined

  async function run(action: string, key: string, okMessage: (data: unknown) => string) {
    setBusy(key)
    setError(null)
    setNotice(null)
    const target = action === 'rules.validate' ? '-' : id.trim()
    const payload = action === 'rules.reload' ? {} : { yaml }
    const result = await mutate(action, target, payload)
    setBusy(null)
    if (!result.ok) {
      setError(`${result.message} (${result.code})`)
      return
    }
    setNotice(okMessage(result.data))
  }

  return (
    <div>
      {!fixedId ? (
        <label style={{ display: 'block', marginBottom: 12 }}>
          <span className="dim" style={{ fontSize: 12 }}>
            Rule id — lowercase letters, digits, dashes and underscores. It becomes the file name.
          </span>
          <input
            value={id}
            onChange={(e) => setId(e.target.value)}
            placeholder="my-new-rule"
            maxLength={64}
            style={{ marginTop: 4 }}
          />
        </label>
      ) : null}

      <label style={{ display: 'block' }}>
        <span className="dim" style={{ fontSize: 12 }}>
          Rule document — validated strictly; unknown fields are rejected.
        </span>
        <textarea
          className="mono"
          value={yaml}
          onChange={(e) => setYaml(e.target.value)}
          rows={22}
          spellCheck={false}
          style={{ marginTop: 4, width: '100%', resize: 'vertical' }}
        />
      </label>

      <div className="button-row" style={{ marginTop: 12 }}>
        <button type="button" disabled={busy !== null} onClick={() => run('rules.validate', 'validate', () => 'Valid: safe to save.')}>
          {busy === 'validate' ? '…' : 'Validate'}
        </button>
        <button
          type="button"
          disabled={busy !== null || (!fixedId && id.trim() === '')}
          onClick={() =>
            run('rules.save', 'save', () => 'Saved. Reload the rules to activate it.', )
          }
        >
          {busy === 'save' ? '…' : 'Save'}
        </button>
        <button type="button" disabled={busy !== null} onClick={() => run('rules.reload', 'reload', (data) => {
          const count = (data as { rules?: number })?.rules
          return `Reloaded${typeof count === 'number' ? ` (${count} rules active)` : ''}.`
        })}>
          {busy === 'reload' ? '…' : 'Reload rules'}
        </button>
        <button type="button" disabled={busy !== null} onClick={() => router.push('/rules')}>
          Back to rules
        </button>
      </div>

      {notice ? (
        <div className="notice" style={{ marginTop: 12 }}>
          {notice} Saving does not activate: press Reload rules when the set is ready.
        </div>
      ) : null}
      {error ? (
        <div className="muted" style={{ color: 'var(--danger)', fontSize: 12, marginTop: 8 }}>
          {error}
        </div>
      ) : null}
    </div>
  )
}

const TEMPLATE = `id: my-new-rule
version: 1
name: My New Rule
description: What this rule detects, in one sentence
severity: medium

match:
  types:
    - auth.ssh.login_failed
  outcomes:
    - failure

threshold:
  count: 5
  window: 60s

group_by:
  - network.src_ip

cooldown: 5m
`
