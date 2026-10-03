import { describe, expect, it } from 'vitest'
import {
  formatBytes,
  formatSpan,
  formatTime,
  humanizeEnum,
  humanizeType,
  severityRank,
} from '@/lib/format'

describe('formatTime', () => {
  it('renders a valid timestamp', () => {
    expect(formatTime('2026-08-19T11:20:30Z')).not.toBe('—')
  })

  it('falls back for a missing or malformed value', () => {
    // The UI must never render "Invalid Date" at an operator.
    expect(formatTime(undefined)).toBe('—')
    expect(formatTime('')).toBe('—')
    expect(formatTime('not-a-date')).toBe('—')
  })
})

describe('formatSpan', () => {
  it('picks a readable unit', () => {
    expect(formatSpan('2026-08-19T11:20:00Z', '2026-08-19T11:20:30Z')).toBe('30s')
    expect(formatSpan('2026-08-19T11:00:00Z', '2026-08-19T11:05:00Z')).toBe('5m')
    expect(formatSpan('2026-08-19T11:00:00Z', '2026-08-19T13:00:00Z')).toBe('2h')
    expect(formatSpan('2026-08-19T00:00:00Z', '2026-08-21T00:00:00Z')).toBe('2d')
  })

  it('refuses an inverted or invalid range instead of showing a negative span', () => {
    expect(formatSpan('2026-08-19T11:00:00Z', '2026-08-19T10:00:00Z')).toBe('—')
    expect(formatSpan('bad', 'worse')).toBe('—')
  })
})

describe('formatBytes', () => {
  it('scales and rounds', () => {
    expect(formatBytes(0)).toBe('0 B')
    expect(formatBytes(512)).toBe('512 B')
    expect(formatBytes(2048)).toBe('2.0 KiB')
    expect(formatBytes(104857600)).toBe('100 MiB')
  })

  it('handles a nonsense value without producing NaN', () => {
    expect(formatBytes(-1)).toBe('0 B')
    expect(formatBytes(Number.NaN)).toBe('0 B')
  })
})

describe('humanize helpers', () => {
  it('turns a dotted event type into a label', () => {
    expect(humanizeType('auth.ssh.login_failed')).toBe('Auth Ssh Login Failed')
  })

  it('turns an enum value into a label', () => {
    expect(humanizeEnum('PRIVILEGE_ESCALATION')).toBe('Privilege Escalation')
    expect(humanizeEnum('NEW')).toBe('New')
  })
})

describe('severityRank', () => {
  it('orders severities identically to the server', () => {
    // The ranks mirror internal/events/model.SeverityRank. If they diverged, a
    // client-side sort would disagree with the server about which severity is
    // higher, which is a correctness bug rather than a cosmetic one.
    expect(severityRank('low')).toBeLessThan(severityRank('medium'))
    expect(severityRank('medium')).toBeLessThan(severityRank('high'))
    expect(severityRank('high')).toBeLessThan(severityRank('critical'))
  })

  it('returns zero for an unknown severity rather than a mid value', () => {
    expect(severityRank('urgent' as never)).toBe(0)
  })
})
