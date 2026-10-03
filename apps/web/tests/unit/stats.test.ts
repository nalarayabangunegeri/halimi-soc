// @vitest-environment node

import { describe, expect, it } from 'vitest'
import { bucketEventsByHour } from '@/lib/stats'

// The volume chart is drawn from the same events the API returns. The bucketing
// must therefore be exact about boundaries: an event counted in the wrong hour
// would show a spike the telemetry does not contain, and an operator might act
// on it.

describe('bucketEventsByHour', () => {
  const now = Date.parse('2026-10-03T12:00:00Z')

  it('places events in their hour', () => {
    const buckets = bucketEventsByHour(
      ['2026-10-03T11:10:00Z', '2026-10-03T11:50:00Z', '2026-10-03T10:05:00Z'],
      3,
      now,
    )
    expect(buckets.map((b) => b.count)).toEqual([1, 2, 0])
  })

  it('ignores events outside the window rather than clamping them', () => {
    const buckets = bucketEventsByHour(['2026-10-01T00:00:00Z', '2026-10-03T12:00:00Z'], 3, now)
    expect(buckets.map((b) => b.count)).toEqual([0, 0, 1])
  })

  it('skips unparseable timestamps', () => {
    const buckets = bucketEventsByHour(['not-a-time', ''], 2, now)
    expect(buckets.map((b) => b.count)).toEqual([0, 0])
  })

  it('returns empty buckets for no input', () => {
    const buckets = bucketEventsByHour([], 4, now)
    expect(buckets).toHaveLength(4)
    expect(buckets.every((b) => b.count === 0)).toBe(true)
  })
})
