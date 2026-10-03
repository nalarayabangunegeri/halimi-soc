// Event volume bucketing for the overview chart.
//
// The chart is drawn from the events the API returns, not from a separate
// telemetry path: a volume figure that came from anywhere else could disagree
// with the event list on the same screen, and an operator should never have to
// decide which of two numbers on one page is true.

export interface VolumeBucket {
  /** Bucket start, as milliseconds since the epoch. */
  start: number
  /** Events whose occurrence time falls in [start, start + width). */
  count: number
}

/**
 * Groups event timestamps into fixed hourly buckets ending at now.
 *
 * Events outside the window are ignored rather than clamped: clamping them
 * into the first bucket would fabricate a spike the telemetry does not show.
 * Unparseable timestamps are skipped for the same reason.
 */
export function bucketEventsByHour(times: string[], buckets: number, now: number): VolumeBucket[] {
  const width = 3_600_000
  const end = Math.floor(now / width) * width
  const out: VolumeBucket[] = []
  for (let i = buckets - 1; i >= 0; i--) {
    out.push({ start: end - i * width, count: 0 })
  }
  for (const raw of times) {
    const at = Date.parse(raw)
    if (Number.isNaN(at)) continue
    const index = Math.floor((at - (end - (buckets - 1) * width)) / width)
    if (index < 0 || index >= buckets) continue
    out[index]!.count++
  }
  return out
}
