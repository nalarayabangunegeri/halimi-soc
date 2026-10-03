import type { Severity } from './types'

/** Formats an RFC3339 timestamp for display, with a stable fallback. */
export function formatTime(value: string | undefined): string {
  if (!value) return '—'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return '—'
  return date.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}

/** Formats a duration between two timestamps. */
export function formatSpan(from: string, to: string): string {
  const start = new Date(from).getTime()
  const end = new Date(to).getTime()
  if (Number.isNaN(start) || Number.isNaN(end) || end < start) return '—'

  const seconds = Math.round((end - start) / 1000)
  if (seconds < 60) return `${seconds}s`
  const minutes = Math.round(seconds / 60)
  if (minutes < 60) return `${minutes}m`
  const hours = Math.round(minutes / 60)
  if (hours < 48) return `${hours}h`
  return `${Math.round(hours / 24)}d`
}

/** Formats a byte count. */
export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 B'
  const units = ['B', 'KiB', 'MiB', 'GiB']
  let value = bytes
  let unit = 0
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024
    unit++
  }
  return `${value.toFixed(value < 10 && unit > 0 ? 1 : 0)} ${units[unit]}`
}

/** Turns a dotted event type into a readable label. */
export function humanizeType(value: string): string {
  return value.replace(/[._]/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase())
}

/** Turns an UPPER_SNAKE stage or status into a readable label. */
export function humanizeEnum(value: string): string {
  return value
    .toLowerCase()
    .split('_')
    .map((part) => (part ? part[0]!.toUpperCase() + part.slice(1) : part))
    .join(' ')
}

/**
 * Severity ordering for client-side sorting.
 *
 * The ranks match the server's `SeverityRank`, so a client sort cannot disagree
 * with the server about which of two severities is higher.
 */
export function severityRank(severity: Severity): number {
  switch (severity) {
    case 'low':
      return 1
    case 'medium':
      return 2
    case 'high':
      return 3
    case 'critical':
      return 4
    default:
      return 0
  }
}
