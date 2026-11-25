import type { Report, Row } from './api'

const observed = new Set(['ok', 'dns_response', 'http_response', 'resolution_failed', 'timeout', 'connection_refused',
  'connection_failed', 'connection_reset', 'stream_closed', 'tls_failed', 'certificate_invalid', 'protocol_error'])
const dnsProbes = new Set(['dns', 'dns-udp', 'dns-tcp', 'dot', 'doh', 'doq', 'doh3'])

function sameProbe(a: Row, b: Row): boolean {
  return a.target === b.target && a.targetRef === b.targetRef && a.probe === b.probe
}

export function comparable(a: Report, b: Report): boolean {
  const timeDelta = Math.abs(Date.parse(a.startedAt) - Date.parse(b.startedAt))
  if (!a.pathEvidence || !b.pathEvidence || a.pathEvidence.host.id !== b.pathEvidence.host.id || a.groupId !== b.groupId ||
      a.groupRevision !== b.groupRevision || a.family !== b.family || a.results.length !== b.results.length ||
      !Number.isFinite(timeDelta) || timeDelta > 15 * 60 * 1000) return false
  return a.results.every((row, index) => sameProbe(row, b.results[index])) && a.results.some((row, index) => {
    const other = b.results[index]
    return observed.has(row.status) && observed.has(other.status) || dnsDifference(row, other) !== undefined
  })
}

type DNSDifference = 'name_error' | 'answer_rejected' | 'empty_answer' | 'error_response' | 'answer_sets'

export function dnsDifference(a: Row, b: Row): DNSDifference | undefined {
  if (!sameProbe(a, b) || !dnsProbes.has(a.probe) || a.stage !== 'dns' || b.stage !== 'dns' || !a.dnsContext || !b.dnsContext) return
  const usable = (row: Row) => row.status === 'dns_response' && !row.dnsRcode && !!row.answerCount && !!row.answerDigest
  const aUsable = usable(a), bUsable = usable(b)
  if (aUsable && bUsable) return a.answerDigest === b.answerDigest ? undefined : 'answer_sets'
  if (!aUsable && !bUsable) return

  const other = aUsable ? b : a
  if (other.status === 'target_rejected' && other.reason === 'dns_or_literal_address_not_public') return 'answer_rejected'
  if (other.status !== 'dns_response' || other.dnsRcode === undefined) return
  if (other.dnsRcode === 3) return 'name_error'
  if (other.dnsRcode !== 0) return 'error_response'
  if (!other.answerCount) return 'empty_answer'
}
