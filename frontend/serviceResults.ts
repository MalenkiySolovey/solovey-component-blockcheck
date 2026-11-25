import type { Report, Row } from './api'

export const availabilityStates = ['available', 'limited', 'unavailable', 'unconfirmed'] as const
export type Availability = typeof availabilityStates[number]
export const availabilityColor: Record<Availability, string | undefined> = {
  available: 'success', limited: 'warning', unavailable: 'error', unconfirmed: undefined,
}

const dns = new Set(['dns', 'dns-udp', 'dns-tcp', 'dot', 'doh', 'doq', 'doh3'])
const web = new Set(['http', 'https', 'http3'])
const transfer = new Set(['http-data', 'https-data'])
const tls = new Set(['tls', 'tls12', 'tls13'])
const failed = new Set(['resolution_failed', 'timeout', 'connection_refused', 'connection_failed', 'connection_reset',
  'stream_closed', 'tls_failed', 'quic_failed', 'certificate_invalid', 'protocol_error'])

export function probeAvailability(row: Row): Availability {
  if (row.status === 'ok') return 'available'
  if (row.status === 'dns_response') {
    if (row.dnsRcode) return 'unavailable'
    return row.answerCount ? 'available' : 'unconfirmed'
  }
  if (row.status === 'http_response' && row.httpStatus) {
    if (row.httpStatus >= 300) return 'limited'
    if (row.httpStatus >= 200) return !transfer.has(row.probe) || row.bodyBytes ? 'available' : 'unconfirmed'
  }
  if (row.reason === 'no_address_for_family') return 'unconfirmed'
  return failed.has(row.status) && row.stage ? 'unavailable' : 'unconfirmed'
}

export function combineAvailability(states: readonly Availability[]): Availability {
  if (states.includes('limited') || states.includes('available') && states.includes('unavailable')) return 'limited'
  if (states.includes('unconfirmed')) return 'unconfirmed'
  return states[0] ?? 'unconfirmed'
}

export function targetAvailability(rows: readonly Row[]): Availability {
  // A successful prerequisite is not a successful web request.
  const application = rows.filter(row => web.has(row.probe) || transfer.has(row.probe))
  const primary = application.length > 0 ? application : rows
  const observed = combineAvailability(primary.map(probeAvailability))
  // A confirmed web response does not require a separate endpoint TCP
  // observation, but a measured failure on a sibling probe still matters.
  return observed === 'available' && rows.some(row => ['limited', 'unavailable'].includes(probeAvailability(row))) ? 'limited' : observed
}

export type TargetResult = { index: number; rows: Row[]; state: Availability }

export function targetResults(count: number, rows: readonly Row[]): TargetResult[] {
  const indexed: Row[][] = Array.from({ length: count }, () => [])
  for (const row of rows) indexed[row.target]?.push(row)
  return indexed.map((targetRows, index) => ({ index, rows: targetRows, state: targetAvailability(targetRows) }))
}

export function serviceAvailability(targets: readonly TargetResult[], finished: boolean): Availability {
  const state = combineAvailability(targets.map(target => target.state))
  return finished || state === 'limited' ? state : 'unconfirmed'
}

export const stageKeys = ['dns', 'tcp', 'udp', 'stun', 'tls', 'quic', 'certificate', 'http', 'transfer'] as const
export type Stage = typeof stageKeys[number]

function stageFact(row: Row, stage: Stage): Availability | undefined {
  if (stage === 'dns' && row.stage !== 'dns' && row.dnsContext && row.answerCount) return 'available'
  if (stage === 'certificate' && row.tlsVerified) return 'available'
  if (stage === 'tls' && row.tlsVersion && row.probe !== 'quic' && row.probe !== 'http3') return 'available'
  if (stage === 'quic' && row.tlsVersion && (row.probe === 'quic' || row.probe === 'http3')) return 'available'
  if (stage === 'http' && row.httpStatus) return row.httpStatus >= 300 ? 'limited' : 'available'
  if (row.stage === stage) return probeAvailability(row)
  // A dedicated TCP probe owns TCP endpoint evidence. CONNECT or a later
  // response on a proxy stream is not an observed endpoint TCP handshake.
}

export function connectionStages(rows: readonly Row[]) {
  return stageKeys.map(stage => {
    const states = rows.flatMap(row => stageFact(row, stage) ?? [])
    return { stage, state: combineAvailability(states), observed: states.length > 0 }
  })
}

export const protocolKeys = ['dns', 'tcp', 'tls', 'http', 'quic', 'transfer', 'stun', 'icmp'] as const
type Protocol = typeof protocolKeys[number]

function protocolOf(probe: string): Protocol | undefined {
  if (dns.has(probe)) return 'dns'
  if (tls.has(probe)) return 'tls'
  if (transfer.has(probe)) return 'transfer'
  if (probe === 'quic' || probe === 'http3') return 'quic'
  if (web.has(probe)) return 'http'
  if (probe === 'tcp' || probe === 'stun' || probe === 'icmp') return probe
}

export function protocolResults(rows: readonly Row[]) {
  const byProtocol = new Map<Protocol, Availability[]>()
  const append = (protocol: Protocol, state: Availability) => {
    const states = byProtocol.get(protocol) ?? []
    states.push(state)
    byProtocol.set(protocol, states)
  }
  for (const row of rows) {
    const protocol = protocolOf(row.probe)
    if (protocol) append(protocol, probeAvailability(row))
    for (const stage of ['dns', 'tls'] as const) {
      const fact = protocol !== stage && stageFact(row, stage)
      if (fact) append(stage, fact)
    }
  }
  return protocolKeys.flatMap(protocol => {
    const states = byProtocol.get(protocol)
    return states ? [{ protocol, state: combineAvailability(states) }] : []
  })
}

export function reportContext(a: Report, b: Report): 'observed' | 'configured' | 'different' {
  const first = a.pathEvidence, second = b.pathEvidence
  if (!first || !second || a.job.phase !== 'COMPLETED' || b.job.phase !== 'COMPLETED' || first.host.id !== second.host.id ||
      first.generation !== second.generation || first.scope !== second.scope || first.context !== second.context ||
      a.path.mode !== b.path.mode || a.path.ref !== b.path.ref || a.path.resolver !== b.path.resolver ||
      a.groupId !== b.groupId || a.groupRevision !== b.groupRevision || a.family !== b.family || a.results.length !== b.results.length) return 'different'
  let observed = !!first.generation || a.path.mode === 'HOST_BASELINE'
  for (const [index, row] of a.results.entries()) {
    const other = b.results[index]
    if (row.target !== other.target || row.targetRef !== other.targetRef || row.probe !== other.probe ||
        row.dnsContext && other.dnsContext && row.dnsContext !== other.dnsContext ||
        row.dnsTransport && other.dnsTransport && row.dnsTransport !== other.dnsTransport) return 'different'
    const socket = dns.has(row.probe) ? row.dnsSocket : row.socket
    const otherSocket = dns.has(row.probe) ? other.dnsSocket : other.socket
    if (socket?.egress && otherSocket?.egress && socket.egress !== otherSocket.egress) return 'different'
    if (a.path.mode === 'HOST_BASELINE' ? !socket?.outsidePanel || !otherSocket?.outsidePanel : !socket?.egress || !otherSocket?.egress) observed = false
  }
  return observed && a.results.length ? 'observed' : 'configured'
}
