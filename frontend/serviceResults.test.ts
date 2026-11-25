import { describe, expect, it } from 'vitest'
import type { HistoryEntry, Report, Row } from './api'
import { addressResults, cardTargetLabel, compareAggregates, compareGroupRuns, connectionStages, probeAvailability, protocolResults, reportContext, serviceAvailability, targetEndpoint, targetResults } from './serviceResults'

const pass: Row = { target: 0, targetRef: 'fixture', probe: 'https', stage: 'http', status: 'http_response', httpStatus: 204,
  tlsVersion: 'TLS 1.3', tlsVerified: true, dnsContext: 'core-policy', answerCount: 1, elapsedMs: 2 }
const failed: Row = { target: 0, targetRef: 'fixture', probe: 'https', stage: 'tls', status: 'connection_reset', elapsedMs: 2 }
const tcp: Row = { target: 0, targetRef: 'fixture', probe: 'tcp', stage: 'tcp', status: 'ok', elapsedMs: 1 }

const report: Report = { job: { jobId: 'suite', phase: 'COMPLETED' }, groupId: 'sample', groupRevision: 'sample-v1',
  path: { mode: 'OUTBOUND', ref: 'direct' }, family: 'ipv4', pathEvidence: { host: { id: 'local' }, scope: 'literal', generation: '2' },
  startedAt: '2026-11-25T17:00:00Z', results: [pass] }

describe('service availability', () => {
  it('distinguishes a failed site from a working site with impaired voice', () => {
    expect(serviceAvailability(targetResults(1, [tcp, failed]), true)).toBe('unavailable')
    const voice = { ...failed, target: 1, probe: 'stun', stage: 'udp', status: 'timeout' }
    expect(serviceAvailability(targetResults(2, [pass, voice]), true)).toBe('limited')
    expect(serviceAvailability(targetResults(2, [pass, { ...voice, status: 'ok' }]), true)).toBe('available')
    expect(serviceAvailability(targetResults(2, [pass, { ...voice, status: 'unsupported' }]), true)).toBe('unconfirmed')
    expect(serviceAvailability(targetResults(2, [failed, { ...voice, status: 'unsupported' }]), true)).toBe('unconfirmed')
    expect(serviceAvailability(targetResults(1, [pass, { ...tcp, status: 'unobservable' }]), true)).toBe('available')
  })

  it('does not assert an unavailable service from an unsupported path, rejected address, or missing family', () => {
    for (const row of [{ ...tcp, status: 'unobservable' }, { ...failed, status: 'target_rejected' }, { ...failed, reason: 'no_address_for_family' }]) {
      expect(probeAvailability(row)).toBe('unconfirmed')
    }
    expect(serviceAvailability(targetResults(1, [failed]), false)).toBe('unconfirmed')
    expect(serviceAvailability(targetResults(1, [pass]), false)).toBe('unconfirmed')
  })

  it('does not confuse an HTTP error, unfollowed redirect, or unsampled body with a successful check', () => {
    expect(probeAvailability({ ...pass, httpStatus: 403 })).toBe('limited')
    expect(probeAvailability({ ...pass, httpStatus: 302 })).toBe('limited')
    expect(probeAvailability({ ...pass, probe: 'https-data' })).toBe('unconfirmed')
    expect(probeAvailability({ ...pass, probe: 'https-data', bodyBytes: 601 })).toBe('available')
  })
})

describe('Check All comparison', () => {
  const entry = (id: string, row: Row): HistoryEntry => ({
    report: { ...report, groupId: id, results: [row] }, targets: [{ name: id, host: 'fixture.example', role: 'site' }],
  })
  const run = (...entries: HistoryEntry[]) => ({
    startedAt: report.startedAt, phase: 'COMPLETED', depth: 'quick' as const,
    progress: { groupsDone: entries.length, totalGroups: entries.length, probesDone: entries.length, totalProbes: entries.length },
    groups: new Map(entries.map(value => [value.report.groupId, value])),
  })

  it('shows only changed groups, including when the number of problems stays the same', () => {
    const before = run(entry('recovered', failed), entry('failed', pass), entry('same', pass))
    const after = run(entry('failed', failed), entry('same', pass), entry('recovered', pass))
    expect(compareAggregates(after, [before])).toEqual({ kind: 'comparable', previousStartedAt: before.startedAt, unobservedPath: true, changes: [
      { id: 'failed', before: 'available', after: 'unavailable' },
      { id: 'recovered', before: 'unavailable', after: 'available' },
    ] })
    expect(compareAggregates(after, [after])).toMatchObject({ kind: 'comparable', changes: [] })
    expect(compareAggregates(after)).toEqual({ kind: 'noPrevious' })
  })

  it('makes no partial comparison if a group is missing, a run is incomplete or scope changed', () => {
    const before = run(entry('changed', failed), entry('same', pass))
    const after = run(entry('changed', pass), entry('same', pass))
    const changedGeneration = entry('same', pass)
    changedGeneration.report.pathEvidence = { ...changedGeneration.report.pathEvidence!, generation: 'new' }
    for (const different of [
      { ...after, omitted: 1 }, { ...after, phase: 'CANCELED' }, { ...after, depth: 'deep' as const },
      { ...after, progress: { ...after.progress, probesDone: 1 } },
      { ...after, groups: new Map([['changed', entry('changed', pass)], ['same', undefined]]) },
      run(entry('changed', pass), entry('other', pass)), run(entry('changed', pass), changedGeneration),
    ]) expect(compareAggregates(different, [before])).toEqual({ kind: 'differentContext' })
  })

  it('uses the newest comparable earlier run, not an intervening cancellation, omission or different path', () => {
    const current = run(entry('site', pass))
    const earlier = { ...run(entry('site', failed)), startedAt: '2026-11-25T16:40:00Z' }
    const otherPath = entry('site', pass)
    otherPath.report.path = { mode: 'OUTBOUND', ref: 'other' }
    const skipped = [run(otherPath), { ...current, omitted: 1 }, { ...current, phase: 'CANCELED' }]
    expect(compareAggregates(current, skipped)).toEqual({ kind: 'differentContext' })
    expect(compareAggregates(current, [...skipped, earlier, current])).toMatchObject({
      kind: 'comparable', previousStartedAt: earlier.startedAt, changes: [{ id: 'site', before: 'unavailable', after: 'available' }],
    })

    const priorReport = { ...report, startedAt: earlier.startedAt, results: [failed] }
    const changedRoute = { ...report, pathEvidence: { ...report.pathEvidence!, generation: 'other' } }
    const canceled = { ...report, job: { ...report.job, phase: 'CANCELED' } }
    expect(compareGroupRuns(report, [changedRoute, canceled])).toEqual({ kind: 'differentContext' })
    expect(compareGroupRuns(report, [changedRoute, canceled, priorReport])).toEqual({
      kind: 'comparable', previousStartedAt: earlier.startedAt, changes: 1, unobservedPath: true,
    })
  })
})

describe('protocol observations', () => {
  it('distinguishes configured voice ports without inventing missing historical ports', () => {
    const target = { name: 'STUN', host: 'voice.example', role: 'voice' }
    expect(targetEndpoint(target)).toBe('voice.example')
    expect(cardTargetLabel(target)).toBe('voice')
    expect(cardTargetLabel({ ...target, port: 3478 })).toBe('STUN · voice.example:3478')
    expect(cardTargetLabel({ ...target, port: 19302 })).toBe('STUN · voice.example:19302')
    expect(targetEndpoint({ ...target, host: '2001:db8::4', port: 19302 })).toBe('[2001:db8::4]:19302')
  })

  it('keeps a successful HTTP exchange and a TLS reset on separate attempted addresses', () => {
    const dnsRow: Row = { ...pass, probe: 'dns', stage: 'dns', status: 'dns_response', httpStatus: undefined, tlsVersion: undefined, tlsVerified: undefined }
    const targets = addressResults([dnsRow, { ...pass, attemptedAddress: '198.51.100.4' },
      { ...failed, probe: 'tls13', attemptedAddress: '2001:db8::4' },
      { ...tcp, status: 'unobservable', attemptedAddress: '198.51.100.4' }])
    expect(targets.map(target => target.address)).toEqual(['198.51.100.4', '2001:db8::4', undefined])
    expect(targets[0].stages).toEqual([
      { stage: 'dns', state: 'available', observed: true }, { stage: 'tcp', state: 'unconfirmed', observed: true },
      { stage: 'tls', state: 'available', observed: true }, { stage: 'certificate', state: 'available', observed: true },
      { stage: 'http', state: 'available', observed: true },
    ])
    expect(targets[1].stages).toEqual([{ stage: 'tls', state: 'unavailable', observed: true }])
    expect(targets[2].rows).toEqual([dnsRow])
    expect(targets[2].stages).toEqual([{ stage: 'dns', state: 'available', observed: true }])
  })

  it('does not reconstruct an address from retained report family or DNS metadata', () => {
    const result = addressResults([{ ...pass, addressFamily: 'ipv4' }, { ...failed, addressFamily: 'ipv6' }])
    expect(result.map(attempt => attempt.address)).toEqual([undefined])
    expect(result[0].rows).toHaveLength(2)
    expect(result[0].stages.map(step => step.stage)).not.toContain('quic')
  })

  it('shows measured DNS, TLS, certificate and HTTP, but not a synthetic TCP pass', () => {
    const steps = Object.fromEntries(connectionStages([pass, { ...tcp, status: 'unobservable', reason: 'proxy_connect_not_endpoint_proof' }]).map(step => [step.stage, step.state]))
    expect(steps).toMatchObject({ dns: 'available', tcp: 'unconfirmed', tls: 'available', certificate: 'available', http: 'available', quic: 'unconfirmed' })
    expect(protocolResults([pass]).map(row => row.protocol)).toEqual(['dns', 'tls', 'http'])
  })

  it('does not pass HTTP or direct TCP from a QUIC handshake', () => {
    const steps = Object.fromEntries(connectionStages([{ ...pass, probe: 'quic', stage: 'quic', status: 'ok', httpStatus: undefined }]).map(step => [step.stage, step.state]))
    expect(steps).toMatchObject({ quic: 'available', certificate: 'available', tls: 'unconfirmed', http: 'unconfirmed', tcp: 'unconfirmed' })
  })

  it('keeps a Chrome-profile failure distinct from ordinary site availability', () => {
    const chrome = { ...failed, probe: 'https-chrome', tlsProfile: 'chrome-133' }
    expect(serviceAvailability(targetResults(1, [pass, chrome]), true)).toBe('limited')
    expect(protocolResults([pass, chrome])).toEqual(expect.arrayContaining([
      { protocol: 'chrome', state: 'unavailable' }, { protocol: 'http', state: 'available' },
    ]))
    expect(connectionStages([chrome]).find(step => step.stage === 'certificate')).toMatchObject({ observed: false })
  })

  it('does not compare a different generation, DNS override, observed egress, or unfinished result as unchanged', () => {
    const reached = { ...report, results: [{ ...pass, socket: { egress: 'one' } }] }
    expect(reportContext(reached, reached)).toBe('observed')
    expect(reportContext(reached, { ...report, results: [failed] })).toBe('configured')
    expect(reportContext(report, report)).toBe('configured')
    expect(reportContext(report, { ...report, pathEvidence: { ...report.pathEvidence!, generation: '3' } })).toBe('different')
    expect(reportContext(report, { ...report, path: { ...report.path, resolver: 'other' } })).toBe('different')
    expect(reportContext(report, { ...report, job: { ...report.job, phase: 'CANCELED' } })).toBe('different')
    expect(reportContext(reached, { ...report, results: [{ ...pass, socket: { egress: 'two' } }] })).toBe('different')
  })
})
