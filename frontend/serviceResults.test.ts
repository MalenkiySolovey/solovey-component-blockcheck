import { describe, expect, it } from 'vitest'
import type { Report, Row } from './api'
import { connectionStages, probeAvailability, protocolResults, reportContext, serviceAvailability, targetResults } from './serviceResults'

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

describe('protocol observations', () => {
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
