import { describe, expect, it } from 'vitest'
import type { Report, Row } from './api'
import { authenticatesDNSSet, comparable, compareProbeResults, dnsDifference } from './comparison'

function answer(overrides: Partial<Row> = {}): Row {
  return { target: 0, targetRef: 'fixture', probe: 'dns', stage: 'dns', status: 'dns_response', elapsedMs: 1,
    dnsContext: 'explicit-core-dns-server', dnsRcode: 0, answerCount: 1, answerDigest: 'accepted-address-set', ...overrides }
}

function report(rows: Row[], overrides: Partial<Report> = {}): Report {
  return { job: { jobId: 'fixture', phase: 'COMPLETED' }, path: { mode: 'OUTBOUND', ref: 'fixture-direct' },
    groupId: 'fixture', groupRevision: 'fixture-revision', family: 'ipv4', pathEvidence: { host: { id: 'local' }, scope: 'outbound-pinned-ip' },
    startedAt: '2026-11-25T17:00:00Z', results: rows, ...overrides }
}

describe('DNS comparison', () => {
  it.each([
    ['name_error', { dnsRcode: 3, answerCount: undefined, answerDigest: undefined }],
    ['empty_answer', { answerCount: undefined, answerDigest: undefined }],
    ['error_response', { dnsRcode: 5, answerCount: undefined, answerDigest: undefined }],
    ['answer_rejected', { status: 'target_rejected', reason: 'dns_or_literal_address_not_public', answerCount: undefined, answerDigest: undefined }],
    ['answer_sets', { answerDigest: 'different-accepted-address-set' }],
  ] as const)('observes %s from the same probe in either order', (kind, fields) => {
    expect(dnsDifference(answer(), answer(fields))).toBe(kind)
    expect(dnsDifference(answer(fields), answer())).toBe(kind)
  })

  it.each([
    {}, { status: 'timeout', dnsRcode: 3 }, { status: 'unobservable', answerDigest: 'different' },
    { targetRef: 'changed-target', dnsRcode: 3 }, { probe: 'doh', dnsRcode: 3 },
    { dnsContext: undefined, dnsRcode: 3 }, { stage: 'tcp', answerDigest: 'different' },
    { status: 'target_rejected', reason: 'dns_address_budget_exceeded' },
    { dnsRcode: undefined, answerCount: undefined, answerDigest: undefined },
  ])('does not infer a DNS difference from %o', fields => {
    expect(dnsDifference(answer(), answer(fields))).toBeUndefined()
  })

  it('keeps the DNS comparison when a sibling probe lacks evidence', () => {
    const unavailable = answer({ probe: 'quic', status: 'unobservable' })
    const a = report([answer(), unavailable])
    const b = report([answer({ status: 'target_rejected', reason: 'dns_or_literal_address_not_public' }), unavailable])
    expect(comparable(a, b)).toBe(true)
    expect(comparable(report([unavailable]), report([unavailable]))).toBe(false)
  })

  it('correlates certificate evidence only to the observed target and answer set', () => {
    const reply = answer()
    const handshake = answer({ probe: 'tls13', status: 'ok', stage: 'tls', tlsVerified: true })
    expect(authenticatesDNSSet(reply, report([handshake]))).toBe(true)
    expect(authenticatesDNSSet(reply, report([{ ...handshake, answerDigest: 'other-set' }]))).toBe(false)
    expect(authenticatesDNSSet(reply, report([{ ...handshake, targetRef: 'other-target' }]))).toBe(false)
    expect(authenticatesDNSSet(reply, report([{ ...handshake, tlsVerified: false }]))).toBe(false)
  })

  it('rejects mismatched or stale report contexts', () => {
    const a = report([answer()])
    expect(comparable(a, report([answer()]))).toBe(true)
    expect(comparable(a, report([answer({ targetRef: 'new-target' })]))).toBe(false)
    expect(comparable(a, report([answer()], { pathEvidence: undefined }))).toBe(false)
    expect(comparable(a, report([answer()], { family: 'ipv6' }))).toBe(false)
    expect(comparable(a, report([answer()], { groupRevision: 'new-revision' }))).toBe(false)
    expect(comparable(a, report([answer()], { startedAt: '2026-11-25T17:15:01Z' }))).toBe(false)
    expect(comparable(a, report([answer()], { startedAt: 'invalid-date' }))).toBe(false)
  })
})

describe('run comparison', () => {
  const web: Row = { target: 0, targetRef: 'fixture', probe: 'https', stage: 'http', status: 'http_response', httpStatus: 204, elapsedMs: 1 }
  const voice: Row = { target: 1, targetRef: 'voice', probe: 'stun', status: 'unsupported', elapsedMs: 1 }

  it('finds observed stage and DNS differences and excludes a capability gap', () => {
    const panel = report([answer(), web, voice], { path: { mode: 'PANEL', ref: 'local-mixed' } })
    const baseline = report([answer({ status: 'target_rejected', reason: 'dns_or_literal_address_not_public', answerCount: undefined }),
      { ...web, stage: 'tls', status: 'tls_failed', httpStatus: undefined }, { ...voice, stage: 'stun', status: 'ok' }], {
      path: { mode: 'HOST_BASELINE' }, startedAt: '2026-11-25T17:01:00Z',
    })
    expect(compareProbeResults(panel, baseline)).toEqual({ outcomes: ['different', 'different', 'unconfirmed'], matched: 2, differed: 2, total: 3 })
    expect(compareProbeResults(baseline, panel)).toEqual(compareProbeResults(panel, baseline))
  })

  it('keeps missing facts and elapsed time out of the difference count', () => {
    const earlier = report([web, voice])
    const current = report([{ ...web, elapsedMs: 1000, httpProtocol: 'h2' }, { ...voice, status: 'unobservable' }])
    expect(compareProbeResults(current, earlier)).toEqual({ outcomes: ['same', 'unconfirmed'], matched: 1, differed: 0, total: 2 })
    expect(compareProbeResults(report([voice]), report([voice]))).toMatchObject({ matched: 0, differed: 0, total: 1 })
  })

  it('surfaces a different HTTP response even when both responses were limited', () => {
    expect(compareProbeResults(report([{ ...web, httpStatus: 403 }]), report([{ ...web, httpStatus: 429 }])))
      .toMatchObject({ outcomes: ['different'], matched: 1, differed: 1 })
  })

  it('does not summarize a partial run or pair changed targets, scope, hosts or stale cross-path observations', () => {
    const current = report([web, voice])
    expect(compareProbeResults(current, report([web, voice], { job: { jobId: 'partial', phase: 'CANCELED' } }))).toBeUndefined()
    expect(compareProbeResults(current, report([web]))).toBeUndefined()
    expect(compareProbeResults(current, report([{ ...web, targetRef: 'other-site' }, voice]))).toBeUndefined()
    expect(compareProbeResults(current, report([web, voice], { pathEvidence: { host: { id: 'other' }, scope: 'outbound-pinned-ip' } }))).toBeUndefined()
    expect(compareProbeResults(current, report([web, voice], { path: { mode: 'HOST_BASELINE' }, startedAt: '2026-11-25T17:25:00Z' }))).toBeUndefined()
  })
})
