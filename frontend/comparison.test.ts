import { describe, expect, it } from 'vitest'
import type { Report, Row } from './api'
import { authenticatesDNSSet, comparable, dnsDifference } from './comparison'

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
