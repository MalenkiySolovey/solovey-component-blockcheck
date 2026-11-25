import api from '@solovey/component-ui/api'

export type Mode = 'PANEL' | 'HOST_BASELINE' | 'OUTBOUND'
export type Family = 'any' | 'ipv4' | 'ipv6'
export type Depth = 'quick' | 'deep'
export type Target = { name: string; host: string; role: string; port?: number; probes: string[] }
export type Group = { id: string; name: string; description?: string; origin?: { template: string; commit: string }; disabled?: boolean; targets: Target[] }
export type Catalog = { groups: Group[]; templates: Group[]; probes: string[]; revision: string }
export type Transfer = { schema: 'solovey.blockcheck.group/v1'; group: Group }
export type Cell = { target: number; probe: string }
type Socket = { interface?: string; egress?: string; outsidePanel?: boolean }
export type Finding = { code: string; confidence: 'observed' | 'indicative'; alternatives?: string[] }
export type GroupFinding = Finding & { target: number; probes: string[] }
export type Row = Cell & { targetRef: string; status: string; reason?: string; elapsedMs: number; addressFamily?: string;
  dnsContext?: string; dnsTransport?: string; dnsConfiguredTransport?: string; dnsRcode?: number; answerCount?: number; answerDigest?: string;
  tlsVerified?: boolean; tlsVersion?: string; httpStatus?: number; stage?: string; interpretation?: Finding;
  bodyBytes?: number; bodyReadMs?: number; bodyExpected?: number; socket?: Socket; dnsSocket?: Socket }
type Path = { mode: Mode; ref?: string; resolver?: string }
export type Report = { job: { jobId: string; phase: string }; path: Path; groupId: string; groupRevision: string; family: Family;
  pathEvidence?: { host: { id: string }; generation?: string; scope: string; context?: string }; startedAt: string; results: Row[]; findings?: GroupFinding[] }
export type Options = { outbounds: string[]; resolvers: string[]; ingresses?: string[]; unavailable: Partial<Record<Mode, string>> }
type SuiteRequest = { groupId?: string; all?: boolean; catalogRevision: string; path: Path; family: Family; cells?: Cell[]; depth?: Depth }
export type SuiteEvent = { kind: 'started' | 'progress' | 'group' | 'finished'; job: {
    operationId: string; phase: string; problem?: { code: string }; cancelSupported: boolean
  }; progress: { groupsDone: number; totalGroups: number; probesDone: number; totalProbes: number };
  group?: { id: string; completed: number; total: number }; rows?: Row[]; findings?: GroupFinding[]; report?: Omit<Report, 'results'> }
interface Envelope<T> { success: boolean; msg: string; obj: T }
const base = 'api/components/blockcheck'
const catalogBytes = 128 * 1024

function unwrap<T>({ data }: { data: Envelope<T> }): T {
  if (!data.success) throw new Error(data.msg || 'blockcheck_request_failed')
  return data.obj
}

async function post<T>(path: string, body: object, signal?: AbortSignal): Promise<T> {
  return unwrap(await api.post<Envelope<T>>(`${base}/${path}`, body, { signal, headers: { 'Content-Type': 'application/json' } }))
}

export async function load(signal: AbortSignal) {
  const [catalog, options] = await Promise.all([
    api.get<Envelope<Catalog>>(`${base}/groups`, { signal }), api.get<Envelope<Options>>(`${base}/options`, { signal }),
  ])
  return { catalog: unwrap(catalog), options: unwrap(options) }
}

export const save = (change: object) => post<Catalog>('groups', change)
export const cancelSuite = (operationId: string, signal: AbortSignal) => post<null>('run/cancel', { operationId }, signal)

export async function streamSuite(request: SuiteRequest, signal: AbortSignal, emit: (event: SuiteEvent) => void) {
  const { data, headers } = await api.post<ReadableStream<Uint8Array>>(`${base}/run/stream`, request, {
    adapter: 'fetch', responseType: 'stream', signal, headers: { 'Content-Type': 'application/json' },
  })
  const streaming = String(headers['content-type']).startsWith('application/x-ndjson')
  const reader = data.getReader()
  const decoder = new TextDecoder('utf-8', { fatal: true })
  let pending = '', terminal = false
  try {
    while (!signal.aborted) {
      const { value, done } = await reader.read()
      if (done) { pending += decoder.decode(); break }
      pending += decoder.decode(value, { stream: true })
      if (streaming) {
        const lines = pending.split('\n')
        pending = lines.pop() ?? ''
        for (const line of lines) {
          if (line.length > 64 * 1024 || terminal) throw new Error('blockcheck_stream_interrupted')
          const event = JSON.parse(line) as SuiteEvent
          emit(event)
          terminal = event.kind === 'finished'
        }
      }
      if (pending.length > 64 * 1024) throw new Error('blockcheck_stream_interrupted')
    }
    if (signal.aborted) return
    if (!streaming) unwrap({ data: JSON.parse(pending) as Envelope<never> })
    if (!terminal || pending.length > 0) throw new Error('blockcheck_stream_interrupted')
  } finally {
    await reader.cancel().catch(() => {})
    reader.releaseLock()
  }
}

export const transferSchema = 'solovey.blockcheck.group/v1'
export async function openTransfer(file: File): Promise<Transfer> {
  if (file.size > catalogBytes) throw new Error('blockcheck_invalid_group')
  const data: Transfer = JSON.parse(await file.text())
  if (data?.schema !== transferSchema || typeof data.group?.name !== 'string' || !Array.isArray(data.group.targets) ||
      !data.group.targets.every(row => typeof row?.name === 'string' && typeof row.host === 'string' &&
        typeof row.role === 'string' && Array.isArray(row.probes))) throw new Error('blockcheck_invalid_group')
  return data
}

const comparisonStatuses = new Set(['ok', 'dns_response', 'http_response', 'resolution_failed', 'timeout', 'connection_refused',
  'connection_failed', 'connection_reset', 'stream_closed', 'tls_failed', 'certificate_invalid', 'protocol_error'])

export function comparable(a: Report, b: Report): boolean {
  if (!a.pathEvidence || !b.pathEvidence || a.pathEvidence.host.id !== b.pathEvidence.host.id || a.groupId !== b.groupId ||
      a.groupRevision !== b.groupRevision || a.family !== b.family || !a.results.length || a.results.length !== b.results.length ||
      Math.abs(Date.parse(a.startedAt) - Date.parse(b.startedAt)) > 15 * 60 * 1000) return false
  return a.results.every((row, index) => {
    const other = b.results[index]
    return row.target === other.target && row.targetRef === other.targetRef && row.probe === other.probe &&
      comparisonStatuses.has(row.status) && comparisonStatuses.has(other.status)
  })
}

export function redacted(report: Report): Report {
  const { mode } = report.path
  const evidence = report.pathEvidence
  return { ...report, path: { mode }, pathEvidence: evidence && { host: evidence.host, scope: evidence.scope, generation: evidence.generation },
    results: report.results.map(row => ({ ...row, socket: undefined, dnsSocket: undefined })) }
}
