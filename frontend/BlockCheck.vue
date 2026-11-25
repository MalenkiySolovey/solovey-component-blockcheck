<template>
  <v-container fluid class="blockcheck">
    <header class="d-flex align-center justify-space-between flex-wrap ga-2 mb-4">
      <h1 class="text-h5">{{ t('blockcheck.title') }}</h1>
      <div class="d-flex flex-wrap ga-2">
        <v-btn variant="text" icon="lucide:refresh-cw" size="small" :title="t('blockcheck.reload')" :aria-label="t('blockcheck.reload')" :disabled="busy || running" @click="reload" />
        <v-btn v-if="running" variant="tonal" prepend-icon="lucide:square" :disabled="stopping" @click="cancel">{{ t('blockcheck.cancel') }}</v-btn>
        <v-btn v-else color="primary" prepend-icon="lucide:play" :disabled="!canRun || !activeGroups" @click="start()">{{ t('blockcheck.checkAll') }}</v-btn>
      </div>
    </header>
    <v-alert v-if="error" type="error" variant="tonal" density="compact" class="mb-4" role="alert">{{ reason(error) }}</v-alert>
    <v-progress-linear v-if="loading" indeterminate aria-hidden="true" class="mb-4" />
    <div v-if="catalog" class="blockcheck-controls">
      <v-select :model-value="hostId" :items="[{value: hostId, title: hostId === 'local' ? t('blockcheck.local') : hostId}]"
        :label="t('blockcheck.host')" density="compact" hide-details readonly />
      <v-select v-model="mode" :items="modes" :label="t('blockcheck.path')" :disabled="running" density="compact" hide-details />
      <v-select v-model="family" :items="families" :label="t('blockcheck.family')" :disabled="running" density="compact" hide-details />
      <v-select v-model="depth" :items="depths" :label="t('blockcheck.depth')" :disabled="running" density="compact" hide-details />
      <v-select v-if="mode === 'PANEL' && options?.ingresses?.length" v-model="ingress" :items="options.ingresses"
        :label="t('blockcheck.ingress')" :disabled="running" density="compact" hide-details />
      <template v-if="mode === 'OUTBOUND'">
        <v-select v-model="outbound" :items="options?.outbounds ?? []" :label="t('blockcheck.outbound')" :disabled="running" density="compact" hide-details />
        <v-select v-model="resolver" :items="options?.resolvers ?? []" :label="t('blockcheck.resolver')" :disabled="running" density="compact" hide-details clearable />
      </template>
    </div>
    <p v-if="mode === 'OUTBOUND' && catalog" class="text-caption text-medium-emphasis mt-2">{{ t('blockcheck.dnsHint') }}</p>
    <div v-if="zapretContext" class="d-flex flex-wrap align-center ga-1 mt-2 text-caption">
      {{ t('blockcheck.zapretContext', { strategy: zapretContext }) }}
      <v-btn v-if="router.hasRoute('component.zapret')" :to="{ name: 'component.zapret', params: { hostId }, query: { binding: outbound } }"
        variant="text" size="small" append-icon="mdi-open-in-new">{{ t('blockcheck.zapretEvidence') }}</v-btn>
    </div>
    <v-alert v-if="pathBlocked" type="info" variant="tonal" density="compact" class="my-3">{{ reason(pathBlocked) }}</v-alert>

    <div v-if="catalog" class="d-flex align-center flex-wrap ga-2 my-3">
      <v-btn variant="tonal" prepend-icon="lucide:plus" :disabled="busy || running" @click="newGroup">{{ t('blockcheck.create') }}</v-btn>
      <v-btn variant="text" prepend-icon="lucide:upload" :disabled="busy || running" @click="upload?.click()">{{ t('blockcheck.import') }}</v-btn>
      <v-btn variant="text" prepend-icon="lucide:rotate-ccw" :disabled="busy || running" @click="restoreId = ''; restoring = true">{{ t('blockcheck.restore') }}</v-btn>
      <input ref="upload" type="file" accept="application/json,.json" hidden @change="importFile" />
    </div>
    <section v-if="running || shownProgress" class="blockcheck-progress mb-3" aria-labelledby="blockcheck-progress">
      <div class="d-flex flex-wrap align-center justify-space-between ga-1">
        <h2 id="blockcheck-progress" class="text-subtitle-2">{{ progressTitle }}</h2>
        <span v-if="shownProgress" class="text-caption" role="status">{{ t('blockcheck.progress', shownProgress.progress) }}</span>
      </div>
      <v-progress-linear v-if="running" class="mt-2" :aria-label="t('blockcheck.progressLabel')"
        :indeterminate="!shownProgress" :model-value="shownProgress ? shownProgress.progress.probesDone / shownProgress.progress.totalProbes * 100 : 0" />
    </section>
    <div v-if="notice" class="text-caption mb-2" role="status">{{ notice }}</div>
    <p v-if="catalog && !catalog.groups.length" class="text-body-2 text-medium-emphasis">{{ t('blockcheck.none') }}</p>
    <div v-else-if="catalog" class="blockcheck-group-grid">
      <v-card v-for="(row, index) in catalog.groups" :key="row.id" tag="article" variant="outlined" class="blockcheck-group pa-3" :data-group-id="row.id">
        <div class="d-flex justify-space-between align-start ga-2">
          <h2 class="text-subtitle-1 font-weight-medium">{{ row.name }}</h2>
          <v-menu>
            <template #activator="{ props }">
              <v-btn v-bind="props" icon="lucide:ellipsis-vertical" variant="text" size="small" density="comfortable"
                :aria-label="t('blockcheck.groupActions', { group: row.name })" :title="t('blockcheck.group')" :disabled="busy || running" />
            </template>
            <v-list density="compact">
              <v-list-item prepend-icon="lucide:pencil" :title="t('blockcheck.edit')" @click="editGroup(row)" />
              <v-list-item prepend-icon="lucide:copy" :title="t('blockcheck.clone')" @click="duplicate(row)" />
              <v-list-item prepend-icon="lucide:download" :title="t('blockcheck.export')" @click="download(row)" />
              <v-list-item :prepend-icon="row.disabled ? 'lucide:square-check' : 'lucide:square'"
                :title="t(`blockcheck.${row.disabled ? 'include' : 'exclude'}`)" @click="change('toggle', { id: row.id })" />
              <v-list-item :disabled="index === 0" prepend-icon="lucide:arrow-up" :title="t('blockcheck.up')" @click="move(row.id, -1)" />
              <v-list-item :disabled="index + 1 === catalog.groups.length" prepend-icon="lucide:arrow-down" :title="t('blockcheck.down')" @click="move(row.id, 1)" />
              <v-list-item prepend-icon="lucide:trash-2" :title="t('blockcheck.remove')" @click="deleting = row" />
            </v-list>
          </v-menu>
        </div>
        <p class="text-caption text-medium-emphasis mb-2">{{ row.description || t('blockcheck.targetsCount', { count: row.targets.length }) }}</p>
        <div class="d-flex align-center flex-wrap ga-2 mb-2">
          <v-chip :color="groupSummary(row.id).color" density="compact" size="small" variant="tonal">{{ groupSummary(row.id).label }}</v-chip>
          <span v-if="row.disabled" class="text-caption text-medium-emphasis">{{ t('blockcheck.excluded') }}</span>
          <span v-if="lastReport(row.id)" class="text-caption text-medium-emphasis">{{ runTitle(lastReport(row.id)!) }}</span>
        </div>
        <div class="d-flex flex-wrap align-center ga-2 mt-auto">
          <v-btn size="small" variant="tonal" prepend-icon="lucide:play" :disabled="!canRun || running || selectionEmpty(row.id)" @click="start(row.id)">{{ t('blockcheck.check') }}</v-btn>
          <v-btn size="small" variant="text" :append-icon="expanded && selected === row.id ? 'lucide:chevron-up' : 'lucide:chevron-down'"
            :aria-expanded="expanded && selected === row.id" @click="showGroup(row)">{{ t('blockcheck.groupDetails') }}</v-btn>
        </div>
      </v-card>
    </div>
    <h2 v-if="expanded && group" id="blockcheck-group-details" class="text-h6 mt-5 mb-2">{{ group.name }}</h2>
    <v-table v-if="expanded && group" class="probe-table" density="compact">
      <thead><tr><th scope="col">{{ t('blockcheck.target') }}</th><th scope="col">{{ t('blockcheck.role') }}</th><th scope="col">{{ t('blockcheck.probes') }}</th></tr></thead>
      <tbody>
        <tr v-for="(target, index) in group.targets" :key="index">
          <th scope="row" class="text-start"><div>{{ target.name }}</div><div class="text-caption text-medium-emphasis">{{ target.host }}</div></th>
          <td>{{ target.role }}</td>
          <td><div class="d-flex flex-wrap ga-2 py-1">
            <v-checkbox-btn v-for="probe in target.probes" :key="probe" :label="probe.toUpperCase()" class="probe-choice" density="compact"
              :aria-label="`${target.name}: ${probe.toUpperCase()}`" :model-value="enabled.has(cellKey(index, probe))"
              :disabled="running" @update:model-value="toggle(index, probe, $event === true)" />
          </div></td>
        </tr>
      </tbody>
    </v-table>

    <section v-if="expanded && visibleReport" class="mt-6" aria-labelledby="blockcheck-results">
      <div class="d-flex align-center justify-space-between flex-wrap ga-2 mb-3">
        <h2 id="blockcheck-results" class="text-h6">{{ t('blockcheck.result') }}</h2>
        <v-btn variant="text" prepend-icon="mdi-content-copy" @click="copyFacts">{{ t('blockcheck.exportFacts') }}</v-btn>
      </div>
      <div class="blockcheck-results-controls mb-3">
        <v-select v-model="runIndex" :items="runChoices" :label="t('blockcheck.history')" density="compact" hide-details />
        <v-select v-if="comparisonChoices.length" v-model="compareIndex" :items="comparisonChoices" :label="t('blockcheck.compare')" density="compact" hide-details clearable />
      </div>
      <div class="text-caption text-medium-emphasis mb-2">{{ t('blockcheck.factsHint') }}</div>
      <details class="mb-2">
        <summary>{{ t('blockcheck.details') }}</summary>
        <dl class="detail-list mt-2">
          <dt>{{ t('blockcheck.path') }}</dt><dd>{{ t(`blockcheck.${visibleReport.path.mode}`) }} · {{ visibleReport.pathEvidence?.scope ?? t('blockcheck.unknown') }}</dd>
          <dt>{{ t('blockcheck.observed') }}</dt><dd>{{ visibleReport.pathEvidence?.context ?? t('blockcheck.unknown') }}</dd>
          <dt>{{ t('blockcheck.revision') }}</dt><dd>{{ visibleReport.pathEvidence?.generation ?? t('blockcheck.unknown') }}</dd>
        </dl>
      </details>
      <ul v-if="visibleReport.findings?.length" class="finding-list mb-3">
        <li v-for="finding in visibleReport.findings" :key="`${finding.target}:${finding.code}`">
          <strong>{{ targetLabel(finding.target) }}</strong> · {{ findingText(finding) }}
          <div class="text-caption text-medium-emphasis">{{ findingDetails(finding) }}</div>
        </li>
      </ul>
      <v-table class="probe-table" density="compact">
        <thead><tr><th scope="col">{{ t('blockcheck.target') }}</th><th scope="col">{{ t('blockcheck.result') }}</th>
          <th v-if="comparison" scope="col">{{ t(`blockcheck.${comparison.report.path.mode}`) }}</th><th scope="col">{{ t('blockcheck.observed') }}</th></tr></thead>
        <tbody>
          <tr v-for="(row, index) in visibleReport.results" :key="cellKey(row.target, row.probe)">
            <th scope="row" class="text-start">{{ targetLabel(row.target) }} · {{ row.probe.toUpperCase() }}</th>
            <td>{{ observation(row) }}<div class="text-caption text-medium-emphasis">{{ row.elapsedMs }} ms</div>
              <details v-if="row.interpretation" class="mt-1 text-caption">
                <summary>{{ findingText(row.interpretation) }}</summary>
                {{ findingDetails(row.interpretation) }}
              </details>
            </td>
            <td v-if="comparison">{{ observation(comparison.report.results[index]) }}<div class="text-caption text-medium-emphasis">{{ comparison.report.results[index].elapsedMs }} ms</div></td>
            <td class="text-caption">{{ rowFacts(row) }}</td>
          </tr>
        </tbody>
      </v-table>
    </section>

    <v-dialog :model-value="!!draft" max-width="720" @update:model-value="!$event && (draft = undefined)">
      <v-card v-if="draft" :title="t(`blockcheck.${draftMode}`)">
        <v-card-text>
          <v-alert v-if="editError" type="error" variant="tonal" density="compact" class="mb-3">{{ reason(editError) }}</v-alert>
          <v-text-field v-model="draft.name" :label="t('blockcheck.name')" maxlength="96" density="compact" />
          <template v-if="draftMode !== 'clone'">
          <v-textarea v-model="draft.description" :label="t('blockcheck.description')" maxlength="384" rows="2" density="compact" />
          <div v-for="(target, index) in draft.targets" :key="index" class="target-editor pt-3">
            <div class="d-flex justify-space-between align-center ga-2 mb-2">
              <h3 class="text-subtitle-2">{{ t('blockcheck.target') }} {{ index + 1 }}</h3>
              <div>
                <v-btn icon="mdi-arrow-up" size="small" variant="text" :aria-label="t('blockcheck.up')" :title="t('blockcheck.up')" :disabled="index === 0" @click="moveTarget(index, -1)" />
                <v-btn icon="mdi-arrow-down" size="small" variant="text" :aria-label="t('blockcheck.down')" :title="t('blockcheck.down')" :disabled="index === draft.targets.length - 1" @click="moveTarget(index, 1)" />
                <v-btn icon="mdi-delete-outline" size="small" variant="text" :aria-label="t('blockcheck.removeTarget')" :title="t('blockcheck.removeTarget')" @click="draft.targets.splice(index, 1)" />
              </div>
            </div>
            <div class="blockcheck-results-controls">
              <v-text-field v-model="target.name" :label="t('blockcheck.name')" maxlength="96" density="compact" />
              <v-text-field v-model="target.host" :label="t('blockcheck.targetHost')" maxlength="253" density="compact" spellcheck="false" />
              <v-text-field v-model="target.role" :label="t('blockcheck.role')" maxlength="128" density="compact" />
              <v-select v-model="target.probes" :items="catalog?.probes ?? []" :label="t('blockcheck.probes')" multiple density="compact" />
              <v-select v-if="target.probes.includes('stun')" v-model="target.port" :items="[3478, 19302]" :label="t('blockcheck.port')" density="compact" />
            </div>
          </div>
          <v-btn variant="text" prepend-icon="mdi-plus" @click="draft.targets.push(blankTarget())">{{ t('blockcheck.addTarget') }}</v-btn>
          </template>
        </v-card-text>
        <v-card-actions><v-spacer />
          <v-btn :disabled="busy" @click="draft = undefined">{{ t('blockcheck.cancel') }}</v-btn>
          <v-btn color="primary" :loading="busy" :disabled="!draft.name.trim() || !draft.targets.length" @click="saveDraft">{{ t('blockcheck.save') }}</v-btn>
        </v-card-actions>
      </v-card>
    </v-dialog>
    <v-dialog :model-value="!!deleting" max-width="460" @update:model-value="!$event && (deleting = undefined)">
      <v-card :title="t('blockcheck.deletePrompt')" :text="deleting?.name">
        <v-card-actions><v-spacer /><v-btn @click="deleting = undefined">{{ t('blockcheck.cancel') }}</v-btn>
          <v-btn color="error" :loading="busy" @click="remove">{{ t('blockcheck.remove') }}</v-btn></v-card-actions>
      </v-card>
    </v-dialog>
    <v-dialog v-model="restoring" max-width="460">
      <v-card :title="t('blockcheck.restorePrompt')">
        <v-card-text><v-select v-model="restoreId" :items="catalog?.templates ?? []" item-title="name" item-value="id" :label="t('blockcheck.template')" /></v-card-text>
        <v-card-actions><v-spacer /><v-btn @click="restoring = false">{{ t('blockcheck.cancel') }}</v-btn>
          <v-btn color="primary" :loading="busy" :disabled="!restoreId" @click="restore">{{ t('blockcheck.restore') }}</v-btn></v-card-actions>
      </v-card>
    </v-dialog>
  </v-container>
</template>

<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRoute, useRouter } from 'vue-router'
import { cancelSuite, comparable, load, openTransfer, redacted, save, streamSuite, transferSchema, type Catalog, type Depth, type Family, type Finding, type Group, type GroupFinding, type Mode, type Options, type Report, type Row, type SuiteEvent, type Target } from './api'

const { t, te } = useI18n()
const route = useRoute()
const router = useRouter()
const hostId = computed(() => typeof route.params.hostId === 'string' ? route.params.hostId : 'local')
const options = ref<Options>()
const catalog = ref<Catalog>()
const selected = ref('')
const expanded = ref(false)
const mode = ref<Mode>('PANEL')
const family = ref<Family>('any')
const depth = ref<Depth>('quick')
const ingress = ref('')
const outbound = ref('')
const resolver = ref<string | null>(null)
const enabled = ref(new Set<string>())
const draft = ref<Group>()
const draftMode = ref<'create' | 'edit' | 'clone' | 'import'>('edit')
const draftRevision = ref('')
const upload = ref<HTMLInputElement>()
const busy = ref(false)
const loading = ref(false)
const running = ref(false)
const stopping = ref(false)
const deleting = ref<Group>()
const restoring = ref(false)
const restoreId = ref('')
const error = ref('')
const editError = ref('')
const notice = ref('')
type HistoryEntry = { report: Report; labels: string[] }
const history = ref(new Map<string, HistoryEntry[]>())
const live = ref<SuiteEvent>()
const lastAggregate = ref<SuiteEvent>()
const runIndex = ref(0)
const compareIndex = ref<number | null>(null)
let runController: AbortController | undefined
let loadController: AbortController | undefined

const pathKeys: Mode[] = ['PANEL', 'HOST_BASELINE', 'OUTBOUND']
const familyKeys: Family[] = ['any', 'ipv4', 'ipv6']
const modes = computed(() => pathKeys.map(value => ({ value, title: t(`blockcheck.${value}`) })))
const families = computed(() => familyKeys.map(value => ({ value, title: t(`blockcheck.${value}`) })))
const depths = computed(() => (['quick', 'deep'] as const).map(value => ({ value, title: t(`blockcheck.${value}`) })))
const groupIndex = computed(() => catalog.value?.groups.findIndex(row => row.id === selected.value) ?? -1)
const group = computed(() => catalog.value?.groups[groupIndex.value])
const activeGroups = computed(() => catalog.value?.groups.filter(row => !row.disabled).length ?? 0)
const cellKey = (index: number, probe: string) => `${index}:${probe}`
const cells = computed(() => group.value?.targets.flatMap((target, index) => target.probes.map(probe => ({ target: index, probe }))) ?? [])
const pathBlocked = computed(() => options.value?.unavailable[mode.value] ?? (options.value && mode.value === 'OUTBOUND'
  ? outbound.value && !options.value.outbounds.includes(outbound.value) ? 'outbound_not_available'
    : resolver.value && !options.value.resolvers.includes(resolver.value) ? 'dns_transport_not_available' : undefined
  : undefined))
const zapretContext = computed(() => mode.value === 'OUTBOUND' && outbound.value && outbound.value === route.query.outbound &&
  typeof route.query.zapret === 'string' && route.query.zapret.length <= 128 ? route.query.zapret : '')
const pathRef = computed(() => mode.value === 'OUTBOUND' ? outbound.value : mode.value === 'PANEL' ? ingress.value : undefined)
const canRun = computed(() => !loading.value && !busy.value && !pathBlocked.value && hostId.value === 'local' && !!catalog.value && !!options.value && (
  mode.value === 'OUTBOUND' ? options.value.outbounds.includes(outbound.value) : mode.value !== 'PANEL' || !!options.value.ingresses?.includes(ingress.value)
))
const selectionEmpty = (id: string) => expanded.value && id === selected.value && enabled.value.size === 0
const shownProgress = computed(() => running.value ? live.value : lastAggregate.value)
const progressTitle = computed(() => stopping.value ? t('blockcheck.stopping') : t(`blockcheck.phase.${shownProgress.value?.job.phase ?? 'RUNNING'}`))
const groupHistory = computed(() => history.value.get(selected.value) ?? [])
const lastReport = (id: string) => history.value.get(id)?.[0]?.report
const visibleReport = computed(() => groupHistory.value[runIndex.value]?.report)
const runTitle = (report: Report) => `${new Date(report.startedAt).toLocaleTimeString()} · ${t(`blockcheck.${report.path.mode}`)}`
const runChoices = computed(() => groupHistory.value.map(({report}, value) => ({ value, title: runTitle(report) })))
const comparisonChoices = computed(() => runChoices.value.filter(({value}) => value !== runIndex.value && visibleReport.value && comparable(visibleReport.value, groupHistory.value[value].report)))
const comparison = computed(() => comparisonChoices.value.some(item => item.value === compareIndex.value) ? groupHistory.value[compareIndex.value!] : undefined)

function groupSummary(id: string) {
  const active = live.value?.group
  if (running.value && live.value?.kind === 'progress' && active?.id === id) {
    return { label: t('blockcheck.groupProgress', active), color: 'info' }
  }
  const report = lastReport(id)
  if (!report) return { label: t('blockcheck.notRun'), color: undefined }
  if (report.job.phase !== 'COMPLETED') return { label: t(`blockcheck.phase.${report.job.phase}`), color: 'warning' }
  const positive = report.results.filter(row => row.status === 'ok' || row.status === 'dns_response' && !!row.answerCount && !row.dnsRcode ||
    row.status === 'http_response' && (row.httpStatus ?? 0) >= 200 && (row.httpStatus ?? 0) < 300 &&
      (!['http-data', 'https-data'].includes(row.probe) || !!row.bodyBytes)).length
  return { label: t('blockcheck.summary', { positive, count: report.results.length }), color: positive === report.results.length ? 'success' : 'warning' }
}

function reason(code: string) { return te(`blockcheck.reason.${code}`) ? t(`blockcheck.reason.${code}`) : code }
function errorCode(err: unknown) {
  const e = err as { message?: string; response?: { data?: { msg?: string } } }
  return e?.response?.data?.msg || e?.message || 'blockcheck_request_failed'
}
function observation(row: Row) {
  const text = t(`blockcheck.status.${row.status}`)
  if (row.httpStatus) return `${text} ${row.httpStatus}`
  if (row.dnsRcode !== undefined) return `${text} · RCODE ${row.dnsRcode} · ${row.answerCount ?? 0}`
  return text
}
function rowFacts(row: Row) {
  return [row.stage && t(`blockcheck.stage.${row.stage}`), row.reason && reason(row.reason), row.dnsContext, row.dnsTransport,
    row.dnsConfiguredTransport && t('blockcheck.configuredTransport', { transport: row.dnsConfiguredTransport }),
    row.addressFamily, row.tlsVersion, row.stage === 'transfer' && t('blockcheck.transferSample', {
      bytes: row.bodyBytes ?? 0, expected: row.bodyExpected ?? t('blockcheck.unknownLength'), ms: row.bodyReadMs ?? 0,
    }), row.socket?.egress].filter(Boolean).join(' · ') || t('blockcheck.unknown')
}
const targetLabel = (index: number) => groupHistory.value[runIndex.value]?.labels[index] ?? `#${index + 1}`
const findingText = (finding: Finding) => t(`blockcheck.finding.${finding.code}`)
function findingDetails(finding: Finding) {
  const alternatives = finding.alternatives?.map(code => t(`blockcheck.alternative.${code}`)).join('; ')
  return [t(`blockcheck.confidence.${finding.confidence}`), alternatives && t('blockcheck.alternatives', { alternatives })].filter(Boolean).join(' · ')
}
function updateCatalog(value: Catalog, preferred = selected.value) {
  catalog.value = value
  selected.value = value.groups.find(row => row.id === preferred)?.id ?? value.groups[0]?.id ?? ''
  const kept = new Set(value.groups.map(row => row.id))
  for (const id of history.value.keys()) if (!kept.has(id)) history.value.delete(id)
}
async function reload() {
  loadController?.abort()
  const request = new AbortController()
  loadController = request
  loading.value = true
  error.value = ''
  try {
    const value = await load(request.signal)
    if (request.signal.aborted) return
    options.value = value.options
    if (!value.options.ingresses?.includes(ingress.value)) ingress.value = value.options.ingresses?.[0] ?? ''
    updateCatalog(value.catalog)
  } catch (err) {
    if (!request.signal.aborted) error.value = errorCode(err)
  } finally {
    if (loadController === request) loading.value = false
  }
}
function toggle(index: number, probe: string, checked: boolean) {
  const key = cellKey(index, probe)
  if (checked) enabled.value.add(key)
  else enabled.value.delete(key)
}
function blankTarget(): Target { return { name: '', host: '', role: '', probes: ['https'] } }
function setupDraft(kind: typeof draftMode.value, group: Group) {
  draftMode.value = kind
  draftRevision.value = catalog.value?.revision ?? ''
  editError.value = ''
  draft.value = { ...group, targets: group.targets.map(row => ({ ...row, probes: [...row.probes] })) }
}
const newGroup = () => setupDraft('create', {id: '', name: '', description: '', targets: [blankTarget()]})
const editGroup = (row: Group) => setupDraft('edit', row)
const duplicate = (row: Group) => setupDraft('clone', { ...row, name: `${row.name} (${t('blockcheck.clone')})` })
async function importFile(ev: Event) {
  const input = ev.target as HTMLInputElement
  const file = input.files?.[0]
  input.value = ''
  if (!file) return
  try { setupDraft('import', (await openTransfer(file)).group) } catch (err) { error.value = errorCode(err) }
}
async function change(action: string, fields: object, revision = catalog.value?.revision, editing = false) {
  if (busy.value || !revision) return false
  busy.value = true
  error.value = ''; editError.value = ''
  try {
    const next = await save({ action, ...fields, expectedRevision: revision })
    const added = ['create', 'clone', 'import'].includes(action)
    updateCatalog(next, added ? next.groups.at(-1)?.id : selected.value)
    if (added && group.value) await showGroup(group.value, true)
    return true
  } catch (err) {
    if (editing) editError.value = errorCode(err)
    else error.value = errorCode(err)
    return false
  } finally { busy.value = false }
}
async function saveDraft() {
  if (!draft.value) return
  const { id, name, description, disabled, targets } = draft.value
  const edited: Group = { id, name: name.trim(), description: description?.trim(), disabled, targets: targets.map(target => ({
    name: target.name.trim(), host: target.host.trim().toLowerCase(), role: target.role.trim(), probes: [...target.probes],
    ...(target.probes.includes('stun') ? { port: target.port } : {}),
  })) }
  const action = draftMode.value
  const fields = action === 'import' ? { transfer: { schema: transferSchema, group: edited } } : { id, group: edited }
  if (await change(action, fields, draftRevision.value, true)) draft.value = undefined
}
async function remove() { if (deleting.value && await change('delete', { id: deleting.value.id })) deleting.value = undefined }
async function restore() { if (restoreId.value && await change('restore', { id: restoreId.value })) restoring.value = false }
function move(id: string, offset: number) {
  const order = catalog.value?.groups.map(row => row.id)
  const previous = order?.indexOf(id) ?? -1, next = previous + offset
  if (!order || previous < 0 || next < 0 || next >= order.length) return
  ;[order[previous], order[next]] = [order[next], order[previous]]
  void change('order', { order })
}
function moveTarget(previous: number, offset: number) {
  const targets = draft.value?.targets
  const next = previous + offset
  if (!targets || next < 0 || next >= targets.length) return
  ;[targets[previous], targets[next]] = [targets[next], targets[previous]]
}
function download(row: Group) {
  const blob = new Blob([JSON.stringify({ schema: transferSchema, group: row })], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url; link.download = `${row.id}.blockcheck.json`; link.click()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}
async function showGroup(row: Group, force = false) {
  expanded.value = force || row.id !== selected.value || !expanded.value
  selected.value = row.id
  if (expanded.value) {
    await nextTick()
    document.getElementById('blockcheck-group-details')?.scrollIntoView({ block: 'nearest' })
  }
}
async function start(groupId?: string) {
  if (!canRun.value || !catalog.value || running.value || (!groupId && !activeGroups.value) || (groupId && selectionEmpty(groupId))) return
  const request = new AbortController()
  runController = request
  const labels = new Map(catalog.value.groups.map(row => [row.id, row.targets.map(target => target.name)]))
  const partial = new Map<string, Row[]>()
  const findings = new Map<string, GroupFinding[]>()
  const selection = groupId === selected.value && expanded.value && enabled.value.size !== cells.value.length
    ? cells.value.filter(row => enabled.value.has(cellKey(row.target, row.probe))) : undefined
  running.value = true; stopping.value = false; live.value = undefined; notice.value = ''; error.value = ''
  let terminal: SuiteEvent | undefined
  try {
    await streamSuite({ groupId, all: !groupId, catalogRevision: catalog.value.revision,
      path: { mode: mode.value, ref: pathRef.value, resolver: mode.value === 'OUTBOUND' ? resolver.value ?? undefined : undefined },
      family: family.value, depth: depth.value, cells: selection }, request.signal, event => {
      if (runController !== request || request.signal.aborted) return
      const id = event.group?.id
      // Drop batch payloads from the last-event slot; rows live with their group.
      live.value = { ...event, rows: undefined, findings: undefined, report: undefined }
      if (id && event.rows) {
        const rows = partial.get(id) ?? []
        rows.push(...event.rows)
        partial.set(id, rows)
      }
      if (id && event.findings) {
        const items = findings.get(id) ?? []
        items.push(...event.findings)
        findings.set(id, items)
      }
      if (id && event.report) {
        const report: Report = { ...event.report, results: partial.get(id) ?? [], findings: findings.get(id) }
        const entry = { report, labels: labels.get(id) ?? [] }
        history.value.set(id, [entry, ...(history.value.get(id) ?? [])].slice(0, 3))
        partial.delete(id)
        findings.delete(id)
        if (id === selected.value) { runIndex.value = 0; compareIndex.value = null }
      }
      if (event.kind === 'finished') terminal = event
    })
    if (!request.signal.aborted && terminal) {
      if (!groupId) lastAggregate.value = terminal
      if (terminal.job.phase === 'CANCELED') notice.value = t('blockcheck.canceled')
      else if (terminal.job.problem) error.value = terminal.job.problem.code
    }
  } catch (err) {
    if (runController === request && !request.signal.aborted) error.value = errorCode(err)
  } finally {
    if (runController === request) { running.value = false; stopping.value = false; live.value = undefined }
  }
}
async function cancel() {
  const request = runController, job = live.value?.job
  if (!request || stopping.value || job?.phase === 'COMPLETED') return
  if (!job) { request.abort(); notice.value = t('blockcheck.canceled'); return }
  if (!job.cancelSupported) return
  stopping.value = true
  try { await cancelSuite(job.operationId, request.signal) }
  catch (err) {
    if (runController !== request || request.signal.aborted || !running.value) return
    stopping.value = false
    if (errorCode(err) !== 'blockcheck_run_not_found') error.value = errorCode(err)
  }
}
async function copyFacts() {
  if (!visibleReport.value) return
  try {
    await navigator.clipboard.writeText(JSON.stringify(redacted(visibleReport.value), null, 2))
    notice.value = t('blockcheck.copied')
  } catch (err) { error.value = errorCode(err) }
}
watch(cells, rows => { enabled.value = new Set(rows.map(row => cellKey(row.target, row.probe))) })
watch(runIndex, () => { compareIndex.value = null })
watch(selected, () => { runIndex.value = 0; compareIndex.value = null })
watch(hostId, () => {
  runController?.abort(); runController = undefined; running.value = false; stopping.value = false
  catalog.value = undefined; options.value = undefined; history.value.clear(); live.value = undefined; lastAggregate.value = undefined
  expanded.value = false
  void reload()
}, { immediate: true })
watch(() => route.fullPath, () => {
  const { query } = route
  mode.value = query.resolver || typeof query.outbound === 'string' ? 'OUTBOUND' : 'PANEL'
  outbound.value = typeof query.outbound === 'string' ? query.outbound : ''
  resolver.value = typeof query.resolver === 'string' ? query.resolver : null
}, { immediate: true })
onBeforeUnmount(() => { runController?.abort(); loadController?.abort() })
</script>

<style scoped>
.blockcheck { max-width: 1240px; }
.blockcheck-controls { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(100%, 210px), 1fr)); gap: 12px; }
.blockcheck-results-controls { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(100%, 240px), 1fr)); gap: 8px 12px; }
.blockcheck-group-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(100%, 260px), 1fr)); gap: 10px; }
.blockcheck-group { display: flex; flex-direction: column; border-radius: 8px; overflow-wrap: anywhere; }
.blockcheck-progress { border-block: 1px solid rgba(var(--v-border-color), var(--v-border-opacity)); padding-block: 8px; }
.probe-table :deep(th), .probe-table :deep(td) { overflow-wrap: anywhere; }
.probe-choice { flex: 0 0 auto; }
.target-editor { border-top: 1px solid rgba(var(--v-border-color), var(--v-border-opacity)); }
.detail-list { display: grid; grid-template-columns: max-content minmax(0, 1fr); gap: 4px 12px; }
.detail-list dd { overflow-wrap: anywhere; }
.finding-list { padding-inline-start: 1.25rem; overflow-wrap: anywhere; }
</style>
