<template>
  <v-container fluid class="blockcheck">
    <header class="d-flex align-center justify-space-between flex-wrap ga-2 mb-4">
      <h1 class="text-h5">{{ t('blockcheck.title') }}</h1>
      <v-btn variant="text" prepend-icon="mdi-refresh" :disabled="busy || running" @click="reload">{{ t('blockcheck.reload') }}</v-btn>
    </header>
    <v-alert v-if="error" type="error" variant="tonal" density="compact" class="mb-4" role="alert">{{ reason(error) }}</v-alert>
    <v-progress-linear v-if="loading || running" indeterminate aria-hidden="true" class="mb-4" />
    <div v-if="catalog" class="blockcheck-controls">
      <v-select :model-value="hostId" :items="[{value: hostId, title: hostId === 'local' ? t('blockcheck.local') : hostId}]"
        :label="t('blockcheck.host')" density="compact" hide-details readonly />
      <v-select v-model="selected" :items="catalog.groups" item-title="name" item-value="id" :disabled="running"
        :label="t('blockcheck.group')" :no-data-text="t('blockcheck.none')" density="compact" hide-details />
      <v-select v-model="mode" :items="modes" :label="t('blockcheck.path')" :disabled="running" density="compact" hide-details />
      <v-select v-model="family" :items="families" :label="t('blockcheck.family')" :disabled="running" density="compact" hide-details />
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
      <v-btn variant="text" prepend-icon="mdi-plus" :disabled="busy || running" @click="newGroup">{{ t('blockcheck.create') }}</v-btn>
      <v-btn variant="text" prepend-icon="mdi-pencil-outline" :disabled="!group || busy || running" @click="editGroup">{{ t('blockcheck.edit') }}</v-btn>
      <v-btn variant="text" prepend-icon="mdi-file-import-outline" :disabled="busy || running" @click="upload?.click()">{{ t('blockcheck.import') }}</v-btn>
      <input ref="upload" type="file" accept="application/json,.json" hidden @change="importFile" />
      <v-menu>
        <template #activator="{ props }">
          <v-btn v-bind="props" icon="mdi-dots-vertical" variant="text" size="small" :aria-label="t('blockcheck.group')" :disabled="busy || running" />
        </template>
        <v-list density="compact">
          <v-list-item :disabled="!group" prepend-icon="mdi-content-copy" :title="t('blockcheck.clone')" @click="duplicate" />
          <v-list-item :disabled="!group" prepend-icon="mdi-file-export-outline" :title="t('blockcheck.export')" @click="download" />
          <v-list-item :disabled="groupIndex < 1" prepend-icon="mdi-arrow-up" :title="t('blockcheck.up')" @click="move(-1)" />
          <v-list-item :disabled="groupIndex < 0 || groupIndex >= catalog.groups.length - 1" prepend-icon="mdi-arrow-down" :title="t('blockcheck.down')" @click="move(1)" />
          <v-list-item prepend-icon="mdi-restore" :title="t('blockcheck.restore')" @click="restoreId = group?.origin?.template ?? ''; restoring = true" />
          <v-list-item :disabled="!group" prepend-icon="mdi-delete-outline" :title="t('blockcheck.remove')" @click="deleting = true" />
        </v-list>
      </v-menu>
      <v-spacer />
      <v-btn v-if="running" variant="tonal" prepend-icon="mdi-stop" @click="cancel">{{ t('blockcheck.cancel') }}</v-btn>
      <v-btn v-else color="primary" prepend-icon="mdi-play" :disabled="!canStart" @click="start">{{ t('blockcheck.start') }}</v-btn>
    </div>
    <div v-if="group?.description" class="text-caption text-medium-emphasis mb-2">{{ group.description }}</div>
    <div v-if="notice" class="text-caption mb-2" role="status">{{ notice }}</div>
    <v-table v-if="group" class="probe-table" density="compact">
      <thead><tr><th scope="col">{{ t('blockcheck.target') }}</th><th scope="col">{{ t('blockcheck.role') }}</th><th scope="col">{{ t('blockcheck.probes') }}</th></tr></thead>
      <tbody>
        <tr v-for="(target, index) in group.targets" :key="index">
          <th scope="row" class="text-start"><div>{{ target.name }}</div><div class="text-caption text-medium-emphasis">{{ target.host }}</div></th>
          <td>{{ target.role }}</td>
          <td><div class="d-flex flex-wrap ga-2 py-1">
            <v-checkbox-btn v-for="probe in target.probes" :key="probe" :label="probe.toUpperCase()" class="probe-choice" density="compact"
              :aria-label="`${target.name}: ${probe.toUpperCase()}`" :model-value="enabled.includes(cellKey(index, probe))"
              :disabled="running || enabled.length >= 32 && !enabled.includes(cellKey(index, probe))" @update:model-value="toggle(index, probe, $event === true)" />
          </div></td>
        </tr>
      </tbody>
    </v-table>

    <section v-if="visibleReport" class="mt-6" aria-labelledby="blockcheck-results">
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
      <v-table class="probe-table" density="compact">
        <thead><tr><th scope="col">{{ t('blockcheck.target') }}</th><th scope="col">{{ t('blockcheck.result') }}</th>
          <th v-if="comparison" scope="col">{{ t(`blockcheck.${comparison.report.path.mode}`) }}</th><th scope="col">{{ t('blockcheck.observed') }}</th></tr></thead>
        <tbody>
          <tr v-for="(row, index) in visibleReport.results" :key="cellKey(row.target, row.probe)">
            <th scope="row" class="text-start">{{ history[runIndex]?.labels[row.target] ?? `#${row.target + 1}` }} · {{ row.probe.toUpperCase() }}</th>
            <td>{{ observation(row) }}<div class="text-caption text-medium-emphasis">{{ row.elapsedMs }} ms</div></td>
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
          <v-btn variant="text" prepend-icon="mdi-plus" :disabled="draft.targets.length >= 32" @click="draft.targets.push(blankTarget())">{{ t('blockcheck.addTarget') }}</v-btn>
          </template>
        </v-card-text>
        <v-card-actions><v-spacer />
          <v-btn :disabled="busy" @click="draft = undefined">{{ t('blockcheck.cancel') }}</v-btn>
          <v-btn color="primary" :loading="busy" :disabled="!draft.name.trim() || !draft.targets.length" @click="saveDraft">{{ t('blockcheck.save') }}</v-btn>
        </v-card-actions>
      </v-card>
    </v-dialog>
    <v-dialog v-model="deleting" max-width="460">
      <v-card :title="t('blockcheck.deletePrompt')" :text="group?.name">
        <v-card-actions><v-spacer /><v-btn @click="deleting = false">{{ t('blockcheck.cancel') }}</v-btn>
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
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRoute, useRouter } from 'vue-router'
import { comparable, load, openTransfer, redacted, run, save, transferSchema, type Catalog, type Family, type Group, type Mode, type Options, type Report, type Row, type Target } from './api'

const { t, te } = useI18n()
const route = useRoute()
const router = useRouter()
const hostId = computed(() => typeof route.params.hostId === 'string' ? route.params.hostId : 'local')
const options = ref<Options>()
const catalog = ref<Catalog>()
const selected = ref('')
const mode = ref<Mode>('PANEL')
const family = ref<Family>('any')
const outbound = ref('')
const resolver = ref<string | null>(null)
const enabled = ref<string[]>([])
const draft = ref<Group>()
const draftMode = ref<'create' | 'edit' | 'clone' | 'import'>('edit')
const draftRevision = ref('')
const upload = ref<HTMLInputElement>()
const busy = ref(false)
const loading = ref(false)
const running = ref(false)
const deleting = ref(false)
const restoring = ref(false)
const restoreId = ref('')
const error = ref('')
const editError = ref('')
const notice = ref('')
const history = ref<{report: Report; labels: string[]}[]>([])
const runIndex = ref(0)
const compareIndex = ref<number | null>(null)
let runController: AbortController | undefined
let loadController: AbortController | undefined

const pathKeys: Mode[] = ['PANEL', 'HOST_BASELINE', 'OUTBOUND']
const familyKeys: Family[] = ['any', 'ipv4', 'ipv6']
const modes = computed(() => pathKeys.map(value => ({ value, title: t(`blockcheck.${value}`) })))
const families = computed(() => familyKeys.map(value => ({ value, title: t(`blockcheck.${value}`) })))
const groupIndex = computed(() => catalog.value?.groups.findIndex(row => row.id === selected.value) ?? -1)
const group = computed(() => catalog.value?.groups[groupIndex.value])
const cellKey = (index: number, probe: string) => `${index}:${probe}`
const cells = computed(() => group.value?.targets.flatMap((target, index) => target.probes.map(probe => ({ target: index, probe }))) ?? [])
const pathBlocked = computed(() => options.value?.unavailable[mode.value] ?? (options.value && mode.value === 'OUTBOUND'
  ? outbound.value && !options.value.outbounds.includes(outbound.value) ? 'outbound_not_available'
    : resolver.value && !options.value.resolvers.includes(resolver.value) ? 'dns_transport_not_available' : undefined
  : undefined))
const zapretContext = computed(() => mode.value === 'OUTBOUND' && outbound.value && outbound.value === route.query.outbound &&
  typeof route.query.zapret === 'string' && route.query.zapret.length <= 128 ? route.query.zapret : '')
const canStart = computed(() => !loading.value && !busy.value && !pathBlocked.value && hostId.value === 'local' &&
  mode.value === 'OUTBOUND' && !!options.value?.outbounds.includes(outbound.value) && !!group.value && enabled.value.length > 0)
const visibleReport = computed(() => history.value[runIndex.value]?.report)
const runTitle = (report: Report) => `${new Date(report.startedAt).toLocaleTimeString()} · ${t(`blockcheck.${report.path.mode}`)}`
const runChoices = computed(() => history.value.map(({report}, value) => ({ value, title: runTitle(report) })))
const comparisonChoices = computed(() => runChoices.value.filter(({value}) => value !== runIndex.value && visibleReport.value && comparable(visibleReport.value, history.value[value].report)))
const comparison = computed(() => comparisonChoices.value.some(item => item.value === compareIndex.value) ? history.value[compareIndex.value!] : undefined)

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
  return [row.reason && reason(row.reason), row.dnsContext, row.dnsTransport,
    row.dnsConfiguredTransport && t('blockcheck.configuredTransport', { transport: row.dnsConfiguredTransport }),
    row.addressFamily, row.socket?.egress].filter(Boolean).join(' · ') || t('blockcheck.unknown')
}
function updateCatalog(value: Catalog, preferred = selected.value) {
  catalog.value = value
  selected.value = value.groups.find(row => row.id === preferred)?.id ?? value.groups[0]?.id ?? ''
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
    updateCatalog(value.catalog)
  } catch (err) {
    if (!request.signal.aborted) error.value = errorCode(err)
  } finally {
    if (loadController === request) loading.value = false
  }
}
function toggle(index: number, probe: string, checked: boolean) {
  const key = cellKey(index, probe)
  enabled.value = enabled.value.filter(item => item !== key)
  if (checked && enabled.value.length < 32) enabled.value.push(key)
}
function blankTarget(): Target { return { name: '', host: '', role: '', probes: ['https'] } }
function setupDraft(kind: typeof draftMode.value, group: Group) {
  draftMode.value = kind
  draftRevision.value = catalog.value?.revision ?? ''
  editError.value = ''
  draft.value = { ...group, targets: group.targets.map(row => ({ ...row, probes: [...row.probes] })) }
}
const newGroup = () => setupDraft('create', {id: '', name: '', description: '', targets: [blankTarget()]})
const editGroup = () => { if (group.value) setupDraft('edit', group.value) }
const duplicate = () => { if (group.value) setupDraft('clone', { ...group.value, name: `${group.value.name} (${t('blockcheck.clone')})` }) }
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
    return true
  } catch (err) {
    if (editing) editError.value = errorCode(err)
    else error.value = errorCode(err)
    return false
  } finally { busy.value = false }
}
async function saveDraft() {
  if (!draft.value) return
  const { id, name, description, targets } = draft.value
  const edited: Group = { id, name: name.trim(), description: description?.trim(), targets: targets.map(target => ({
    name: target.name.trim(), host: target.host.trim().toLowerCase(), role: target.role.trim(), probes: [...target.probes],
    ...(target.probes.includes('stun') ? { port: target.port } : {}),
  })) }
  const action = draftMode.value
  const fields = action === 'import' ? { transfer: { schema: transferSchema, group: edited } } : { id, group: edited }
  if (await change(action, fields, draftRevision.value, true)) draft.value = undefined
}
async function remove() { if (group.value && await change('delete', { id: group.value.id })) deleting.value = false }
async function restore() { if (restoreId.value && await change('restore', { id: restoreId.value })) restoring.value = false }
function move(offset: number) {
  const order = catalog.value?.groups.map(row => row.id)
  const previous = groupIndex.value, next = previous + offset
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
function download() {
  if (!group.value) return
  const blob = new Blob([JSON.stringify({ schema: transferSchema, group: group.value }, null, 2)], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url; link.download = `${group.value.id}.blockcheck.json`; link.click()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}
async function start() {
  if (!canStart.value || !catalog.value || !group.value || running.value) return
  const request = new AbortController()
  runController = request
  const labels = group.value.targets.map(row => row.name)
  running.value = true; notice.value = ''; error.value = ''
  try {
    const report = await run({ groupId: group.value.id, catalogRevision: catalog.value.revision,
      path: { mode: mode.value, ref: outbound.value, resolver: resolver.value ?? undefined }, family: family.value,
      cells: cells.value.filter(row => enabled.value.includes(cellKey(row.target, row.probe))) }, request.signal)
    if (!request.signal.aborted) {
      history.value = [{ report, labels }, ...history.value].slice(0, 5)
      runIndex.value = 0; compareIndex.value = null
    }
  } catch (err) {
    if (request.signal.aborted) notice.value = t('blockcheck.canceled')
    else error.value = errorCode(err)
  } finally { if (runController === request) running.value = false }
}
function cancel() { runController?.abort() }
async function copyFacts() {
  if (!visibleReport.value) return
  try {
    await navigator.clipboard.writeText(JSON.stringify(redacted(visibleReport.value), null, 2))
    notice.value = t('blockcheck.copied')
  } catch (err) { error.value = errorCode(err) }
}
watch(cells, rows => { enabled.value = rows.slice(0, 32).map(row => cellKey(row.target, row.probe)) })
watch(runIndex, () => { compareIndex.value = null })
watch(hostId, () => { cancel(); catalog.value = undefined; history.value = []; void reload() }, { immediate: true })
watch(() => route.fullPath, () => {
  const { query } = route
  mode.value = query.resolver || typeof query.outbound === 'string' ? 'OUTBOUND' : 'PANEL'
  outbound.value = typeof query.outbound === 'string' ? query.outbound : ''
  resolver.value = typeof query.resolver === 'string' ? query.resolver : null
}, { immediate: true })
onBeforeUnmount(() => { cancel(); loadController?.abort() })
</script>

<style scoped>
.blockcheck { max-width: 1240px; }
.blockcheck-controls { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(100%, 210px), 1fr)); gap: 12px; }
.blockcheck-results-controls { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(100%, 240px), 1fr)); gap: 8px 12px; }
.probe-table :deep(th), .probe-table :deep(td) { overflow-wrap: anywhere; }
.probe-choice { flex: 0 0 auto; }
.target-editor { border-top: 1px solid rgba(var(--v-border-color), var(--v-border-opacity)); }
.detail-list { display: grid; grid-template-columns: max-content minmax(0, 1fr); gap: 4px 12px; }
.detail-list dd { overflow-wrap: anywhere; }
</style>
