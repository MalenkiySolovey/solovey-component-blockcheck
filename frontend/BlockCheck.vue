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
    <section v-if="running" class="blockcheck-progress mb-3" aria-labelledby="blockcheck-progress">
      <div class="d-flex flex-wrap align-center justify-space-between ga-1">
        <h2 id="blockcheck-progress" class="text-subtitle-2">{{ progressTitle }}</h2>
        <span v-if="shownProgress" class="text-caption" role="status">{{ t('blockcheck.progress', shownProgress.progress) }}</span>
      </div>
      <v-progress-linear v-if="running" class="mt-2" :aria-label="t('blockcheck.progressLabel')"
        :indeterminate="!shownProgress" :model-value="shownProgress ? shownProgress.progress.probesDone / shownProgress.progress.totalProbes * 100 : 0" />
    </section>
    <section v-if="aggregate" class="result-overview mb-4" aria-labelledby="blockcheck-overview">
      <div class="d-flex flex-wrap align-center justify-space-between ga-2">
        <h2 id="blockcheck-overview" class="text-subtitle-1 font-weight-medium">{{ t(aggregateIndex ? 'blockcheck.previousOverview' : 'blockcheck.overview') }}</h2>
        <div class="text-caption text-medium-emphasis">{{ aggregateContext }}</div>
      </div>
      <v-select v-if="aggregateChoices.length > 1" v-model="aggregateIndex" :items="aggregateChoices" :label="t('blockcheck.aggregateHistory')"
        density="compact" hide-details class="aggregate-history mt-2" />
      <dl class="overview-counts mt-2">
        <div v-for="state in availabilityStates" :key="state" :data-availability="state">
          <dt class="text-caption">{{ availability(state) }}</dt><dd class="text-h6">{{ aggregate.counts[state] }}</dd>
        </div>
      </dl>
      <div class="d-flex flex-wrap ga-2 mt-2 text-caption text-medium-emphasis">
        <span>{{ t(`blockcheck.phase.${aggregate.phase}`) }}</span>
        <span>{{ t('blockcheck.progress', aggregate.progress) }}</span>
        <span>{{ t('blockcheck.problemCount', { count: aggregate.counts.limited + aggregate.counts.unavailable }) }}</span>
        <span>{{ t('blockcheck.elapsed', { duration: duration(aggregate.elapsed) }) }}</span>
        <span>{{ aggregateChange }}</span>
        <span v-if="aggregate.omitted">{{ t('blockcheck.historyOmitted', { count: aggregate.omitted }) }}</span>
      </div>
      <details v-if="aggregateChanges.length" :key="aggregate.id" class="aggregate-changes mt-2 text-body-2">
        <summary>{{ t('blockcheck.changedGroupDetails') }}</summary>
        <ul class="mt-1">
          <li v-for="change in aggregateChanges" :key="change.id">
            <strong>{{ groupNames.get(change.id) ?? change.id }}</strong>:
            <i18n-t keypath="blockcheck.groupTransition" scope="global">
              <template #before><span :data-availability="change.before">{{ availability(change.before) }}</span></template>
              <template #after><span :data-availability="change.after">{{ availability(change.after) }}</span></template>
            </i18n-t>
          </li>
        </ul>
      </details>
    </section>
    <v-alert v-if="historyWarning" type="warning" variant="tonal" density="compact" class="mb-2">{{ reason(historyWarning) }}</v-alert>
    <div v-if="notice" class="text-caption mb-2" role="status">{{ notice }}</div>
    <p v-if="catalog && !catalog.groups.length" class="text-body-2 text-medium-emphasis">{{ t('blockcheck.none') }}</p>
    <div v-else-if="catalog" class="blockcheck-group-grid">
      <v-card v-for="(row, index) in catalog.groups" :key="row.id" tag="article" variant="outlined" class="blockcheck-group pa-3" :data-group-id="row.id">
        <div class="d-flex justify-space-between align-start ga-2">
          <h2 class="d-flex align-center ga-2 text-subtitle-1 font-weight-medium">
            <v-icon :icon="groupIcon(row)" size="20" aria-hidden="true" /><span>{{ row.name }}</span>
          </h2>
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
          <span v-if="lastReport(row.id)" class="text-caption text-medium-emphasis" :title="runTitle(lastReport(row.id)!)">{{ cardRunTitle(lastReport(row.id)!) }}</span>
        </div>
        <template v-if="serviceCards.get(row.id)">
          <ul class="card-targets text-caption mb-2" :aria-label="t('blockcheck.targetResults')">
            <li v-for="target in serviceCards.get(row.id)!.preview" :key="target.index" class="d-flex flex-wrap align-baseline justify-space-between ga-1">
              <span>{{ target.label }}</span>
              <span class="result-state" :data-availability="target.state">{{ availability(target.state) }}</span>
            </li>
          </ul>
          <p v-if="serviceCards.get(row.id)!.hidden" class="text-caption text-medium-emphasis mb-2">
            {{ t('blockcheck.moreTargets', { count: serviceCards.get(row.id)!.hidden }) }}
          </p>
          <ul class="protocol-results d-flex flex-wrap ga-2 mb-2 text-caption" :aria-label="t('blockcheck.protocolResults')">
            <li v-for="result in serviceCards.get(row.id)!.protocols" :key="result.protocol" class="d-inline-flex align-center ga-1"
              :title="availability(result.state)">
              <v-icon :icon="availabilityIcon[result.state]" class="result-state" :data-availability="result.state" size="14" aria-hidden="true" />
              <span>{{ t('blockcheck.protocol.' + result.protocol) }}<span class="d-sr-only">: {{ availability(result.state) }}</span></span>
            </li>
          </ul>
        </template>
        <div class="d-flex flex-wrap align-center ga-2 mt-auto">
          <v-btn size="small" variant="tonal" prepend-icon="lucide:play" :disabled="!canRun || running || selectionEmpty(row.id)" @click="start(row.id)">{{ t('blockcheck.check') }}</v-btn>
          <v-btn size="small" variant="text" :append-icon="expanded && selected === row.id ? 'lucide:chevron-up' : 'lucide:chevron-down'"
            :aria-expanded="expanded && selected === row.id" @click="showGroup(row)">{{ t('blockcheck.groupDetails') }}</v-btn>
        </div>
      </v-card>
    </div>
    <h2 v-if="expanded && group" id="blockcheck-group-details" tabindex="-1" class="text-h6 mt-5 mb-2">{{ group.name }}</h2>
    <details v-if="expanded && group" :key="group.id" :open="!visibleReport" class="blockcheck-scope">
      <summary>{{ t('blockcheck.probeSelection') }}</summary>
      <v-table class="probe-table" density="compact">
      <thead><tr><th scope="col">{{ t('blockcheck.target') }}</th><th scope="col">{{ t('blockcheck.role') }}</th><th scope="col">{{ t('blockcheck.probes') }}</th></tr></thead>
      <tbody>
        <tr v-for="(target, index) in group.targets" :key="index">
          <th scope="row" class="text-start"><div>{{ target.name }}</div><div class="text-caption text-medium-emphasis">{{ targetEndpoint(target) }}</div></th>
          <td>{{ target.role }}</td>
          <td><div class="d-flex flex-wrap ga-2 py-1">
            <v-checkbox-btn v-for="probe in target.probes" :key="probe" :label="probeLabel(probe)" class="probe-choice" density="compact"
              :aria-label="`${target.name}: ${probeLabel(probe)}`" :model-value="enabled.has(cellKey(index, probe))"
              :disabled="running" @update:model-value="toggle(index, probe, $event === true)" />
          </div></td>
        </tr>
      </tbody>
      </v-table>
    </details>

    <section v-if="expanded && visibleReport" class="mt-6" aria-labelledby="blockcheck-results">
      <div class="d-flex align-center justify-space-between flex-wrap ga-2 mb-3">
        <h2 id="blockcheck-results" class="text-h6">{{ t('blockcheck.result') }}</h2>
        <v-btn variant="text" prepend-icon="mdi-content-copy" @click="copyFacts">{{ t('blockcheck.exportFacts') }}</v-btn>
      </div>
      <div class="blockcheck-results-controls mb-3">
        <v-select v-model="runIndex" :items="runChoices" :label="t(options?.history ? 'blockcheck.history' : 'blockcheck.sessionHistory')" density="compact" hide-details />
        <v-select v-if="comparisonChoices.length" v-model="compareIndex" :items="comparisonChoices" :label="t('blockcheck.compare')" density="compact" hide-details clearable />
      </div>
      <div v-if="previousGroupChange" class="text-caption text-medium-emphasis mb-2">{{ previousGroupChange }}</div>
      <div class="text-caption text-medium-emphasis mb-2">{{ t('blockcheck.factsHint') }}</div>
      <details class="mb-2">
        <summary>{{ t('blockcheck.details') }}</summary>
        <dl class="detail-list mt-2">
          <dt>{{ t('blockcheck.path') }}</dt><dd>{{ pathTitle(visibleReport) }} · {{ visibleReport.pathEvidence?.scope ?? t('blockcheck.unknown') }}</dd>
          <dt>{{ t('blockcheck.observed') }}</dt><dd>{{ visibleReport.pathEvidence?.context ?? t('blockcheck.unknown') }}</dd>
          <dt>{{ t('blockcheck.revision') }}</dt><dd>{{ visibleReport.pathEvidence?.generation ?? t('blockcheck.unknown') }}</dd>
          <dt>{{ t('blockcheck.family') }}</dt><dd>{{ t('blockcheck.' + visibleReport.family) }}</dd>
          <template v-if="reportDuration(visibleReport)"><dt>{{ t('blockcheck.duration') }}</dt><dd>{{ reportDuration(visibleReport) }}</dd></template>
        </dl>
      </details>
      <ul v-if="visibleReport.findings?.length" class="finding-list mb-3">
        <li v-for="finding in visibleReport.findings" :key="`${finding.target}:${finding.code}`">
          <strong>{{ targetLabel(finding.target) }}</strong> · {{ findingText(finding) }}
          <div class="text-caption text-medium-emphasis">{{ findingDetails(finding) }}</div>
        </li>
      </ul>
      <h3 class="text-subtitle-2 mt-4 mb-2">{{ t('blockcheck.targetResults') }}</h3>
      <details v-for="target in visibleTargets" :key="visibleReport.job.jobId + ':' + target.index" class="target-result" :open="target.index === 0 || target.state === 'unavailable' || target.state === 'limited'">
        <summary>
          <span class="font-weight-medium">{{ target.meta.name }}</span>
          <span v-if="target.endpoint && target.endpoint !== target.meta.name" class="text-caption text-medium-emphasis">{{ target.endpoint }}</span>
          <span v-if="target.meta.role && target.meta.role !== target.meta.name" class="text-caption text-medium-emphasis">{{ target.meta.role }}</span>
          <span class="result-state text-caption" :data-availability="target.state">{{ availability(target.state) }}</span>
        </summary>
        <section v-for="attempt in target.addresses" :key="attempt.address ?? ''" class="attempt-scope mb-3">
          <h4 class="d-flex align-center ga-2 text-body-2 font-weight-medium">
            <v-icon :icon="attempt.address ? 'lucide:network' : 'lucide:info'" size="16" aria-hidden="true" />
            {{ attempt.address ? t('blockcheck.attemptedAddress', { address: attempt.address }) : t('blockcheck.noRecordedAddress') }}
          </h4>
          <ol v-if="attempt.stages.length" class="connection-stages my-2" :aria-label="t('blockcheck.connectionStages')">
            <li v-for="step in attempt.stages" :key="step.stage" :data-stage="step.stage" :data-availability="step.state">
              <v-icon :icon="availabilityIcon[step.state]" size="16" aria-hidden="true" />
              <strong class="text-caption">{{ t('blockcheck.stage.' + step.stage) }}</strong>
              <span class="text-caption">{{ step.observed ? availability(step.state) : t('blockcheck.unknown') }}</span>
            </li>
          </ol>
          <ul class="list-unstyled probe-evidence" :aria-label="t('blockcheck.observed')">
            <li v-for="row in attempt.rows" :key="row.probe" class="py-2">
              <div class="d-flex flex-wrap align-baseline ga-2">
                <strong>{{ probeLabel(row.probe) }}</strong>
                <span class="result-state" :data-availability="probeAvailability(row)">{{ observation(row) }}</span>
                <span class="text-caption text-medium-emphasis">{{ duration(row.elapsedMs) }}</span>
              </div>
              <div class="text-caption text-medium-emphasis">{{ rowFacts(row, false) }}</div>
              <div v-if="row.interpretation" class="mt-1 text-caption">
                <strong>{{ findingText(row.interpretation) }}</strong><div>{{ findingDetails(row.interpretation) }}</div>
              </div>
              <template v-if="comparedRows.get(cellKey(row.target, row.probe))">
                <div class="text-caption mt-1">{{ t('blockcheck.compactComparison', { path: pathTitle(comparison!.report), result: observation(comparedRows.get(cellKey(row.target, row.probe))!.row), duration: duration(comparedRows.get(cellKey(row.target, row.probe))!.row.elapsedMs) }) }}</div>
                <div class="text-caption text-medium-emphasis">{{ rowFacts(comparedRows.get(cellKey(row.target, row.probe))!.row) }}</div>
                <details v-if="comparedRows.get(cellKey(row.target, row.probe))!.dns" class="mt-1 text-caption">
                  <summary>{{ t('blockcheck.dnsDifference.' + comparedRows.get(cellKey(row.target, row.probe))!.dns) }}</summary>
                  <div>{{ t('blockcheck.dnsDifferenceEvidence') }}</div>
                  <div v-for="path in comparedRows.get(cellKey(row.target, row.probe))!.authenticated" :key="path.key">
                    {{ t('blockcheck.dnsCertificateEvidence', { path: path.label }) }}
                  </div>
                </details>
              </template>
            </li>
          </ul>
        </section>
        <p v-if="!target.addresses.length" class="text-caption text-medium-emphasis mb-2">{{ t('blockcheck.unknown') }}</p>
      </details>
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
              <v-select v-model="target.probes" :items="(catalog?.probes ?? []).map(value => ({ value, title: probeLabel(value) }))"
                :label="t('blockcheck.probes')" multiple density="compact" />
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
import { cancelSuite, load, loadHistory, openTransfer, redacted, save, streamSuite, transferSchema, type Catalog, type Depth, type Family, type Finding, type Group, type GroupFinding, type HistoryEntry, type HistoryRun, type Mode, type Options, type Report, type Row, type SuiteEvent, type SuiteProgress, type Target } from './api'
import { authenticatesDNSSet, comparable, dnsDifference } from './comparison'
import { addressResults, availabilityColor, availabilityStates, cardTargetLabel, compareAggregates, groupAvailability, probeAvailability, protocolResults, reportContext, targetEndpoint, targetResults, type Availability } from './serviceResults'

const { t, te, locale } = useI18n()
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
type AggregateRun = { id: string; groups: Map<string, HistoryEntry | undefined>; path: Report['path']; family: Family; depth: Depth;
  startedAt: string; elapsed: number; phase: string; progress: SuiteProgress; omitted?: number }
const history = ref(new Map<string, HistoryEntry[]>())
const historyWarning = ref('')
const currentBatches = ref(new Map<string, Row[]>())
const shownProgress = ref<SuiteEvent>()
const aggregateRuns = ref<AggregateRun[]>([])
const aggregateIndex = ref(0)
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
const progressTitle = computed(() => stopping.value ? t('blockcheck.stopping') : t(`blockcheck.phase.${shownProgress.value?.job.phase ?? 'RUNNING'}`))
const groupHistory = computed(() => history.value.get(selected.value) ?? [])
const lastReport = (id: string) => history.value.get(id)?.[0]?.report
const visibleEntry = computed(() => groupHistory.value[runIndex.value])
const visibleReport = computed(() => visibleEntry.value?.report)
const pathLabel = (path: Report['path']) => [t(`blockcheck.${path.mode}`), path.ref,
  path.resolver && t('blockcheck.comparisonResolver', { resolver: path.resolver })].filter(Boolean).join(' · ')
const pathTitle = (report: Report) => pathLabel(report.path)
const runDate = (value: string) => new Date(value).toLocaleString(locale.value, { dateStyle: 'short', timeStyle: 'short' })
const cardRunTitle = (report: Report) => [runDate(report.startedAt), report.path.ref ?? t(`blockcheck.${report.path.mode}`)].join(' · ')
const runTitle = (report: Report) => [runDate(report.startedAt), pathTitle(report),
  report.job.phase !== 'COMPLETED' && t(`blockcheck.phase.${report.job.phase}`)].filter(Boolean).join(' · ')
const runChoices = computed(() => groupHistory.value.map(({report}, value) => ({ value, title: runTitle(report) })))
const comparisonChoices = computed(() => runChoices.value.filter(({value}) => value !== runIndex.value && visibleReport.value && (
  comparable(visibleReport.value, groupHistory.value[value].report) || reportContext(visibleReport.value, groupHistory.value[value].report) !== 'different')))
const comparison = computed(() => comparisonChoices.value.some(item => item.value === compareIndex.value) ? groupHistory.value[compareIndex.value!] : undefined)
const comparedRows = computed(() => {
  const other = comparison.value?.report
  const current = visibleReport.value
  return new Map(other && current ? current.results.map((row, index) => {
    const compared = other.results[index]
    const dns = dnsDifference(row, compared)
    const authenticated = !dns ? [] : [{ key: 'current', row, report: current }, { key: 'compared', row: compared, report: other }]
      .filter(entry => authenticatesDNSSet(entry.row, entry.report))
      .map(entry => ({ key: entry.key, label: runTitle(entry.report) }))
    return [cellKey(row.target, row.probe), { row: compared, dns, authenticated }] as const
  }) : [])
})

const availability = (state: Availability) => t(`blockcheck.availability.${state}`)
const availabilityIcon: Record<Availability, string> = { available: 'lucide:check', limited: 'lucide:alert-triangle', unavailable: 'lucide:x-circle', unconfirmed: 'lucide:info' }
const groupIcons: Record<string, string> = { youtube: 'lucide:play', discord: 'lucide:message-square', telegram: 'lucide:send',
  instagram: 'lucide:eye', facebook: 'lucide:users', x: 'lucide:message-square', whatsapp: 'lucide:message-square', spotify: 'lucide:activity',
  chatgpt: 'lucide:message-square', rutracker: 'lucide:download', twitch: 'lucide:play', linkedin: 'lucide:users',
  'web-controls': 'lucide:shield-check', 'dns-extras': 'lucide:network', 'stun-controls': 'lucide:activity', 'icmp-controls': 'lucide:gauge' }
const groupIcon = (row: Group) => groupIcons[row.origin?.template ?? ''] ?? 'lucide:globe'
const groupNames = computed(() => new Map(catalog.value?.groups.map(row => [row.id, row.name])))
const serviceCards = computed(() => new Map((catalog.value?.groups ?? []).flatMap(row => {
  const batch = currentBatches.value.get(row.id), entry = history.value.get(row.id)?.[0]
  const rows = batch ?? entry?.report.results
  if (!rows) return []
  const meta = (batch ? row.targets : entry?.targets) ?? row.targets
  const targets = targetResults(meta.length, rows)
  const priority: Record<Availability, number> = { unavailable: 0, limited: 1, unconfirmed: 2, available: 3 }
  const preview = targets.slice().sort((a, b) => priority[a.state] - priority[b.state]).slice(0, 3).map(target => ({
    ...target, label: cardTargetLabel(meta[target.index]),
  }))
  return [[row.id, { preview, protocols: protocolResults(rows), hidden: targets.length - preview.length }] as const]
})))
const visibleTargets = computed(() => {
  const entry = visibleEntry.value
  return entry ? targetResults(entry.targets.length, entry.report.results).map(target => ({
    ...target, meta: entry.targets[target.index], endpoint: targetEndpoint(entry.targets[target.index]), addresses: addressResults(target.rows),
  })) : []
})
const aggregate = computed(() => {
  const run = aggregateRuns.value[aggregateIndex.value]
  if (!run) return
  const counts: Record<Availability, number> = { available: 0, limited: 0, unavailable: 0, unconfirmed: 0 }
  for (const entry of run.groups.values()) counts[groupAvailability(entry)]++
  return { ...run, counts }
})
const aggregateChoices = computed(() => aggregateRuns.value.map((run, value) => ({value, title: [runDate(run.startedAt), pathLabel(run.path)].join(' · ')})))
const aggregateContext = computed(() => {
  const run = aggregate.value
  return run ? [runDate(run.startedAt), hostId.value === 'local' ? t('blockcheck.local') : hostId.value, pathLabel(run.path),
    t('blockcheck.' + run.family), t('blockcheck.' + run.depth)].join(' · ') : ''
})
const aggregateComparison = computed(() => compareAggregates(aggregateRuns.value[aggregateIndex.value], aggregateRuns.value[aggregateIndex.value + 1]))
const aggregateChanges = computed(() => aggregateComparison.value.kind === 'comparable' ? aggregateComparison.value.changes : [])
const aggregateChange = computed(() => {
  const result = aggregateComparison.value
  if (result.kind !== 'comparable') return t(`blockcheck.${result.kind}`)
  const changed = result.changes.length
  return comparisonText(changed ? t('blockcheck.changedGroups', { count: changed }) : t('blockcheck.noChanges'), result.unobservedPath)
})
const previousGroupChange = computed(() => {
  const entry = visibleEntry.value, prior = groupHistory.value[runIndex.value + 1]
  if (!entry) return ''
  if (!prior) return t('blockcheck.noPrevious')
  const scope = reportContext(entry.report, prior.report)
  if (scope === 'different') return t('blockcheck.differentContext')
  const changes = entry.report.results.filter((row, index) => probeAvailability(row) !== probeAvailability(prior.report.results[index])).length
  return comparisonText(changes ? t('blockcheck.changedProbes', { count: changes }) : t('blockcheck.noChanges'), scope === 'configured')
})
const comparisonText = (message: string, unobservedPath: boolean) => unobservedPath ? `${message} · ${t('blockcheck.pathNotConfirmed')}` : message

function groupSummary(id: string) {
  const active = shownProgress.value?.group
  if (running.value && shownProgress.value?.kind === 'progress' && active?.id === id) {
    return { label: t('blockcheck.groupProgress', active), color: 'info' }
  }
  const report = lastReport(id)
  if (!report) return { label: t('blockcheck.notRun'), color: undefined }
  const state = groupAvailability(history.value.get(id)?.[0])
  return { label: availability(state), color: availabilityColor[state] }
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
function duration(ms: number) {
  return ms < 1000 ? t('blockcheck.milliseconds', { ms }) : t('blockcheck.seconds', { seconds: new Intl.NumberFormat(locale.value, { maximumFractionDigits: 1 }).format(ms / 1000) })
}
function reportDuration(report: Report) {
  const elapsed = Date.parse(report.finishedAt ?? '') - Date.parse(report.startedAt)
  return Number.isFinite(elapsed) && elapsed >= 0 ? duration(elapsed) : undefined
}
const probeLabel = (probe: string) => te('blockcheck.probe.' + probe) ? t('blockcheck.probe.' + probe) : probe.toUpperCase()
function rowFacts(row: Row, includeAddress = true) {
  return [row.stage && t(`blockcheck.stage.${row.stage}`), row.reason && reason(row.reason), row.dnsContext, row.dnsTransport,
    row.dnsConfiguredTransport && t('blockcheck.configuredTransport', { transport: row.dnsConfiguredTransport }),
    includeAddress && row.attemptedAddress && t('blockcheck.attemptedAddress', { address: row.attemptedAddress }),
    row.addressFamily && t('blockcheck.' + row.addressFamily), row.tlsVersion, row.tlsVerified && t('blockcheck.verifiedCertificate'),
    row.tlsProfile === 'chrome-133' && t('blockcheck.tlsProfile.chrome-133'), row.httpProtocol,
    row.httpResponseStartMs !== undefined && t('blockcheck.httpResponseStart', { duration: duration(row.httpResponseStartMs) }),
    row.stage === 'transfer' && t('blockcheck.transferSample', {
      bytes: row.bodyBytes ?? 0, expected: row.bodyExpected ?? t('blockcheck.unknownLength'), ms: row.bodyReadMs ?? 0,
    }), row.socket?.egress, row.socket?.interface].filter(Boolean).join(' · ') || t('blockcheck.unknown')
}
const targetLabel = (index: number) => {
  const target = visibleEntry.value?.targets[index]
  return target ? [target.name, target.port && targetEndpoint(target)].filter(Boolean).join(' · ') : `#${index + 1}`
}
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
function newest<T>(items: T[], identity: (item: T) => string, startedAt: (item: T) => string): T[] {
  return [...new Map(items.map(item => [identity(item), item])).values()].sort((a, b) => Date.parse(startedAt(b)) - Date.parse(startedAt(a)))
}
function restoreHistory(runs: HistoryRun[]) {
  const known = new Set(catalog.value?.groups.map(row => row.id))
  const reported = new Map<string, HistoryEntry[]>()
  const aggregates: AggregateRun[] = []
  for (const run of runs) {
    const groups = new Map<string, HistoryEntry | undefined>((run.groupIds ?? []).map(id => [id, undefined]))
    for (const entry of run.groups) {
      const id = entry.report.groupId
      groups.set(id, entry)
      if (!known.has(id)) continue
      const entries = reported.get(id) ?? []
      entries.push(entry)
      reported.set(id, entries)
    }
    const elapsed = Date.parse(run.finishedAt) - Date.parse(run.startedAt)
    if (run.all && elapsed >= 0) aggregates.push({ ...run, groups, elapsed })
  }
  for (const [id, entries] of reported) {
    history.value.set(id, newest([...entries, ...(history.value.get(id) ?? [])], item => item.report.job.jobId, item => item.report.startedAt).slice(0, 8))
  }
  aggregateRuns.value = newest([...aggregates, ...aggregateRuns.value], item => item.id, item => item.startedAt).slice(0, 8)
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
    if (value.options.history) {
      try {
        const runs = await loadHistory(request.signal)
        if (!request.signal.aborted) { restoreHistory(runs); historyWarning.value = '' }
      } catch {
        if (!request.signal.aborted) historyWarning.value = 'blockcheck_history_unavailable'
      }
    }
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
    document.getElementById('blockcheck-group-details')?.focus()
  }
}
async function start(groupId?: string) {
  if (!canRun.value || !catalog.value || running.value || (!groupId && !activeGroups.value) || (groupId && selectionEmpty(groupId))) return
  const request = new AbortController()
  runController = request
  const groups = groupId ? catalog.value.groups.filter(row => row.id === groupId) : catalog.value.groups.filter(row => !row.disabled)
  const targets = new Map(groups.map(row => [row.id, row.targets.map(({ name, host, role, port }) => ({ name, host, role, port }))]))
  const results = new Map<string, HistoryEntry | undefined>(groups.map(row => [row.id, undefined]))
  const path = { mode: mode.value, ref: pathRef.value, resolver: mode.value === 'OUTBOUND' ? resolver.value ?? undefined : undefined }
  const selectedFamily = family.value, selectedDepth = depth.value
  const startedAt = new Date().toISOString(), started = performance.now()
  const partial = new Map<string, Row[]>()
  const findings = new Map<string, GroupFinding[]>()
  const selection = groupId === selected.value && expanded.value && enabled.value.size !== cells.value.length
    ? cells.value.filter(row => enabled.value.has(cellKey(row.target, row.probe))) : undefined
  running.value = true; stopping.value = false; shownProgress.value = undefined; currentBatches.value.clear(); notice.value = ''; error.value = ''
  let terminal: SuiteEvent | undefined
  try {
    await streamSuite({ groupId, all: !groupId, catalogRevision: catalog.value.revision, path,
      family: selectedFamily, depth: selectedDepth, cells: selection }, request.signal, event => {
      if (runController !== request || request.signal.aborted) return
      const id = event.group?.id
      // Drop batch payloads from the last-event slot; rows live with their group.
      shownProgress.value = { ...event, rows: undefined, findings: undefined, report: undefined }
      if (id && event.rows) {
        const rows = partial.get(id) ?? reactiveRows(id)
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
        const entry = { report, targets: targets.get(id) ?? [] }
        results.set(id, entry)
        history.value.set(id, [entry, ...(history.value.get(id) ?? [])].slice(0, 8))
        currentBatches.value.delete(id)
        partial.delete(id)
        findings.delete(id)
        if (id === selected.value) { runIndex.value = 0; compareIndex.value = null }
      }
      if (event.kind === 'finished') terminal = event
    })
    if (!request.signal.aborted && terminal) {
      if (terminal.historySaved !== undefined) historyWarning.value = terminal.historySaved ? '' : 'blockcheck_history_not_saved'
      if (!groupId) {
        const measured = Date.parse(terminal.finishedAt ?? '') - Date.parse(terminal.startedAt ?? '')
        const entry: AggregateRun = { id: terminal.job.operationId, groups: results, path, family: selectedFamily, depth: selectedDepth,
          elapsed: measured >= 0 ? measured : Math.round(performance.now() - started), phase: terminal.job.phase, progress: terminal.progress,
          startedAt: terminal.startedAt ?? startedAt }
        aggregateRuns.value = [entry, ...aggregateRuns.value].slice(0, 8)
        aggregateIndex.value = 0
      }
      if (terminal.job.phase === 'CANCELED') notice.value = t('blockcheck.canceled')
      else if (terminal.job.problem) error.value = terminal.job.problem.code
    }
  } catch (err) {
    if (runController === request && !request.signal.aborted) error.value = errorCode(err)
  } finally {
    if (runController === request) { running.value = false; stopping.value = false; shownProgress.value = undefined; currentBatches.value.clear() }
  }
}
function reactiveRows(id: string): Row[] {
  currentBatches.value.set(id, [])
  return currentBatches.value.get(id)!
}
async function cancel() {
  const request = runController, job = shownProgress.value?.job
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
  catalog.value = undefined; options.value = undefined; history.value.clear(); shownProgress.value = undefined
  currentBatches.value.clear(); aggregateRuns.value = []; aggregateIndex.value = 0; historyWarning.value = ''
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
.blockcheck-controls { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(100%, 150px), 1fr)); gap: 10px; }
.blockcheck-results-controls { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(100%, 240px), 1fr)); gap: 8px 12px; }
.blockcheck-group-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(100%, 260px), 1fr)); gap: 10px; }
.blockcheck-group { display: flex; flex-direction: column; border-radius: 8px; overflow-wrap: anywhere; border-color: rgba(var(--v-border-color), var(--v-border-opacity)); }
.blockcheck-group h2 { margin: 0; font-size: 1rem; line-height: 1.4; letter-spacing: 0; }
.blockcheck-group h2 :deep(.v-icon) { flex-shrink: 0; }
.blockcheck-progress { border-block: 1px solid rgba(var(--v-border-color), var(--v-border-opacity)); padding-block: 8px; }
.blockcheck-scope > summary { cursor: pointer; padding-block: 6px; }
.result-overview { padding-block: 12px; border-bottom: 1px solid rgba(var(--v-border-color), var(--v-border-opacity)); }
.aggregate-history { width: min(100%, 480px); }
.overview-counts { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(100%, 132px), 1fr)); gap: 8px; }
.overview-counts > div { min-width: 0; border-inline-start: 2px solid var(--result-accent, currentColor); padding-inline-start: 8px; overflow-wrap: anywhere; }
.overview-counts dd { margin: 0; }
.aggregate-changes { overflow-wrap: anywhere; }
.aggregate-changes summary { cursor: pointer; }
.aggregate-changes ul { padding-inline-start: 1.25rem; }
[data-availability="available"] { --result-accent: rgb(var(--v-theme-success)); }
[data-availability="limited"] { --result-accent: rgb(var(--v-theme-warning)); }
[data-availability="unavailable"] { --result-accent: rgb(var(--v-theme-error)); }
[data-availability] { color: color-mix(in srgb, var(--result-accent, rgb(var(--v-theme-on-surface))) 57%, rgb(var(--v-theme-on-surface))); }
[data-availability="unconfirmed"] { color: rgba(var(--v-theme-on-surface), var(--v-medium-emphasis-opacity)); }
.card-targets, .protocol-results, .probe-evidence, .connection-stages { list-style: none; padding: 0; }
.card-targets li, .probe-evidence li { border-top: 1px solid rgba(var(--v-border-color), var(--v-border-opacity)); }
.card-targets li { padding-block: 3px; }
.protocol-results li { min-width: 0; }
.target-result { border-block-start: 1px solid rgba(var(--v-border-color), var(--v-border-opacity)); overflow-wrap: anywhere; }
.target-result > summary { cursor: pointer; padding-block: 10px; }
.target-result > summary > span { display: inline-block; margin-inline-end: 8px; max-inline-size: 100%; }
.attempt-scope + .attempt-scope { border-block-start: 1px solid rgba(var(--v-border-color), var(--v-border-opacity)); padding-block-start: 12px; }
.connection-stages { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(100%, 118px), 1fr)); gap: 6px 10px; }
.connection-stages li { display: grid; gap: 3px; justify-items: start; border-inline-start: 2px solid var(--result-accent, currentColor); padding-inline-start: 8px; }
.probe-table :deep(th), .probe-table :deep(td) { overflow-wrap: anywhere; }
.probe-choice { flex: 0 0 auto; }
.target-editor { border-top: 1px solid rgba(var(--v-border-color), var(--v-border-opacity)); }
.detail-list { display: grid; grid-template-columns: max-content minmax(0, 1fr); gap: 4px 12px; }
.detail-list dd { overflow-wrap: anywhere; }
.finding-list { padding-inline-start: 1.25rem; overflow-wrap: anywhere; }
</style>
