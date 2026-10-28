import {
    useCallback,
    useEffect,
    useMemo,
    useState,
    type FormEvent,
} from "react";

import { CopyButton } from "../components/copy-button";
import { ShadowWorkbench } from "../components/shadow-workbench";
import {ShadowHistory} from '../components/shadow-history';
import {SigmaImport} from '../components/sigma-import';
import type {SigmaPreview} from '../api/sigma-contract';
import { SeverityBadge } from "../components/severity-badge";
import { StatePanel } from "../components/state-panel";
import { TimeValue } from "../components/time-value";
import type { BackendApi } from "../types/api";
import type {
    AdvancedAvailabilityStatus,
    AdvancedDetectionRule,
    AdvancedRuleDryRunResult,
    DetectionAnalytics,
    DetectionCoverage,
    DetectionQualityReport,
    RuleConditionField,
    RuleConditionOperator,
    RuleDraft,
    RuleDraftCreate,
    RuleDraftVersion,
    RuleDryRunResult,
} from "../types/detection-engineering";
import type { DetectionRuleSummary } from "../types/siem";
import type {
    CanarySafetyStatus,
    DetectionConfigurationVersion,
    DetectionDiagnostics,
    DetectionRuleLifecycle,
    DetectionTuningComparison,
    ShadowRun,
    TelemetryPrerequisiteEvidence,
} from "../types/detection-readiness";
import { humanize } from "../utils/format";

type Tab = "inventory" | "advanced" | "coverage" | "analytics" | "drafts" | "shadow-v2" | "shadow-history" | "sigma";
type AdvancedView =
    | "overview"
    | "configuration"
    | "test"
    | "shadow"
    | "tuning"
    | "quality"
    | "readiness"
    | "diagnostics";
const EMPTY_DRAFT: RuleDraftCreate = {
    name: "",
    description: "",
    severity: 8,
    source_type: "network",
    mitre_ids: [],
    documentation: "",
    conditions: [{ field: "rule_id", operator: "EQUALS", value: "" }],
    change_summary: "Initial draft",
};
function failure(reason: unknown): string {
    return reason instanceof Error
        ? reason.message
        : "Detection engineering operation failed.";
}
function mitreUrl(id: string): string {
    return `https://attack.mitre.org/techniques/${id.replace(".", "/")}/`;
}

export function DetectionEngineeringPage({
    api,
    canMutate,
    onOpenAlerts,
    onOpenEvent,
    onInvestigateFinding = () => undefined,
    onInvestigateDurable,
    initialRuleId,
}: {
    api: BackendApi;
    canMutate: boolean;
    onOpenAlerts(ruleId: string): void;
    onOpenEvent(eventId: string): void;
    onInvestigateFinding?(ruleId: string, findingKey: string, startTime: string, endTime: string): void;
    onInvestigateDurable?(target: import('../types/investigation-workbench').WorkbenchTarget): void;
    initialRuleId?: string | null;
}) {
    const [tab, setTab] = useState<Tab>("inventory");
    const [importedRules,setImportedRules]=useState<SigmaPreview['rules']>([]);
    const [rules, setRules] = useState<DetectionRuleSummary[] | null>(null);
    const [advancedRules, setAdvancedRules] = useState<AdvancedDetectionRule[]>([]);
    const [coverage, setCoverage] = useState<DetectionCoverage | null>(null);
    const [analytics, setAnalytics] = useState<DetectionAnalytics | null>(null);
    const [drafts, setDrafts] = useState<RuleDraft[]>([]);
    const [selectedRule, setSelectedRule] =
        useState<DetectionRuleSummary | null>(null);
    const [selectedAdvancedRule, setSelectedAdvancedRule] =
        useState<AdvancedDetectionRule | null>(null);
    const [advancedDryRun, setAdvancedDryRun] =
        useState<AdvancedRuleDryRunResult | null>(null);
    const [advancedView, setAdvancedView] = useState<AdvancedView>("overview");
    const [lifecycle, setLifecycle] = useState<DetectionRuleLifecycle | null>(null);
    const [configurations, setConfigurations] = useState<DetectionConfigurationVersion[]>([]);
    const [telemetryReadiness, setTelemetryReadiness] =
        useState<TelemetryPrerequisiteEvidence | null>(null);
    const [detectionDiagnostics, setDetectionDiagnostics] =
        useState<DetectionDiagnostics | null>(null);
    const [detectionQuality, setDetectionQuality] =
        useState<DetectionQualityReport | null>(null);
    const [shadowRuns, setShadowRuns] = useState<ShadowRun[]>([]);
    const [tuningComparison, setTuningComparison] =
        useState<DetectionTuningComparison | null>(null);
    const [canarySafety, setCanarySafety] = useState<CanarySafetyStatus | null>(null);
    const [revision, setRevision] = useState(0);
    const [selectedDraft, setSelectedDraft] = useState<RuleDraft | null>(null);
    const [versions, setVersions] = useState<RuleDraftVersion[]>([]);
    const [dryRun, setDryRun] = useState<RuleDryRunResult | null>(null);
    const [form, setForm] = useState<RuleDraftCreate>(EMPTY_DRAFT);
    const [mitreText, setMitreText] = useState("");
    const [deploymentConfirmed, setDeploymentConfirmed] = useState(false);
    const [deploymentReason, setDeploymentReason] = useState("");
    const [search, setSearch] = useState("");

    useEffect(() => {
        if (!initialRuleId || advancedRules.length === 0) return;
        const match = advancedRules.find((rule) => rule.rule_id === initialRuleId);
        if (match) { setTab("advanced"); setSelectedAdvancedRule(match); }
    }, [advancedRules, initialRuleId]);
    useEffect(() => {
        if (!selectedAdvancedRule) {
            setLifecycle(null);
            setConfigurations([]);
            setTelemetryReadiness(null);
            setDetectionDiagnostics(null);
            setDetectionQuality(null);
            setShadowRuns([]);
            setTuningComparison(null);
            setCanarySafety(null);
            return;
        }
        const controller = new AbortController();
        const ruleId = selectedAdvancedRule.rule_id;
        void Promise.all([
            api.getDetectionLifecycle(ruleId, controller.signal),
            api.listDetectionConfigurations(ruleId, controller.signal),
            api.getDetectionTelemetry(ruleId, controller.signal),
            api.getDetectionDiagnostics(ruleId, controller.signal),
            api.listShadowRuns(ruleId, controller.signal),
            api.getCanarySafety(ruleId, controller.signal),
        ]).then(([nextLifecycle, nextConfigurations, nextTelemetry, nextDiagnostics, nextRuns, nextCanary]) => {
            setLifecycle(nextLifecycle);
            setConfigurations(nextConfigurations);
            setTelemetryReadiness(nextTelemetry);
            setDetectionDiagnostics(nextDiagnostics);
            setShadowRuns(nextRuns);
            setCanarySafety(nextCanary);
        }).catch((reason: unknown) => {
            if (!(reason instanceof DOMException && reason.name === "AbortError"))
                setError(failure(reason));
        });
        return () => controller.abort();
    }, [api, selectedAdvancedRule, revision]);
    useEffect(() => {
        if (!selectedAdvancedRule) return;
        const controller = new AbortController();
        setDetectionQuality(null);
        void api.getDetectionQuality(selectedAdvancedRule.rule_id, controller.signal)
            .then(setDetectionQuality)
            .catch((reason: unknown) => {
                if (!(reason instanceof DOMException && reason.name === "AbortError"))
                    setDetectionQuality(null);
            });
        return () => controller.abort();
    }, [api, selectedAdvancedRule]);
    const [advancedSearch, setAdvancedSearch] = useState("");
    const [advancedStatus, setAdvancedStatus] = useState<AdvancedAvailabilityStatus | "ALL">("ALL");
    const [advancedSource, setAdvancedSource] = useState("ALL");
    const [rulePage, setRulePage] = useState(0);
    const [loading, setLoading] = useState(true);
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [message, setMessage] = useState<string | null>(null);

    const load = useCallback(async () => {
        setLoading(true);
        setError(null);
        try {
            const [nextRules, nextAdvancedRules, nextCoverage, nextAnalytics, nextDrafts] =
                await Promise.all([
                    api.listRules(),
                    api.listAdvancedDetectionRules(30),
                    api.getDetectionCoverage(),
                    api.getDetectionAnalytics(30),
                    api.listRuleDrafts(),
                ]);
            setRules(nextRules);
            setAdvancedRules(nextAdvancedRules);
            setCoverage(nextCoverage);
            setAnalytics(nextAnalytics);
            setDrafts(nextDrafts);
            setSelectedDraft((current) =>
                current
                    ? (nextDrafts.find(
                          (item) => item.draft_id === current.draft_id,
                      ) ?? null)
                    : null,
            );
        } catch (reason) {
            setError(failure(reason));
        } finally {
            setLoading(false);
        }
    }, [api]);
    useEffect(() => {
        void load();
    }, [load, revision]);
    useEffect(() => {
        const close = () => setSelectedRule(null);
        window.addEventListener("cyberqalqon:escape", close);
        return () => window.removeEventListener("cyberqalqon:escape", close);
    }, []);

    const filteredRules = useMemo(
        () =>
            (rules ?? []).filter((rule) => {
                const query = search.trim().toLowerCase();
                return (
                    !query ||
                    `${rule.rule_id} ${rule.name} ${rule.description} ${rule.mitre_ids.join(" ")}`
                        .toLowerCase()
                        .includes(query)
                );
            }),
        [rules, search],
    );
    const visibleRules = filteredRules.slice(rulePage * 25, rulePage * 25 + 25);
    const advancedSources = useMemo(
        () => Array.from(new Set(advancedRules.flatMap((rule) => rule.prerequisites.source_types))).sort(),
        [advancedRules],
    );
    const filteredAdvancedRules = useMemo(
        () => advancedRules.filter((rule) => {
            const query = advancedSearch.trim().toLowerCase();
            const matchesSearch = !query ||
                `${rule.rule_id} ${rule.name} ${rule.description} ${rule.mitre_ids.join(" ")} ${rule.prerequisites.event_codes.join(" ")}`
                    .toLowerCase().includes(query);
            const matchesStatus = advancedStatus === "ALL" || rule.availability?.status === advancedStatus;
            const matchesSource = advancedSource === "ALL" || rule.prerequisites.source_types.includes(advancedSource);
            return matchesSearch && matchesStatus && matchesSource;
        }),
        [advancedRules, advancedSearch, advancedStatus, advancedSource],
    );

    const runAdvancedDryRun = async (rule: AdvancedDetectionRule) => {
        setBusy(true);
        setError(null);
        setMessage(null);
        setSelectedAdvancedRule(rule);
        setAdvancedDryRun(null);
        try {
            const result = await api.dryRunAdvancedDetectionRule(rule.rule_id, {
                relative_minutes: 43200,
                max_events: 1000,
                max_findings: 100,
                max_execution_ms: 1000,
            });
            setAdvancedDryRun(result);
            setSelectedAdvancedRule(result.rule);
            setMessage("Deterministic 30-day dry-run completed without alerts, incidents, cases, or notifications.");
        } catch (reason) {
            setError(failure(reason));
        } finally {
            setBusy(false);
        }
    };

    const runShadow = async () => {
        if (!selectedAdvancedRule) return;
        setBusy(true);
        setError(null);
        setMessage(null);
        try {
            const result = await api.runShadowEvaluation(selectedAdvancedRule.rule_id);
            setShadowRuns((current) => [result.run, ...current.filter((item) => item.run_id !== result.run.run_id)]);
            setMessage(
                `Shadow run completed with ${result.run.match_count} finding(s); no production alerts, incidents, or cases were created.`,
            );
            setRevision((value) => value + 1);
        } catch (reason) {
            setError(failure(reason));
        } finally {
            setBusy(false);
        }
    };

    const compareTuning = async () => {
        if (!selectedAdvancedRule || configurations.length === 0) return;
        setBusy(true);
        setError(null);
        setMessage(null);
        try {
            const result = await api.compareDetectionTuning(
                selectedAdvancedRule.rule_id,
                configurations[0],
            );
            setTuningComparison(result);
            setMessage("Historical sensitivity comparison completed without production side effects.");
        } catch (reason) {
            setError(failure(reason));
        } finally {
            setBusy(false);
        }
    };

    const selectDraft = async (draft: RuleDraft) => {
        setSelectedDraft(draft);
        setDryRun(null);
        setDeploymentConfirmed(false);
        setDeploymentReason("");
        setForm({
            name: draft.name,
            description: draft.description,
            severity: draft.severity,
            source_type: draft.source_type,
            mitre_ids: [...draft.mitre_ids],
            conditions: draft.conditions.map((item) => ({ ...item })),
            documentation: draft.documentation,
            change_summary: "Update local draft",
        });
        setMitreText(draft.mitre_ids.join(", "));
        try {
            setVersions(await api.listRuleDraftVersions(draft.draft_id));
        } catch {
            setVersions([]);
        }
    };
    const resetDraft = () => {
        setSelectedDraft(null);
        setForm(EMPTY_DRAFT);
        setMitreText("");
        setVersions([]);
        setDryRun(null);
    };
    const saveDraft = async (event: FormEvent) => {
        event.preventDefault();
        setBusy(true);
        setError(null);
        setMessage(null);
        const payload = {
            ...form,
            mitre_ids: mitreText
                .split(",")
                .map((item) => item.trim().toUpperCase())
                .filter(Boolean),
        };
        try {
            const result = selectedDraft
                ? await api.updateRuleDraft(selectedDraft.draft_id, {
                      ...payload,
                      expected_version: selectedDraft.version,
                  })
                : await api.createRuleDraft(payload);
            setMessage(
                selectedDraft
                    ? "Draft updated; validation and test state reset."
                    : "Local draft created.",
            );
            await load();
            await selectDraft(result);
        } catch (reason) {
            setError(failure(reason));
        } finally {
            setBusy(false);
        }
    };
    const validate = async () => {
        if (!selectedDraft) return;
        setBusy(true);
        setError(null);
        try {
            const result = await api.validateRuleDraft(
                selectedDraft.draft_id,
                selectedDraft.version,
            );
            setMessage(
                result.warnings.join(" ") || "Declarative schema validated.",
            );
            await load();
            await selectDraft(result.draft);
        } catch (reason) {
            setError(failure(reason));
        } finally {
            setBusy(false);
        }
    };
    const test = async () => {
        if (!selectedDraft) return;
        setBusy(true);
        setError(null);
        try {
            const result = await api.dryRunRuleDraft(selectedDraft.draft_id, {
                expected_version: selectedDraft.version,
                relative_minutes: 43200,
                max_events: 1000,
            });
            setMessage(
                "Historical evaluation completed without alert, incident, or notification side effects.",
            );
            await load();
            await selectDraft(result.draft);
            setDryRun(result);
        } catch (reason) {
            setError(failure(reason));
        } finally {
            setBusy(false);
        }
    };
    const confirmDeployment = async () => {
        if (!selectedDraft) return;
        setBusy(true);
        setError(null);
        try {
            const result = await api.confirmManualDeployment(
                selectedDraft.draft_id,
                selectedDraft.version,
                deploymentReason.trim(),
            );
            setMessage(result.message);
            setDeploymentConfirmed(false);
            setDeploymentReason("");
            await load();
            await selectDraft(result.draft);
        } catch (reason) {
            setError(failure(reason));
        } finally {
            setBusy(false);
        }
    };
    const rollback = async (version: number) => {
        if (
            !selectedDraft ||
            !window.confirm(
                `Create a new draft version from version ${version}?`,
            )
        )
            return;
        setBusy(true);
        setError(null);
        try {
            const result = await api.rollbackRuleDraft(
                selectedDraft.draft_id,
                version,
                selectedDraft.version,
                `Restore version ${version}`,
            );
            setMessage(
                `Restored version ${version} into new draft version ${result.version}.`,
            );
            await load();
            await selectDraft(result);
        } catch (reason) {
            setError(failure(reason));
        } finally {
            setBusy(false);
        }
    };
    const updateCondition = (
        index: number,
        next: Partial<RuleDraftCreate["conditions"][number]>,
    ) =>
        setForm({
            ...form,
            conditions: form.conditions.map((item, itemIndex) =>
                itemIndex === index ? { ...item, ...next } : item,
            ),
        });
    const addCondition = () => {
        if (form.conditions.length >= 8) return;
        setForm({
            ...form,
            conditions: [
                ...form.conditions,
                { field: "rule_id", operator: "EQUALS", value: "" },
            ],
        });
    };
    const removeCondition = (index: number) => {
        if (form.conditions.length <= 1) return;
        setForm({
            ...form,
            conditions: form.conditions.filter(
                (_, itemIndex) => itemIndex !== index,
            ),
        });
    };

    return (
        <div className="page-grid">
            <section className="page-column">
                <header className="page-header">
                    <div>
                        <span className="eyebrow">Detection engineering</span>
                        <h1>Rules, coverage and quality</h1>
                        <p>
                            Authoritative activity metadata, safe local drafts,
                            bounded tests, and deterministic analytics.
                        </p>
                    </div>
                    <span className="health-pill health-pill--unknown">
                        No automatic deployment
                    </span>
                </header>
                <nav
                    className="tab-list"
                    aria-label="Detection engineering sections"
                >
                    {(
                        [
                            "inventory",
                            "advanced",
                            "coverage",
                            "analytics",
                            "drafts",
                            "shadow-v2",
                            "shadow-history",
                            "sigma",
                        ] as Tab[]
                    ).map((item) => (
                        <button
                            className={tab === item ? "is-active" : undefined}
                            type="button"
                            aria-pressed={tab === item}
                            onClick={() => setTab(item)}
                            key={item}
                        >
                            {humanize(item)}
                        </button>
                    ))}
                </nav>
                {error && (
                    <p
                        className="form-message form-message--error"
                        role="alert"
                    >
                        {error}
                    </p>
                )}
                {message && (
                    <p
                        className="form-message form-message--success"
                        role="status"
                    >
                        {message}
                    </p>
                )}
                {loading && (
                    <StatePanel
                        kind="loading"
                        title="Loading detection engineering"
                        message="Reading real rule activity, coverage, and quality data…"
                    />
                )}
                {!loading && error && !rules && (
                    <StatePanel
                        kind="unavailable"
                        title="Detection engineering unavailable"
                        message={error}
                        actionLabel="Retry"
                        onAction={() => setRevision((value) => value + 1)}
                    />
                )}

                {!loading && tab === "shadow-v2" && <ShadowWorkbench api={api} canMutate={canMutate} onOpenEvent={onOpenEvent}/>}
                {!loading && tab === 'sigma' && <SigmaImport api={api} canMutate={canMutate} onUseRule={row=>{
                    setImportedRules(current=>[...current.filter(value=>value.rule_version!==row.rule_version),row].slice(-8));
                    setTab('shadow-history');
                }}/>}
                {!loading && tab === 'shadow-history' && <ShadowHistory api={api} canMutate={canMutate} onOpenEvent={onOpenEvent} onInvestigate={onInvestigateDurable} importedRules={importedRules}/>}
                {!loading && tab === "inventory" && (
                    <>
                        <section className="panel">
                            <label className="field">
                                <span>
                                    Search rules, descriptions, or MITRE IDs
                                </span>
                                <input
                                    type="search"
                                    value={search}
                                    onChange={(event) => {
                                        setSearch(event.target.value);
                                        setRulePage(0);
                                    }}
                                />
                            </label>
                        </section>
                        {visibleRules.length === 0 ? (
                            <StatePanel
                                kind="empty"
                                title="No matching rules"
                                message="No deployed or observed rule matches the current search."
                            />
                        ) : (
                            <div className="table-frame">
                                <table className="data-table">
                                    <thead>
                                        <tr>
                                            <th>Rule</th>
                                            <th>Detection</th>
                                            <th>Severity</th>
                                            <th>MITRE</th>
                                            <th>Enabled</th>
                                            <th>Triggered</th>
                                            <th>Test record</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {visibleRules.map((rule) => (
                                            <tr key={rule.rule_id}>
                                                <td>
                                                    <button
                                                        className="row-link mono"
                                                        type="button"
                                                        onClick={() =>
                                                            setSelectedRule(
                                                                rule,
                                                            )
                                                        }
                                                    >
                                                        {rule.rule_id}
                                                    </button>
                                                </td>
                                                <td>
                                                    <strong>{rule.name}</strong>
                                                    <span className="cell-subtle">
                                                        {rule.source_type} ·{" "}
                                                        {rule.management_mode}
                                                    </span>
                                                </td>
                                                <td>
                                                    {rule.severity == null ? (
                                                        "—"
                                                    ) : (
                                                        <SeverityBadge
                                                            level={
                                                                rule.severity
                                                            }
                                                        />
                                                    )}
                                                </td>
                                                <td>
                                                    {rule.mitre_ids.length
                                                        ? rule.mitre_ids.join(
                                                              ", ",
                                                          )
                                                        : "Unmapped"}
                                                </td>
                                                <td>
                                                    <span
                                                        title={
                                                            rule.enabled_evidence
                                                        }
                                                    >
                                                        {rule.enabled_state}
                                                    </span>
                                                </td>
                                                <td>
                                                    {rule.alert_count}
                                                    <span className="cell-subtle">
                                                        {rule.last_triggered ? (
                                                            <TimeValue
                                                                value={
                                                                    rule.last_triggered
                                                                }
                                                                relative
                                                            />
                                                        ) : (
                                                            "Never"
                                                        )}
                                                    </span>
                                                </td>
                                                <td>{rule.tested_state}</td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        )}
                        <footer className="pagination">
                            <span>
                                Showing {visibleRules.length} of{" "}
                                {filteredRules.length} rules
                            </span>
                            <div>
                                <button
                                    className="button button--secondary"
                                    type="button"
                                    disabled={rulePage === 0}
                                    onClick={() =>
                                        setRulePage((value) => value - 1)
                                    }
                                >
                                    Previous
                                </button>
                                <button
                                    className="button button--secondary"
                                    type="button"
                                    disabled={
                                        (rulePage + 1) * 25 >=
                                        filteredRules.length
                                    }
                                    onClick={() =>
                                        setRulePage((value) => value + 1)
                                    }
                                >
                                    Next
                                </button>
                            </div>
                        </footer>
                    </>
                )}

                {!loading && tab === "advanced" && (
                    <>
                        <section className="panel">
                            <div className="section-heading">
                                <div>
                                    <h2>M11 advanced detection pack</h2>
                                    <p>
                                        Nine versioned, disabled-by-policy rules
                                        with explicit prerequisites and a shared
                                        deterministic evaluator.
                                    </p>
                                </div>
                                <span className="health-pill health-pill--unknown">
                                    Live activation disabled
                                </span>
                            </div>
                            <div className="filter-grid">
                                <label className="field">
                                    <span>Search rule, event ID, or MITRE ID</span>
                                    <input
                                        type="search"
                                        value={advancedSearch}
                                        onChange={(event) => setAdvancedSearch(event.target.value)}
                                    />
                                </label>
                                <label className="field">
                                    <span>Telemetry status</span>
                                    <select
                                        value={advancedStatus}
                                        onChange={(event) => setAdvancedStatus(event.target.value as AdvancedAvailabilityStatus | "ALL")}
                                    >
                                        <option value="ALL">All statuses</option>
                                        <option value="RECENTLY_OBSERVED">Recently observed</option>
                                        <option value="OBSERVED_STALE">Observed stale</option>
                                        <option value="PREREQUISITE_MISSING">Prerequisite missing</option>
                                        <option value="NO_DATA">No data</option>
                                        <option value="UNKNOWN">Unknown</option>
                                    </select>
                                </label>
                                <label className="field">
                                    <span>Source type</span>
                                    <select value={advancedSource} onChange={(event) => setAdvancedSource(event.target.value)}>
                                        <option value="ALL">All sources</option>
                                        {advancedSources.map((source) => <option value={source} key={source}>{source}</option>)}
                                    </select>
                                </label>
                            </div>
                        </section>
                        {filteredAdvancedRules.length === 0 ? (
                            <StatePanel kind="empty" title="No matching advanced detections" message="Change the search or telemetry filters." />
                        ) : (
                            <div className="table-frame">
                                <table className="data-table">
                                    <thead>
                                        <tr>
                                            <th>Rule</th>
                                            <th>Detection</th>
                                            <th>Severity</th>
                                            <th>Prerequisites</th>
                                            <th>Telemetry</th>
                                            <th>MITRE</th>
                                            <th>Action</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {filteredAdvancedRules.map((rule) => (
                                            <tr key={rule.rule_id}>
                                                <td className="mono">{rule.rule_id}</td>
                                                <td>
                                                    <button
                                                        className="row-link"
                                                        type="button"
                                                        onClick={() => {
                                                            setSelectedAdvancedRule(rule);
                                                            setAdvancedDryRun(null);
                                                        }}
                                                    >
                                                        {rule.name}
                                                    </button>
                                                    <span className="cell-subtle">v{rule.version} · disabled</span>
                                                </td>
                                                <td><SeverityBadge level={rule.severity} /></td>
                                                <td>
                                                    {rule.prerequisites.event_codes.join(", ") || rule.prerequisites.event_categories.join(", ")}
                                                    <span className="cell-subtle">
                                                        {rule.prerequisites.required_fields.length} required fields
                                                    </span>
                                                </td>
                                                <td>
                                                    {humanize(rule.availability?.status ?? "UNKNOWN")}
                                                    <span className="cell-subtle">
                                                        {rule.availability?.observed_event_count ?? 0} eligible events
                                                    </span>
                                                </td>
                                                <td>
                                                    {rule.mitre_ids.length
                                                        ? rule.mitre_ids.map((id) => (
                                                              <a href={mitreUrl(id)} target="_blank" rel="noreferrer" key={id}>{id}</a>
                                                          ))
                                                        : "No broad mapping"}
                                                </td>
                                                <td>
                                                    <button
                                                        className="button button--secondary"
                                                        type="button"
                                                        disabled={!canMutate || busy}
                                                        onClick={() => void runAdvancedDryRun(rule)}
                                                    >
                                                        Dry-run 30 days
                                                    </button>
                                                </td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        )}
                        <p className="trust-note">
                            Parser support, stored-data observation, recent
                            observation, and live collector configuration are
                            separate facts. Configuration remains unknown until
                            an authoritative collector API proves it.
                        </p>
                        {selectedAdvancedRule && (
                            <section className="panel advanced-rule-detail">
                                <div className="section-heading">
                                    <div>
                                        <span className="eyebrow">{selectedAdvancedRule.rule_id} · v{selectedAdvancedRule.version}</span>
                                        <h2>{selectedAdvancedRule.name}</h2>
                                        <p>{selectedAdvancedRule.description}</p>
                                    </div>
                                    <button className="icon-button" type="button" aria-label="Close advanced rule detail" onClick={() => {
                                        setSelectedAdvancedRule(null);
                                        setAdvancedDryRun(null);
                                    }}>×</button>
                                </div>
                                <dl className="metadata-grid">
                                    <div><dt>Activation</dt><dd>{humanize(selectedAdvancedRule.activation_state)}</dd></div>
                                    <div><dt>Telemetry</dt><dd>{humanize(selectedAdvancedRule.availability?.status ?? "UNKNOWN")}</dd></div>
                                    <div><dt>Threshold</dt><dd>{selectedAdvancedRule.threshold} event(s)</dd></div>
                                    <div><dt>Window</dt><dd>{selectedAdvancedRule.window_seconds} seconds</dd></div>
                                    <div><dt>Grouping</dt><dd>{selectedAdvancedRule.grouping_fields.join(", ")}</dd></div>
                                    <div><dt>Configuration</dt><dd>{selectedAdvancedRule.prerequisites.configuration_status}</dd></div>
                                    <div><dt>Validation</dt><dd>{humanize(selectedAdvancedRule.validation_status)}</dd></div>
                                </dl>
                                <p className="trust-note">{selectedAdvancedRule.availability?.explanation}</p>
                                <div className="split-panels">
                                    <div>
                                        <h3>Conditions and prerequisites</h3>
                                        <ul>{selectedAdvancedRule.conditions.map((item) => <li key={item}>{item}</li>)}</ul>
                                        <p><strong>Required fields:</strong> {selectedAdvancedRule.prerequisites.required_fields.join(", ")}</p>
                                        {selectedAdvancedRule.availability?.missing_required_fields.length ? (
                                            <p className="stale-warning">Missing in observed telemetry: {selectedAdvancedRule.availability.missing_required_fields.join(", ")}</p>
                                        ) : null}
                                    </div>
                                    <div>
                                        <h3>False-positive controls</h3>
                                        <ul>{selectedAdvancedRule.false_positive_notes.map((item) => <li key={item}>{item}</li>)}</ul>
                                        <h3>Analyst guidance</h3>
                                        <ul>{selectedAdvancedRule.analyst_guidance.map((item) => <li key={item}>{item}</li>)}</ul>
                                    </div>
                                </div>
                                <h3>Deduplication</h3>
                                <p>{selectedAdvancedRule.deduplication}</p>
                                {selectedAdvancedRule.mitre_mappings.length > 0 && (
                                    <>
                                        <h3>MITRE ATT&amp;CK rationale</h3>
                                        <ul>
                                            {selectedAdvancedRule.mitre_mappings.map((mapping) => (
                                                <li key={mapping.technique_id}>
                                                    <a href={mitreUrl(mapping.technique_id)} target="_blank" rel="noreferrer">
                                                        {mapping.technique_id} · {mapping.technique_name}
                                                    </a>{" "}
                                                    ({mapping.tactic}) — {mapping.relationship}
                                                </li>
                                            ))}
                                        </ul>
                                    </>
                                )}
                                <h3>Validation contract</h3>
                                <ul>{selectedAdvancedRule.validation_notes.map((item) => <li key={item}>{item}</li>)}</ul>
                                <p className="trust-note">
                                    Packaged rules are read-only and disabled.
                                    Use the Drafts editor for analyst-authored
                                    candidates; neither path changes live Wazuh.
                                </p>
                                <div className="tab-list" role="tablist" aria-label="Advanced detection readiness views">
                                    {(["overview", "configuration", "test", "shadow", "tuning", "quality", "readiness", "diagnostics"] as AdvancedView[]).map((view) => (
                                        <button
                                            type="button"
                                            role="tab"
                                            aria-selected={advancedView === view}
                                            className={advancedView === view ? "is-active" : undefined}
                                            onClick={() => setAdvancedView(view)}
                                            key={view}
                                        >
                                            {humanize(view)}
                                        </button>
                                    ))}
                                </div>
                                {advancedView === "overview" && lifecycle && (
                                    <section className="dry-run-result">
                                        <h3>Detection overview</h3>
                                        <dl className="metadata-grid">
                                            <div><dt>Configuration state</dt><dd>{humanize(lifecycle.configuration_state)}</dd></div>
                                            <div><dt>Validation state</dt><dd>{humanize(lifecycle.validation_state)}</dd></div>
                                            <div><dt>Deployment eligibility</dt><dd>{humanize(lifecycle.deployment_eligibility)}</dd></div>
                                            <div><dt>Runtime activation</dt><dd>{humanize(lifecycle.runtime_activation_state)}</dd></div>
                                            <div><dt>Telemetry</dt><dd>{humanize(lifecycle.telemetry_status)}</dd></div>
                                            <div><dt>Configuration version</dt><dd>{lifecycle.active_configuration_version}</dd></div>
                                        </dl>
                                        <p className="stale-warning">{lifecycle.inactive_reason}</p>
                                        <p className="trust-note">A validated or tested configuration remains inactive until a separate backend-enforced approval milestone.</p>
                                    </section>
                                )}
                                {advancedView === "configuration" && (
                                    <section className="dry-run-result">
                                        <h3>Versioned rule configuration</h3>
                                        {configurations.length === 0 ? (
                                            <p className="muted-copy">No approved schema-backed configuration is available.</p>
                                        ) : (
                                            <div className="table-frame">
                                                <table className="data-table">
                                                    <thead><tr><th>Version</th><th>State</th><th>Threshold</th><th>Window</th><th>Limits</th><th>Reason</th></tr></thead>
                                                    <tbody>
                                                        {configurations.map((config) => (
                                                            <tr key={config.config_id}>
                                                                <td className="mono">v{config.version}</td>
                                                                <td>{humanize(config.lifecycle_state)}</td>
                                                                <td>{config.threshold_count}</td>
                                                                <td>{config.time_window_seconds}s</td>
                                                                <td>{config.evaluation_limits.max_events} events / {config.evaluation_limits.max_findings} findings / {config.evaluation_limits.max_execution_ms}ms</td>
                                                                <td>{config.change_reason}</td>
                                                            </tr>
                                                        ))}
                                                    </tbody>
                                                </table>
                                            </div>
                                        )}
                                        <p className="trust-note">Configuration is declarative JSON only; Python, shell, SQL, and direct Wazuh deployment are not accepted. ADMIN mutation permission is separate from runtime activation.</p>
                                    </section>
                                )}
                                {advancedView === "test" && (
                                    <section className="dry-run-result">
                                        <h3>Historical deterministic test</h3>
                                        <button className="button button--secondary" type="button" disabled={!canMutate || busy} onClick={() => void runAdvancedDryRun(selectedAdvancedRule)}>Run bounded 30-day dry-run</button>
                                        <p className="trust-note">A PASS may support TESTED state but never changes runtime activation.</p>
                                    </section>
                                )}
                                {advancedView === "shadow" && (
                                    <section className="dry-run-result">
                                        <div className="section-heading">
                                            <div><h3>Shadow runs</h3><p>Read-only evaluation stored outside production alert and incident pipelines.</p></div>
                                            <button className="button button--primary" type="button" disabled={!canMutate || busy} onClick={() => void runShadow()}>Run 24-hour shadow evaluation</button>
                                        </div>
                                        {shadowRuns.length === 0 ? <p className="muted-copy">No operator-triggered shadow runs recorded.</p> : (
                                            <ul className="audit-list">
                                                {shadowRuns.map((run) => (
                                                    <li key={run.run_id}>
                                                        <div><strong>{run.status} · {run.match_count} finding(s)</strong><TimeValue value={run.started_at} /></div>
                                                        <p>{run.evaluated_event_count} events · {run.execution_ms.toFixed(2)} ms · source {humanize(run.source_availability)} · no production side effects</p>
                                                    </li>
                                                ))}
                                            </ul>
                                        )}
                                    </section>
                                )}
                                {advancedView === "tuning" && (
                                    <section className="dry-run-result">
                                        <div className="section-heading">
                                            <div><h3>Tuning comparison</h3><p>Compare the active threshold with a more conservative candidate over the same history.</p></div>
                                            <button className="button button--secondary" type="button" disabled={!canMutate || busy || configurations.length === 0 || !["DET-001", "DET-002"].includes(selectedAdvancedRule.rule_id)} onClick={() => void compareTuning()}>Compare sensitivity</button>
                                        </div>
                                        {!['DET-001', 'DET-002'].includes(selectedAdvancedRule.rule_id) && <p className="trust-note">This multi-branch packaged rule has fixed M11 thresholds and windows; changing them would create a divergent algorithm.</p>}
                                        {tuningComparison && (
                                            <>
                                                <div className="table-frame"><table className="data-table">
                                                    <thead><tr><th>Threshold</th><th>Window</th><th>Events</th><th>Findings</th><th>Duplicates</th><th>Missing fields</th></tr></thead>
                                                    <tbody>{tuningComparison.results.map((result) => (
                                                        <tr key={`${result.candidate.threshold_count}-${result.candidate.time_window_seconds}`}>
                                                            <td>{result.candidate.threshold_count}</td><td>{result.candidate.time_window_seconds}s</td><td>{result.evaluated_event_count}</td><td>{result.finding_count}</td><td>{result.duplicate_count}</td><td>{result.missing_field_count}</td>
                                                        </tr>
                                                    ))}</tbody>
                                                </table></div>
                                                <p className="trust-note">{tuningComparison.interpretation}</p>
                                            </>
                                        )}
                                    </section>
                                )}
                                {advancedView === "quality" && (
                                    <section className="dry-run-result">
                                        <h3>Golden dataset quality</h3>
                                        {!detectionQuality ? (
                                            <p className="muted-copy">Quality result is unavailable for this rule.</p>
                                        ) : (
                                            <>
                                                <dl className="metadata-grid">
                                                    <div><dt>Fixture status</dt><dd>{detectionQuality.all_applicable_fixtures_passed ? "PASS" : "FAIL"}</dd></div>
                                                    <div><dt>Precision</dt><dd>{detectionQuality.metrics.precision === null ? "Unavailable" : `${(detectionQuality.metrics.precision * 100).toFixed(1)}%`}</dd></div>
                                                    <div><dt>Recall</dt><dd>{detectionQuality.metrics.recall === null ? "Unavailable" : `${(detectionQuality.metrics.recall * 100).toFixed(1)}%`}</dd></div>
                                                    <div><dt>False-positive rate</dt><dd>{detectionQuality.metrics.false_positive_rate === null ? "Unavailable" : `${(detectionQuality.metrics.false_positive_rate * 100).toFixed(1)}%`}</dd></div>
                                                    <div><dt>Duplicate finding rate</dt><dd>{(detectionQuality.metrics.duplicate_finding_rate * 100).toFixed(1)}%</dd></div>
                                                    <div><dt>Evaluation p95</dt><dd>{detectionQuality.metrics.evaluation_time_p95_ms.toFixed(3)} ms</dd></div>
                                                    <div><dt>Event ordering</dt><dd>{detectionQuality.metrics.event_order_consistent ? "Consistent" : "Mismatch"}</dd></div>
                                                    <div><dt>Repeat recovery</dt><dd>{detectionQuality.metrics.repeat_evaluation_consistent ? "Consistent" : "Mismatch"}</dd></div>
                                                </dl>
                                                <div className="table-frame">
                                                    <table className="data-table">
                                                        <thead><tr><th>Scenario</th><th>Label</th><th>Expected</th><th>Actual</th><th>Duplicates</th><th>Result</th></tr></thead>
                                                        <tbody>{detectionQuality.fixtures.map((fixture) => (
                                                            <tr key={fixture.scenario}>
                                                                <td>{humanize(fixture.scenario)}</td>
                                                                <td>{fixture.applicable ? fixture.ground_truth : "NOT APPLICABLE"}</td>
                                                                <td>{fixture.expected_finding_count}</td>
                                                                <td>{fixture.actual_finding_count}</td>
                                                                <td>{fixture.evaluator_duplicate_count}</td>
                                                                <td>{fixture.passed ? "PASS" : "FAIL"}</td>
                                                            </tr>
                                                        ))}</tbody>
                                                    </table>
                                                </div>
                                                <p className="trust-note">
                                                    {detectionQuality.dataset_label}: classification metrics use labeled synthetic fixtures only. They are not live-production accuracy scores. Runtime remains {humanize(detectionQuality.runtime_activation_state)} and deployment remains {humanize(detectionQuality.deployment_eligibility)}.
                                                </p>
                                            </>
                                        )}
                                    </section>
                                )}
                                {advancedView === "readiness" && telemetryReadiness && (
                                    <section className="dry-run-result">
                                        <h3>Telemetry readiness</h3>
                                        <dl className="metadata-grid">
                                            <div><dt>Status</dt><dd>{humanize(telemetryReadiness.status)}</dd></div>
                                            <div><dt>Latest evidence</dt><dd><TimeValue value={telemetryReadiness.latest_observed_event} /></dd></div>
                                            <div><dt>Normalization</dt><dd>{telemetryReadiness.normalization_compatible ? "Compatible" : "Incomplete"}</dd></div>
                                            <div><dt>Required events</dt><dd>{[...telemetryReadiness.required_event_codes, ...telemetryReadiness.required_categories].join(", ") || "Category-based"}</dd></div>
                                        </dl>
                                        <p>{telemetryReadiness.explanation}</p>
                                        {telemetryReadiness.missing_prerequisites.length > 0 && <p className="stale-warning">Missing: {telemetryReadiness.missing_prerequisites.join(", ")}</p>}
                                        {canarySafety && (
                                            <>
                                                <h3>Canary readiness checklist</h3>
                                                <ul>{canarySafety.blockers.map((blocker) => <li key={blocker}>{blocker}</li>)}</ul>
                                                <p className="trust-note">Activation path enabled: no · operator approval recorded: no · runtime state: {canarySafety.runtime_activation_state}</p>
                                            </>
                                        )}
                                    </section>
                                )}
                                {advancedView === "diagnostics" && detectionDiagnostics && (
                                    <section className="dry-run-result">
                                        <h3>Bounded diagnostics</h3>
                                        <dl className="metadata-grid">
                                            <div><dt>Evaluations</dt><dd>{detectionDiagnostics.evaluation_count}</dd></div>
                                            <div><dt>Average duration</dt><dd>{detectionDiagnostics.average_duration_ms.toFixed(2)} ms</dd></div>
                                            <div><dt>Findings</dt><dd>{detectionDiagnostics.finding_count}</dd></div>
                                            <div><dt>Duplicate events</dt><dd>{detectionDiagnostics.duplicate_event_count}</dd></div>
                                            <div><dt>Missing fields</dt><dd>{detectionDiagnostics.missing_field_count}</dd></div>
                                            <div><dt>State recoveries</dt><dd>{detectionDiagnostics.state_recovery_count}</dd></div>
                                            <div><dt>Timeouts</dt><dd>{detectionDiagnostics.evaluation_timeout_count}</dd></div>
                                            <div><dt>Truncations</dt><dd>{detectionDiagnostics.truncation_count}</dd></div>
                                        </dl>
                                        <p className="trust-note">Diagnostics expose bounded aggregate counts only; account names and private evidence are not operational metric labels.</p>
                                    </section>
                                )}
                                {advancedView === "test" && advancedDryRun && advancedDryRun.rule.rule_id === selectedAdvancedRule.rule_id && (
                                    <section className="dry-run-result">
                                        <h3>Advanced dry-run result</h3>
                                        <p>
                                            {advancedDryRun.finding_count} findings among {advancedDryRun.evaluated_event_count} bounded events in {advancedDryRun.execution_ms.toFixed(2)} ms (budget {advancedDryRun.execution_budget_ms} ms).
                                        </p>
                                        <p className="trust-note">
                                            Deterministic event-time ordering; no alerts, incidents, cases, notifications, or live rule changes.
                                        </p>
                                        {advancedDryRun.findings.length === 0 ? (
                                            <p className="muted-copy">No correlation met the rule threshold in this range.</p>
                                        ) : advancedDryRun.findings.map((finding) => (
                                            <article className="panel" key={finding.finding_id}>
                                                <div className="section-heading">
                                                    <div>
                                                        <strong>{finding.finding_id}</strong>
                                                        <p>{finding.explanation}</p>
                                                    </div>
                                                    <SeverityBadge level={finding.severity} />
                                                </div>
                                                <p>
                                                    {finding.matched_event_count} evidence events · threshold {finding.threshold} · {Object.entries(finding.group).map(([key, value]) => `${key}=${value}`).join(" · ")}
                                                </p>
                                                <button className="button button--primary" type="button" onClick={() => onInvestigateFinding(selectedAdvancedRule.rule_id, finding.deduplication_key, advancedDryRun.start_time, advancedDryRun.end_time)}>Open Investigation Workbench</button>
                                                <ul className="audit-list">
                                                    {finding.evidence.map((evidence) => (
                                                        <li key={evidence.event_id}>
                                                            <button className="row-link mono" type="button" onClick={() => onOpenEvent(evidence.event_id)}>{evidence.event_id}</button>
                                                            <span>{evidence.summary} · <TimeValue value={evidence.timestamp} /></span>
                                                        </li>
                                                    ))}
                                                </ul>
                                            </article>
                                        ))}
                                    </section>
                                )}
                            </section>
                        )}
                    </>
                )}

                {!loading && tab === "coverage" && coverage && (
                    <>
                        <section className="metric-grid">
                            <article>
                                <span>Mapped rules</span>
                                <strong>{coverage.mapped_rule_count}</strong>
                            </article>
                            <article>
                                <span>Unmapped rules</span>
                                <strong>{coverage.unmapped_rule_count}</strong>
                            </article>
                            <article>
                                <span>Validation gaps</span>
                                <strong>{coverage.validation_gap_count}</strong>
                            </article>
                        </section>
                        {coverage.techniques.length === 0 ? (
                            <StatePanel
                                kind="empty"
                                title="No explicit mappings"
                                message="No rule contains an authoritative MITRE technique mapping."
                            />
                        ) : (
                            <div className="table-frame">
                                <table className="data-table">
                                    <thead>
                                        <tr>
                                            <th>Technique</th>
                                            <th>State</th>
                                            <th>Mapped</th>
                                            <th>Enabled</th>
                                            <th>Triggered</th>
                                            <th>Tested</th>
                                            <th>Sources</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {coverage.techniques.map((item) => (
                                            <tr key={item.technique_id}>
                                                <td>
                                                    <a
                                                        href={mitreUrl(
                                                            item.technique_id,
                                                        )}
                                                        target="_blank"
                                                        rel="noreferrer"
                                                    >
                                                        {item.technique_id}
                                                    </a>
                                                    <span className="cell-subtle">
                                                        {item.rule_ids.join(
                                                            ", ",
                                                        )}
                                                    </span>
                                                </td>
                                                <td>
                                                    {humanize(
                                                        item.coverage_state,
                                                    )}
                                                </td>
                                                <td>
                                                    {
                                                        item.mapped_detection_count
                                                    }
                                                </td>
                                                <td>
                                                    {
                                                        item.enabled_detection_count
                                                    }
                                                </td>
                                                <td>
                                                    {
                                                        item.triggered_detection_count
                                                    }{" "}
                                                    · {item.alert_count} alerts
                                                </td>
                                                <td>
                                                    {
                                                        item.tested_detection_count
                                                    }
                                                </td>
                                                <td>
                                                    {item.sources.join(", ")}
                                                </td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        )}
                        <p className="trust-note">
                            Mapped, enabled, triggered, and tested are separate
                            facts. Mapping alone is not proven detection
                            coverage.
                        </p>
                    </>
                )}

                {!loading && tab === "analytics" && analytics && (
                    <>
                        <section className="metric-grid">
                            <article>
                                <span>Alerts in range</span>
                                <strong>
                                    {analytics.alert_trend.reduce(
                                        (sum, item) => sum + item.count,
                                        0,
                                    )}
                                </strong>
                            </article>
                            <article>
                                <span>False positives</span>
                                <strong>
                                    {analytics.false_positive_trend.reduce(
                                        (sum, item) => sum + item.count,
                                        0,
                                    )}
                                </strong>
                            </article>
                            <article>
                                <span>Tuning candidates</span>
                                <strong>
                                    {
                                        analytics.suggested_tuning_candidates
                                            .length
                                    }
                                </strong>
                            </article>
                        </section>
                        <div className="split-panels">
                            <section className="panel">
                                <h2>Top rules</h2>
                                {analytics.top_rules.length ? (
                                    <ol className="rank-list">
                                        {analytics.top_rules.map((item) => (
                                            <li key={item.name}>
                                                <button
                                                    className="row-link mono"
                                                    type="button"
                                                    onClick={() =>
                                                        onOpenAlerts(item.name)
                                                    }
                                                >
                                                    {item.name}
                                                </button>
                                                <strong>{item.count}</strong>
                                            </li>
                                        ))}
                                    </ol>
                                ) : (
                                    <p className="muted-copy">
                                        No alerts in range.
                                    </p>
                                )}
                            </section>
                            <section className="panel">
                                <h2>Top source IPs</h2>
                                {analytics.top_source_ips.length ? (
                                    <ol className="rank-list">
                                        {analytics.top_source_ips.map(
                                            (item) => (
                                                <li key={item.name}>
                                                    <span className="mono">
                                                        {item.name}
                                                    </span>
                                                    <strong>
                                                        {item.count}
                                                    </strong>
                                                </li>
                                            ),
                                        )}
                                    </ol>
                                ) : (
                                    <p className="muted-copy">
                                        No source IP evidence.
                                    </p>
                                )}
                            </section>
                        </div>
                        <section className="panel">
                            <h2>Analyst terminal dispositions</h2>
                            {analytics.analyst_dispositions.length ? (
                                <div className="table-frame">
                                    <table className="data-table">
                                        <thead>
                                            <tr>
                                                <th>Analyst</th>
                                                <th>Resolved</th>
                                                <th>False positive</th>
                                                <th>Total</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {analytics.analyst_dispositions.map(
                                                (item) => (
                                                    <tr key={item.analyst}>
                                                        <td>{item.analyst}</td>
                                                        <td>
                                                            {
                                                                item.resolved_count
                                                            }
                                                        </td>
                                                        <td>
                                                            {
                                                                item.false_positive_count
                                                            }
                                                        </td>
                                                        <td>{item.total_count}</td>
                                                    </tr>
                                                ),
                                            )}
                                        </tbody>
                                    </table>
                                </div>
                            ) : (
                                <p className="muted-copy">
                                    No analyst terminal dispositions in this
                                    range.
                                </p>
                            )}
                        </section>
                        <div className="table-frame">
                            <table className="data-table">
                                <thead>
                                    <tr>
                                        <th>Rule</th>
                                        <th>Total alerts</th>
                                        <th>Dispositioned</th>
                                        <th>False positive</th>
                                        <th>Rate</th>
                                        <th>Suggestion</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {analytics.false_positive_rules.map(
                                        (item) => (
                                            <tr key={item.rule_id}>
                                                <td className="mono">
                                                    {item.rule_id}
                                                </td>
                                                <td>{item.total_alerts}</td>
                                                <td>
                                                    {item.dispositioned_alerts}
                                                </td>
                                                <td>
                                                    {item.false_positive_count}
                                                </td>
                                                <td>
                                                    {item.false_positive_rate ==
                                                    null
                                                        ? "Insufficient dispositions"
                                                        : `${(item.false_positive_rate * 100).toFixed(1)}%`}
                                                </td>
                                                <td>
                                                    {item.tuning_candidate
                                                        ? "Review tuning"
                                                        : "No deterministic suggestion"}
                                                </td>
                                            </tr>
                                        ),
                                    )}
                                </tbody>
                            </table>
                        </div>
                        <p className="trust-note">
                            Tuning candidates require at least five terminal
                            dispositions and a false-positive rate of 40% or
                            more. Nothing is suppressed automatically.
                        </p>
                    </>
                )}

                {!loading && tab === "drafts" && (
                    <div className="detection-draft-layout">
                        <section className="panel">
                            <div className="section-heading">
                                <div>
                                    <h2>Local drafts</h2>
                                    <p>
                                        Validated declarative rules; not live
                                        Wazuh configuration.
                                    </p>
                                </div>
                                <button
                                    className="button button--secondary"
                                    type="button"
                                    onClick={resetDraft}
                                >
                                    New draft
                                </button>
                            </div>
                            {drafts.length === 0 ? (
                                <p className="muted-copy">No local drafts.</p>
                            ) : (
                                <ul className="draft-list">
                                    {drafts.map((draft) => (
                                        <li key={draft.draft_id}>
                                            <button
                                                className="row-link"
                                                type="button"
                                                onClick={() => {
                                                    void selectDraft(draft);
                                                }}
                                            >
                                                <strong>{draft.name}</strong>
                                                <span>
                                                    {draft.status} · v
                                                    {draft.version}
                                                </span>
                                            </button>
                                        </li>
                                    ))}
                                </ul>
                            )}
                        </section>
                        <section className="panel">
                            <h2>
                                {selectedDraft
                                    ? `Edit ${selectedDraft.name}`
                                    : "Create local draft"}
                            </h2>
                            {canMutate ? (
                                <form
                                    className="stack-form"
                                    onSubmit={saveDraft}
                                >
                                    <label className="field">
                                        <span>Name</span>
                                        <input
                                            required
                                            maxLength={128}
                                            value={form.name}
                                            onChange={(event) =>
                                                setForm({
                                                    ...form,
                                                    name: event.target.value,
                                                })
                                            }
                                        />
                                    </label>
                                    <label className="field">
                                        <span>Description</span>
                                        <textarea
                                            required
                                            maxLength={2048}
                                            value={form.description}
                                            onChange={(event) =>
                                                setForm({
                                                    ...form,
                                                    description:
                                                        event.target.value,
                                                })
                                            }
                                        />
                                    </label>
                                    <div className="inline-form">
                                        <label className="field">
                                            <span>Severity</span>
                                            <input
                                                type="number"
                                                min="0"
                                                max="16"
                                                value={form.severity}
                                                onChange={(event) =>
                                                    setForm({
                                                        ...form,
                                                        severity: Number(
                                                            event.target.value,
                                                        ),
                                                    })
                                                }
                                            />
                                        </label>
                                        <label className="field">
                                            <span>Source type</span>
                                            <input
                                                required
                                                pattern="[a-z][a-z0-9_]*"
                                                maxLength={64}
                                                value={form.source_type}
                                                onChange={(event) =>
                                                    setForm({
                                                        ...form,
                                                        source_type:
                                                            event.target.value,
                                                    })
                                                }
                                            />
                                        </label>
                                        <label className="field field--grow">
                                            <span>
                                                MITRE IDs, comma separated
                                            </span>
                                            <input
                                                value={mitreText}
                                                onChange={(event) =>
                                                    setMitreText(
                                                        event.target.value,
                                                    )
                                                }
                                                placeholder="T1046, T1595.002"
                                            />
                                        </label>
                                    </div>
                                    <fieldset className="condition-builder">
                                        <legend>
                                            Declarative conditions (all must
                                            match)
                                        </legend>
                                        {form.conditions.map(
                                            (condition, index) => (
                                                <div
                                                    className="condition-row"
                                                    key={index}
                                                >
                                                    <select
                                                        aria-label={
                                                            index === 0
                                                                ? "Condition field"
                                                                : `Condition field ${index + 1}`
                                                        }
                                                        value={condition.field}
                                                        onChange={(event) =>
                                                            updateCondition(
                                                                index,
                                                                {
                                                                    field: event
                                                                        .target
                                                                        .value as RuleConditionField,
                                                                },
                                                            )
                                                        }
                                                    >
                                                        {[
                                                            "source_type",
                                                            "hostname",
                                                            "agent_id",
                                                            "agent_name",
                                                            "operating_system",
                                                            "event_provider",
                                                            "event_channel",
                                                            "process_name",
                                                            "process_path",
                                                            "command_line",
                                                            "parent_process_name",
                                                            "parent_process_path",
                                                            "source_ip",
                                                            "destination_ip",
                                                            "username",
                                                            "event_category",
                                                            "event_action",
                                                            "outcome",
                                                            "rule_id",
                                                            "event_code",
                                                            "message",
                                                        ].map((field) => (
                                                            <option
                                                                value={field}
                                                                key={field}
                                                            >
                                                                {humanize(
                                                                    field,
                                                                )}
                                                            </option>
                                                        ))}
                                                    </select>
                                                    <select
                                                        aria-label={
                                                            index === 0
                                                                ? "Condition operator"
                                                                : `Condition operator ${index + 1}`
                                                        }
                                                        value={
                                                            condition.operator
                                                        }
                                                        onChange={(event) =>
                                                            updateCondition(
                                                                index,
                                                                {
                                                                    operator:
                                                                        event
                                                                            .target
                                                                            .value as RuleConditionOperator,
                                                                },
                                                            )
                                                        }
                                                    >
                                                        <option value="EQUALS">
                                                            Equals
                                                        </option>
                                                        <option value="CONTAINS">
                                                            Contains
                                                        </option>
                                                        <option value="STARTS_WITH">
                                                            Starts with
                                                        </option>
                                                    </select>
                                                    <input
                                                        aria-label={
                                                            index === 0
                                                                ? "Condition value"
                                                                : `Condition value ${index + 1}`
                                                        }
                                                        required
                                                        maxLength={512}
                                                        value={condition.value}
                                                        onChange={(event) =>
                                                            updateCondition(
                                                                index,
                                                                {
                                                                    value: event
                                                                        .target
                                                                        .value,
                                                                },
                                                            )
                                                        }
                                                    />
                                                    <button
                                                        className="button button--ghost"
                                                        type="button"
                                                        disabled={
                                                            form.conditions
                                                                .length === 1
                                                        }
                                                        aria-label={`Remove condition ${index + 1}`}
                                                        onClick={() =>
                                                            removeCondition(
                                                                index,
                                                            )
                                                        }
                                                    >
                                                        Remove
                                                    </button>
                                                </div>
                                            ),
                                        )}
                                        <button
                                            className="button button--secondary"
                                            type="button"
                                            disabled={
                                                form.conditions.length >= 8
                                            }
                                            onClick={addCondition}
                                        >
                                            Add condition
                                        </button>
                                    </fieldset>
                                    <label className="field">
                                        <span>Documentation</span>
                                        <textarea
                                            maxLength={8192}
                                            value={form.documentation}
                                            onChange={(event) =>
                                                setForm({
                                                    ...form,
                                                    documentation:
                                                        event.target.value,
                                                })
                                            }
                                        />
                                    </label>
                                    <label className="field">
                                        <span>Change summary</span>
                                        <input
                                            required
                                            maxLength={512}
                                            value={form.change_summary}
                                            onChange={(event) =>
                                                setForm({
                                                    ...form,
                                                    change_summary:
                                                        event.target.value,
                                                })
                                            }
                                        />
                                    </label>
                                    <button
                                        className="button button--primary"
                                        type="submit"
                                        disabled={
                                            busy ||
                                            form.conditions.some(
                                                (item) => !item.value.trim(),
                                            )
                                        }
                                    >
                                        {selectedDraft
                                            ? "Save new version"
                                            : "Create draft"}
                                    </button>
                                </form>
                            ) : (
                                <p className="trust-note">
                                    Your role has read-only access to local
                                    drafts.
                                </p>
                            )}
                            {selectedDraft && (
                                <div className="draft-actions">
                                    <button
                                        className="button button--secondary"
                                        type="button"
                                        disabled={
                                            !canMutate ||
                                            busy ||
                                            selectedDraft.status !== "DRAFT"
                                        }
                                        onClick={() => {
                                            void validate();
                                        }}
                                    >
                                        Validate schema
                                    </button>
                                    <button
                                        className="button button--secondary"
                                        type="button"
                                        disabled={
                                            !canMutate ||
                                            busy ||
                                            !["VALIDATED", "TESTED"].includes(
                                                selectedDraft.status,
                                            )
                                        }
                                        onClick={() => {
                                            void test();
                                        }}
                                    >
                                        Dry-run 30 days
                                    </button>
                                </div>
                            )}
                            {dryRun && (
                                <section className="dry-run-result">
                                    <h3>Dry-run result</h3>
                                    <p>
                                        {dryRun.match_count} matches among{" "}
                                        {dryRun.evaluated_event_count} evaluated
                                        events in{" "}
                                        {dryRun.execution_ms.toFixed(2)} ms.
                                    </p>
                                    <p className="trust-note">
                                        No alerts, incidents, or notifications
                                        were generated.
                                    </p>
                                    {dryRun.matched_event_ids.map((id) => (
                                        <button
                                            className="row-link mono"
                                            type="button"
                                            onClick={() => onOpenEvent(id)}
                                            key={id}
                                        >
                                            {id}
                                        </button>
                                    ))}
                                </section>
                            )}
                            {selectedDraft?.status === "TESTED" &&
                                canMutate && (
                                    <section className="manual-deployment">
                                        <h3>Manual deployment review</h3>
                                        <label className="field field--checkbox">
                                            <span>Explicit confirmation</span>
                                            <span>
                                                <input
                                                    type="checkbox"
                                                    checked={
                                                        deploymentConfirmed
                                                    }
                                                    onChange={(event) =>
                                                        setDeploymentConfirmed(
                                                            event.target
                                                                .checked,
                                                        )
                                                    }
                                                />{" "}
                                                I understand CyberQalqon will
                                                not modify live Wazuh rules.
                                            </span>
                                        </label>
                                        <label className="field">
                                            <span>Reason</span>
                                            <input
                                                maxLength={512}
                                                value={deploymentReason}
                                                onChange={(event) =>
                                                    setDeploymentReason(
                                                        event.target.value,
                                                    )
                                                }
                                            />
                                        </label>
                                        <button
                                            className="button button--primary"
                                            type="button"
                                            disabled={
                                                busy ||
                                                !deploymentConfirmed ||
                                                !deploymentReason.trim()
                                            }
                                            onClick={() => {
                                                void confirmDeployment();
                                            }}
                                        >
                                            Record manual deployment readiness
                                        </button>
                                    </section>
                                )}
                            {selectedDraft && (
                                <section>
                                    <h3>Version history</h3>
                                    {versions.length === 0 ? (
                                        <p className="muted-copy">
                                            No version history available.
                                        </p>
                                    ) : (
                                        <ul className="audit-list">
                                            {versions.map((version) => (
                                                <li key={version.version_id}>
                                                    <div>
                                                        <strong>
                                                            Version{" "}
                                                            {
                                                                version.version_number
                                                            }
                                                        </strong>
                                                        <TimeValue
                                                            value={
                                                                version.created_at
                                                            }
                                                        />
                                                    </div>
                                                    <p>
                                                        {version.change_summary}{" "}
                                                        ·{" "}
                                                        {version.actor_display}
                                                    </p>
                                                    {canMutate &&
                                                        version.version_number !==
                                                            selectedDraft.version && (
                                                            <button
                                                                className="button button--ghost"
                                                                type="button"
                                                                disabled={busy}
                                                                onClick={() => {
                                                                    void rollback(
                                                                        version.version_number,
                                                                    );
                                                                }}
                                                            >
                                                                Restore as new
                                                                draft
                                                            </button>
                                                        )}
                                                </li>
                                            ))}
                                        </ul>
                                    )}
                                </section>
                            )}
                        </section>
                    </div>
                )}
            </section>
            {selectedRule && (
                <aside className="detail-panel" aria-label="Rule detail">
                    <header className="detail-panel__header">
                        <div>
                            <span className="eyebrow">
                                {selectedRule.management_mode}
                            </span>
                            <h2>{selectedRule.name}</h2>
                        </div>
                        <button
                            className="icon-button"
                            type="button"
                            aria-label="Close rule detail"
                            onClick={() => setSelectedRule(null)}
                        >
                            ×
                        </button>
                    </header>
                    <div className="detail-panel__body">
                        <dl className="metadata-grid">
                            <div>
                                <dt>Rule ID</dt>
                                <dd className="mono">{selectedRule.rule_id}</dd>
                            </div>
                            <div>
                                <dt>Owner</dt>
                                <dd>{selectedRule.owner ?? "Not supplied"}</dd>
                            </div>
                            <div>
                                <dt>Version</dt>
                                <dd>
                                    {selectedRule.rule_version ?? "Unavailable"}
                                </dd>
                            </div>
                            <div>
                                <dt>Enabled</dt>
                                <dd>
                                    {selectedRule.enabled_state} ·{" "}
                                    {selectedRule.enabled_evidence}
                                </dd>
                            </div>
                            <div>
                                <dt>Test record</dt>
                                <dd>{selectedRule.tested_state}</dd>
                            </div>
                            <div>
                                <dt>Alerts</dt>
                                <dd>{selectedRule.alert_count}</dd>
                            </div>
                        </dl>
                        <p>{selectedRule.description}</p>
                        {selectedRule.documentation && (
                            <p className="mono">{selectedRule.documentation}</p>
                        )}
                        <CopyButton
                            value={selectedRule.rule_id}
                            label="Copy rule ID"
                        />
                        <button
                            className="button button--primary"
                            type="button"
                            onClick={() => onOpenAlerts(selectedRule.rule_id)}
                        >
                            Open related alerts
                        </button>
                        <p className="trust-note">
                            This inventory is read-only for Wazuh rules. Version
                            is left unavailable unless an authoritative source
                            supplies it.
                        </p>
                    </div>
                </aside>
            )}
        </div>
    );
}
