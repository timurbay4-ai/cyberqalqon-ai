import {
    useCallback,
    useEffect,
    useMemo,
    useState,
    type FormEvent,
} from "react";

import { CopyButton } from "../components/copy-button";
import { SeverityBadge } from "../components/severity-badge";
import { StatePanel } from "../components/state-panel";
import { TimeValue } from "../components/time-value";
import type { BackendApi } from "../types/api";
import type {
    DetectionAnalytics,
    DetectionCoverage,
    RuleConditionField,
    RuleConditionOperator,
    RuleDraft,
    RuleDraftCreate,
    RuleDraftVersion,
    RuleDryRunResult,
} from "../types/detection-engineering";
import type { DetectionRuleSummary } from "../types/siem";
import { humanize } from "../utils/format";

type Tab = "inventory" | "coverage" | "analytics" | "drafts";
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
}: {
    api: BackendApi;
    canMutate: boolean;
    onOpenAlerts(ruleId: string): void;
    onOpenEvent(eventId: string): void;
}) {
    const [tab, setTab] = useState<Tab>("inventory");
    const [rules, setRules] = useState<DetectionRuleSummary[] | null>(null);
    const [coverage, setCoverage] = useState<DetectionCoverage | null>(null);
    const [analytics, setAnalytics] = useState<DetectionAnalytics | null>(null);
    const [drafts, setDrafts] = useState<RuleDraft[]>([]);
    const [selectedRule, setSelectedRule] =
        useState<DetectionRuleSummary | null>(null);
    const [selectedDraft, setSelectedDraft] = useState<RuleDraft | null>(null);
    const [versions, setVersions] = useState<RuleDraftVersion[]>([]);
    const [dryRun, setDryRun] = useState<RuleDryRunResult | null>(null);
    const [form, setForm] = useState<RuleDraftCreate>(EMPTY_DRAFT);
    const [mitreText, setMitreText] = useState("");
    const [deploymentConfirmed, setDeploymentConfirmed] = useState(false);
    const [deploymentReason, setDeploymentReason] = useState("");
    const [search, setSearch] = useState("");
    const [rulePage, setRulePage] = useState(0);
    const [loading, setLoading] = useState(true);
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [message, setMessage] = useState<string | null>(null);
    const [revision, setRevision] = useState(0);

    const load = useCallback(async () => {
        setLoading(true);
        setError(null);
        try {
            const [nextRules, nextCoverage, nextAnalytics, nextDrafts] =
                await Promise.all([
                    api.listRules(),
                    api.getDetectionCoverage(),
                    api.getDetectionAnalytics(30),
                    api.listRuleDrafts(),
                ]);
            setRules(nextRules);
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
                            "coverage",
                            "analytics",
                            "drafts",
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
