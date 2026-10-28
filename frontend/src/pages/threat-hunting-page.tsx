import { useCallback, useEffect, useState, type FormEvent } from "react";

import { CopyButton } from "../components/copy-button";
import { SeverityBadge } from "../components/severity-badge";
import { StatePanel } from "../components/state-panel";
import { TimeValue } from "../components/time-value";
import type { BackendApi } from "../types/api";
import type {
    SavedHunt,
    ThreatHuntPage as HuntPage,
    ThreatHuntQuery,
} from "../types/detection-engineering";

const EMPTY_QUERY: ThreatHuntQuery = {
    relativeMinutes: 1440,
    sort: "newest",
    limit: 50,
};

function failure(reason: unknown): string {
    return reason instanceof Error ? reason.message : "Threat hunt failed.";
}

function download(blob: Blob, filename: string) {
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    link.click();
    URL.revokeObjectURL(url);
}

function safeLocation(query: ThreatHuntQuery) {
    const url = new URL(window.location.href);
    url.search = "";
    url.searchParams.set("view", "hunting");
    if (query.relativeMinutes)
        url.searchParams.set("range", String(query.relativeMinutes));
    if (query.eventCategory)
        url.searchParams.set("category", query.eventCategory);
    if (query.ruleId) url.searchParams.set("rule_id", query.ruleId);
    if (query.mitreId) url.searchParams.set("mitre_id", query.mitreId);
    window.history.pushState({ cyberqalqonHunt: query }, "", url);
}

export function ThreatHuntingPage({
    api,
    canMutate,
    onOpenEvent,
    onOpenAlert,
    onOpenIncident,
}: {
    api: BackendApi;
    canMutate: boolean;
    onOpenEvent(id: string): void;
    onOpenAlert(id: string): void;
    onOpenIncident(id: string): void;
}) {
    const [draft, setDraft] = useState<ThreatHuntQuery>(EMPTY_QUERY);
    const [query, setQuery] = useState<ThreatHuntQuery>(EMPTY_QUERY);
    const [page, setPage] = useState<HuntPage | null>(null);
    const [saved, setSaved] = useState<SavedHunt[]>([]);
    const [savedName, setSavedName] = useState("");
    const [cursorHistory, setCursorHistory] = useState<
        Array<string | undefined>
    >([]);
    const [loading, setLoading] = useState(true);
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [message, setMessage] = useState<string | null>(null);
    const [revision, setRevision] = useState(0);

    const loadSaved = useCallback(async () => {
        try {
            setSaved(await api.listSavedHunts());
        } catch {
            setSaved([]);
        }
    }, [api]);

    useEffect(() => {
        void loadSaved();
    }, [loadSaved]);
    useEffect(() => {
        const controller = new AbortController();
        setLoading(true);
        setError(null);
        api.runThreatHunt(query, controller.signal)
            .then(setPage)
            .catch((reason: unknown) => {
                if (!(
                    reason instanceof DOMException &&
                    reason.name === "AbortError"
                ))
                    setError(failure(reason));
            })
            .finally(() => setLoading(false));
        return () => controller.abort();
    }, [api, query, revision]);

    useEffect(() => {
        const restore = (event: PopStateEvent) => {
            const restored = (
                event.state as { cyberqalqonHunt?: ThreatHuntQuery } | null
            )?.cyberqalqonHunt;
            if (restored) {
                setDraft(restored);
                setQuery(restored);
                setCursorHistory([]);
            }
        };
        window.addEventListener("popstate", restore);
        return () => window.removeEventListener("popstate", restore);
    }, []);

    const apply = (event: FormEvent) => {
        event.preventDefault();
        const next = { ...draft, cursor: undefined };
        setCursorHistory([]);
        setQuery(next);
        safeLocation(next);
    };
    const reset = () => {
        setDraft(EMPTY_QUERY);
        setQuery(EMPTY_QUERY);
        setCursorHistory([]);
        safeLocation(EMPTY_QUERY);
    };
    const save = async () => {
        setBusy(true);
        setError(null);
        try {
            await api.saveThreatHunt(savedName.trim(), {
                ...query,
                cursor: undefined,
            });
            setSavedName("");
            setMessage("Hunt query saved for your analyst account.");
            await loadSaved();
        } catch (reason) {
            setError(failure(reason));
        } finally {
            setBusy(false);
        }
    };
    const remove = async (id: string) => {
        if (!window.confirm("Delete this saved hunt?")) return;
        setBusy(true);
        try {
            await api.deleteSavedHunt(id);
            await loadSaved();
        } catch (reason) {
            setError(failure(reason));
        } finally {
            setBusy(false);
        }
    };
    const exportResults = async () => {
        setBusy(true);
        setError(null);
        try {
            const result = await api.downloadThreatHunt({
                ...query,
                cursor: undefined,
            });
            download(result.blob, result.filename);
            setMessage("Authorized hunt export downloaded.");
        } catch (reason) {
            setError(failure(reason));
        } finally {
            setBusy(false);
        }
    };
    const next = () => {
        if (!page?.next_cursor) return;
        setCursorHistory((items) => [...items, query.cursor]);
        setQuery((current) => ({
            ...current,
            cursor: page.next_cursor ?? undefined,
        }));
    };
    const previous = () => {
        if (!cursorHistory.length) return;
        const history = [...cursorHistory];
        const cursor = history.pop();
        setCursorHistory(history);
        setQuery((current) => ({ ...current, cursor }));
    };

    return (
        <div className="page-grid">
            <section className="page-column">
                <header className="page-header">
                    <div>
                        <span className="eyebrow">Threat hunting</span>
                        <h1>Historical investigation</h1>
                        <p>
                            Run bounded searches over the existing normalized
                            event store. Hunts never create alerts or incidents.
                        </p>
                    </div>
                    <span className="health-pill health-pill--unknown">
                        Read-only evaluation
                    </span>
                </header>
                <form
                    className="panel hunt-filters"
                    aria-label="Threat hunt filters"
                    onSubmit={apply}
                >
                    <label className="field">
                        <span>Time range</span>
                        <select
                            value={draft.relativeMinutes ?? 1440}
                            onChange={(event) =>
                                setDraft({
                                    ...draft,
                                    relativeMinutes: Number(
                                        event.target.value,
                                    ) as ThreatHuntQuery["relativeMinutes"],
                                })
                            }
                        >
                            <option value="15">15 minutes</option>
                            <option value="60">1 hour</option>
                            <option value="1440">24 hours</option>
                            <option value="10080">7 days</option>
                            <option value="43200">30 days</option>
                        </select>
                    </label>
                    <label className="field">
                        <span>Any IP</span>
                        <input
                            aria-label="Any IP"
                            value={draft.ip ?? ""}
                            maxLength={64}
                            onChange={(event) =>
                                setDraft({
                                    ...draft,
                                    ip: event.target.value || undefined,
                                })
                            }
                            placeholder="192.0.2.10"
                        />
                    </label>
                    <label className="field">
                        <span>Host</span>
                        <input
                            value={draft.hostname ?? ""}
                            maxLength={255}
                            onChange={(event) =>
                                setDraft({
                                    ...draft,
                                    hostname: event.target.value || undefined,
                                })
                            }
                        />
                    </label>
                    <label className="field">
                        <span>Username</span>
                        <input
                            value={draft.username ?? ""}
                            maxLength={512}
                            onChange={(event) =>
                                setDraft({
                                    ...draft,
                                    username: event.target.value || undefined,
                                })
                            }
                        />
                    </label>
                    <label className="field">
                        <span>Category</span>
                        <input
                            value={draft.eventCategory ?? ""}
                            maxLength={255}
                            onChange={(event) =>
                                setDraft({
                                    ...draft,
                                    eventCategory:
                                        event.target.value || undefined,
                                })
                            }
                        />
                    </label>
                    <label className="field">
                        <span>Rule ID</span>
                        <input
                            value={draft.ruleId ?? ""}
                            maxLength={128}
                            onChange={(event) =>
                                setDraft({
                                    ...draft,
                                    ruleId: event.target.value || undefined,
                                })
                            }
                        />
                    </label>
                    <label className="field">
                        <span>MITRE technique</span>
                        <input
                            value={draft.mitreId ?? ""}
                            maxLength={16}
                            onChange={(event) =>
                                setDraft({
                                    ...draft,
                                    mitreId: event.target.value || undefined,
                                })
                            }
                            placeholder="T1046"
                        />
                    </label>
                    <label className="field field--grow">
                        <span>Evidence text</span>
                        <input
                            type="search"
                            value={draft.search ?? ""}
                            maxLength={200}
                            onChange={(event) =>
                                setDraft({
                                    ...draft,
                                    search: event.target.value || undefined,
                                })
                            }
                        />
                    </label>
                    <label className="field field--grow">
                        <span>CQQL refinement</span>
                        <textarea
                            aria-label="CQQL refinement"
                            value={draft.cqql ?? ""}
                            rows={3}
                            maxLength={2000}
                            onChange={(event) =>
                                setDraft({
                                    ...draft,
                                    cqql: event.target.value || undefined,
                                })
                            }
                            placeholder={'event.code = "4625" AND event.severity >= 5'}
                        />
                        <small>Combined with the bounded hunt filters. Matches remain analyst hypotheses, not detections.</small>
                    </label>
                    <div className="filter-actions">
                        <button
                            className="button button--primary"
                            type="submit"
                        >
                            Run hunt
                        </button>
                        <button
                            className="button button--ghost"
                            type="button"
                            onClick={reset}
                        >
                            Reset
                        </button>
                        <button
                            className="button button--secondary"
                            type="button"
                            disabled={busy || !page}
                            onClick={() => {
                                void exportResults();
                            }}
                        >
                            Export CSV
                        </button>
                    </div>
                </form>
                <section className="panel saved-hunts">
                    <div className="section-heading">
                        <div>
                            <h2>Saved hunts</h2>
                            <p>Private to the authenticated analyst.</p>
                        </div>
                    </div>
                    <div className="inline-form">
                        <label className="field field--grow">
                            <span>Save current hunt as</span>
                            <input
                                value={savedName}
                                maxLength={100}
                                onChange={(event) =>
                                    setSavedName(event.target.value)
                                }
                            />
                        </label>
                        <button
                            className="button button--secondary"
                            type="button"
                            disabled={!canMutate || busy || !savedName.trim()}
                            onClick={() => {
                                void save();
                            }}
                        >
                            Save hunt
                        </button>
                    </div>
                    {saved.length === 0 ? (
                        <p className="muted-copy">No saved hunts.</p>
                    ) : (
                        <ul className="saved-hunt-list">
                            {saved.map((item) => (
                                <li key={item.saved_hunt_id}>
                                    <button
                                        className="row-link"
                                        type="button"
                                        onClick={() => {
                                            setDraft(item.query);
                                            setQuery(item.query);
                                            setCursorHistory([]);
                                            safeLocation(item.query);
                                        }}
                                    >
                                        {item.name}
                                    </button>
                                    <TimeValue
                                        value={item.updated_at}
                                        relative
                                    />
                                    {canMutate && (
                                        <button
                                            className="button button--ghost"
                                            type="button"
                                            disabled={busy}
                                            onClick={() => {
                                                void remove(item.saved_hunt_id);
                                            }}
                                        >
                                            Delete
                                        </button>
                                    )}
                                </li>
                            ))}
                        </ul>
                    )}
                </section>
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
                        title="Running bounded hunt"
                        message="Searching persisted security events…"
                    />
                )}
                {!loading && error && !page && (
                    <StatePanel
                        kind="unavailable"
                        title="Threat hunt unavailable"
                        message={error}
                        actionLabel="Retry"
                        onAction={() => setRevision((value) => value + 1)}
                    />
                )}
                {!loading && page && page.items.length === 0 && (
                    <StatePanel
                        kind="empty"
                        title="No matching evidence"
                        message="No persisted event matches the current bounded hunt."
                    />
                )}
                {!loading && page && page.items.length > 0 && (
                    <div className="table-frame">
                        <table className="data-table hunt-table">
                            <thead>
                                <tr>
                                    <th>Time</th>
                                    <th>Evidence</th>
                                    <th>Host</th>
                                    <th>Network / identity</th>
                                    <th>Rule</th>
                                    <th>Relationships</th>
                                </tr>
                            </thead>
                            <tbody>
                                {page.items.map((item) => (
                                    <tr key={item.event_id}>
                                        <td>
                                            <button
                                                className="row-link"
                                                type="button"
                                                onClick={() =>
                                                    onOpenEvent(item.event_id)
                                                }
                                            >
                                                <TimeValue
                                                    value={item.timestamp}
                                                />
                                            </button>
                                            <CopyButton
                                                value={item.event_id}
                                                label="Copy event ID"
                                            />
                                        </td>
                                        <td>
                                            <strong>{item.message}</strong>
                                            <span className="cell-subtle">
                                                {item.source_type} ·{" "}
                                                {item.event_category ??
                                                    "uncategorized"}
                                            </span>
                                        </td>
                                        <td>{item.hostname ?? "—"}</td>
                                        <td>
                                            <span>
                                                {item.source_ip ??
                                                    item.destination_ip ??
                                                    item.username ??
                                                    "—"}
                                            </span>
                                        </td>
                                        <td>
                                            {item.severity == null ? null : (
                                                <SeverityBadge
                                                    level={item.severity}
                                                />
                                            )}
                                            <span className="mono">
                                                {item.rule_id ?? "—"}
                                            </span>
                                        </td>
                                        <td>
                                            {item.related_alert_id && (
                                                <button
                                                    className="button button--secondary"
                                                    type="button"
                                                    onClick={() =>
                                                        onOpenAlert(
                                                            item.related_alert_id!,
                                                        )
                                                    }
                                                >
                                                    Alert
                                                </button>
                                            )}
                                            {item.related_incident_ids.map(
                                                (id) => (
                                                    <button
                                                        className="button button--secondary"
                                                        type="button"
                                                        onClick={() =>
                                                            onOpenIncident(id)
                                                        }
                                                        key={id}
                                                    >
                                                        Incident
                                                    </button>
                                                ),
                                            )}
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}
                {page && (
                    <footer className="pagination">
                        <span>
                            Showing {page.items.length} of {page.total} matching
                            events
                        </span>
                        <div>
                            <button
                                className="button button--secondary"
                                type="button"
                                disabled={!cursorHistory.length || loading}
                                onClick={previous}
                            >
                                Previous
                            </button>
                            <button
                                className="button button--secondary"
                                type="button"
                                disabled={!page.next_cursor || loading}
                                onClick={next}
                            >
                                Next
                            </button>
                        </div>
                    </footer>
                )}
            </section>
        </div>
    );
}
