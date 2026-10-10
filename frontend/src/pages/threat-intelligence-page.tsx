import {
    useCallback,
    useEffect,
    useMemo,
    useState,
    type FormEvent,
} from "react";

import { CopyButton } from "../components/copy-button";
import { StatePanel } from "../components/state-panel";
import { TimeValue } from "../components/time-value";
import type { BackendApi } from "../types/api";
import type {
    IOCDefinition,
    IOCIndicator,
    IOCMatchSummary,
    IndicatorType,
} from "../types/detection-engineering";

function failure(reason: unknown): string {
    return reason instanceof Error
        ? reason.message
        : "Threat intelligence operation failed.";
}
function download(blob: Blob, filename: string) {
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    link.click();
    URL.revokeObjectURL(url);
}

const EMPTY: IOCDefinition = {
    indicator_type: "IPV4",
    value: "",
    source: "Manual SOC review",
    confidence: 50,
    description: "",
    expires_at: null,
};

export function ThreatIntelligencePage({
    api,
    canMutate,
    onOpenEvent,
}: {
    api: BackendApi;
    canMutate: boolean;
    onOpenEvent(id: string): void;
}) {
    const [indicators, setIndicators] = useState<IOCIndicator[] | null>(null);
    const [matches, setMatches] = useState<IOCMatchSummary | null>(null);
    const [form, setForm] = useState<IOCDefinition>(EMPTY);
    const [search, setSearch] = useState("");
    const [type, setType] = useState<IndicatorType | "">("");
    const [activeOnly, setActiveOnly] = useState(false);
    const [page, setPage] = useState(0);
    const [importText, setImportText] = useState("");
    const [loading, setLoading] = useState(true);
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [message, setMessage] = useState<string | null>(null);
    const [revision, setRevision] = useState(0);

    const load = useCallback(async () => {
        setLoading(true);
        setError(null);
        try {
            const [nextIndicators, nextMatches] = await Promise.all([
                api.listIOCs({
                    indicatorType: type || undefined,
                    activeOnly,
                    search: search || undefined,
                    limit: 200,
                }),
                api.getIOCMatches(7, 500),
            ]);
            setIndicators(nextIndicators);
            setMatches(nextMatches);
            setPage(0);
        } catch (reason) {
            setError(failure(reason));
        } finally {
            setLoading(false);
        }
    }, [activeOnly, api, search, type]);
    useEffect(() => {
        void load();
    }, [load, revision]);

    const visible = useMemo(
        () => (indicators ?? []).slice(page * 25, page * 25 + 25),
        [indicators, page],
    );
    const create = async (event: FormEvent) => {
        event.preventDefault();
        setBusy(true);
        setError(null);
        setMessage(null);
        try {
            await api.createIOC(form);
            setForm(EMPTY);
            setMessage("Indicator stored and audited.");
            await load();
        } catch (reason) {
            setError(failure(reason));
        } finally {
            setBusy(false);
        }
    };
    const toggle = async (indicator: IOCIndicator) => {
        setBusy(true);
        setError(null);
        try {
            await api.updateIOC(indicator.indicator_id, {
                indicator_type: indicator.indicator_type,
                value: indicator.value,
                source: indicator.source,
                confidence: indicator.confidence,
                description: indicator.description,
                expires_at: indicator.expires_at,
                expected_version: indicator.version,
                is_active: !indicator.is_active,
            });
            await load();
        } catch (reason) {
            setError(failure(reason));
        } finally {
            setBusy(false);
        }
    };
    const importIndicators = async () => {
        setBusy(true);
        setError(null);
        setMessage(null);
        try {
            const parsed: unknown = JSON.parse(importText);
            if (
                !Array.isArray(parsed) ||
                parsed.length === 0 ||
                parsed.length > 100
            )
                throw new Error(
                    "Import must be a JSON array containing 1–100 indicators.",
                );
            const result = await api.importIOCs(parsed as IOCDefinition[]);
            setMessage(
                `Imported ${result.created}; skipped ${result.duplicates} normalized duplicates.`,
            );
            setImportText("");
            await load();
        } catch (reason) {
            setError(failure(reason));
        } finally {
            setBusy(false);
        }
    };
    const exportIndicators = async () => {
        setBusy(true);
        setError(null);
        try {
            const result = await api.downloadIOCs();
            download(result.blob, result.filename);
            setMessage("Authorized IOC export downloaded.");
        } catch (reason) {
            setError(failure(reason));
        } finally {
            setBusy(false);
        }
    };

    return (
        <div className="page-grid">
            <section className="page-column">
                <header className="page-header">
                    <div>
                        <span className="eyebrow">
                            Local threat intelligence
                        </span>
                        <h1>IOC repository</h1>
                        <p>
                            Manually curated indicators matched against
                            available normalized event fields. No external feeds
                            or blocking actions.
                        </p>
                    </div>
                    <span className="health-pill health-pill--unknown">
                        Local only
                    </span>
                </header>
                <section className="panel">
                    <div className="section-heading">
                        <div>
                            <h2>Indicator inventory</h2>
                            <p>
                                Normalization and deduplication are enforced by
                                the backend.
                            </p>
                        </div>
                        <button
                            className="button button--secondary"
                            type="button"
                            disabled={busy}
                            onClick={() => {
                                void exportIndicators();
                            }}
                        >
                            Export JSON
                        </button>
                    </div>
                    <div className="filters filters--compact">
                        <label className="field field--grow">
                            <span>Search value or source</span>
                            <input
                                type="search"
                                value={search}
                                onChange={(event) =>
                                    setSearch(event.target.value)
                                }
                            />
                        </label>
                        <label className="field">
                            <span>Type</span>
                            <select
                                value={type}
                                onChange={(event) =>
                                    setType(
                                        event.target.value as
                                            IndicatorType | "",
                                    )
                                }
                            >
                                <option value="">All types</option>
                                <option value="IPV4">IPv4</option>
                                <option value="IPV6">IPv6</option>
                                <option value="DOMAIN">Domain</option>
                                <option value="FILE_HASH">File hash</option>
                            </select>
                        </label>
                        <label className="field field--checkbox">
                            <span>State</span>
                            <span>
                                <input
                                    type="checkbox"
                                    checked={activeOnly}
                                    onChange={(event) =>
                                        setActiveOnly(event.target.checked)
                                    }
                                />{" "}
                                Active only
                            </span>
                        </label>
                    </div>
                    {loading && (
                        <StatePanel
                            kind="loading"
                            title="Loading local indicators"
                            message="Reading bounded IOC metadata and matches…"
                        />
                    )}
                    {!loading && error && !indicators && (
                        <StatePanel
                            kind="unavailable"
                            title="IOC repository unavailable"
                            message={error}
                            actionLabel="Retry"
                            onAction={() => setRevision((value) => value + 1)}
                        />
                    )}
                    {!loading && indicators?.length === 0 && (
                        <StatePanel
                            kind="empty"
                            title="No indicators"
                            message="No local IOC matches these filters."
                        />
                    )}
                    {visible.length > 0 && (
                        <div className="table-frame">
                            <table className="data-table">
                                <thead>
                                    <tr>
                                        <th>Indicator</th>
                                        <th>Type</th>
                                        <th>Confidence</th>
                                        <th>Source</th>
                                        <th>State</th>
                                        <th>Updated</th>
                                        <th>Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {visible.map((item) => (
                                        <tr key={item.indicator_id}>
                                            <td>
                                                <strong className="mono">
                                                    {item.value}
                                                </strong>
                                                <span className="cell-subtle">
                                                    {item.description ||
                                                        "No description"}
                                                </span>
                                            </td>
                                            <td>
                                                {item.indicator_type}
                                                {item.hash_algorithm
                                                    ? ` · ${item.hash_algorithm}`
                                                    : ""}
                                            </td>
                                            <td>{item.confidence}%</td>
                                            <td>{item.source}</td>
                                            <td>
                                                <span
                                                    className={`health-pill ${item.is_active && !item.expired ? "health-pill--active" : "health-pill--stale"}`}
                                                >
                                                    {item.expired
                                                        ? "Expired"
                                                        : item.is_active
                                                          ? "Active"
                                                          : "Inactive"}
                                                </span>
                                            </td>
                                            <td>
                                                <TimeValue
                                                    value={item.updated_at}
                                                    relative
                                                />
                                            </td>
                                            <td>
                                                <CopyButton
                                                    value={item.value}
                                                    label="Copy IOC value"
                                                />
                                                {canMutate && (
                                                    <button
                                                        className="button button--ghost"
                                                        type="button"
                                                        disabled={busy}
                                                        onClick={() => {
                                                            void toggle(item);
                                                        }}
                                                    >
                                                        {item.is_active
                                                            ? "Deactivate"
                                                            : "Reactivate"}
                                                    </button>
                                                )}
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    )}
                    {indicators && (
                        <footer className="pagination">
                            <span>
                                Showing {visible.length} of {indicators.length}{" "}
                                loaded indicators
                            </span>
                            <div>
                                <button
                                    className="button button--secondary"
                                    type="button"
                                    disabled={page === 0}
                                    onClick={() =>
                                        setPage((value) => value - 1)
                                    }
                                >
                                    Previous
                                </button>
                                <button
                                    className="button button--secondary"
                                    type="button"
                                    disabled={
                                        (page + 1) * 25 >= indicators.length
                                    }
                                    onClick={() =>
                                        setPage((value) => value + 1)
                                    }
                                >
                                    Next
                                </button>
                            </div>
                        </footer>
                    )}
                </section>
                {canMutate && (
                    <section className="panel">
                        <div className="section-heading">
                            <div>
                                <h2>Add indicator</h2>
                                <p>
                                    IPv4, IPv6, FQDN, MD5, SHA1, or SHA256 only.
                                </p>
                            </div>
                        </div>
                        <form className="filters" onSubmit={create}>
                            <label className="field">
                                <span>Type</span>
                                <select
                                    value={form.indicator_type}
                                    onChange={(event) =>
                                        setForm({
                                            ...form,
                                            indicator_type: event.target
                                                .value as IndicatorType,
                                        })
                                    }
                                >
                                    <option value="IPV4">IPv4</option>
                                    <option value="IPV6">IPv6</option>
                                    <option value="DOMAIN">Domain</option>
                                    <option value="FILE_HASH">File hash</option>
                                </select>
                            </label>
                            <label className="field field--grow">
                                <span>Value</span>
                                <input
                                    required
                                    maxLength={512}
                                    value={form.value}
                                    onChange={(event) =>
                                        setForm({
                                            ...form,
                                            value: event.target.value,
                                        })
                                    }
                                />
                            </label>
                            <label className="field">
                                <span>Source</span>
                                <input
                                    required
                                    maxLength={255}
                                    value={form.source}
                                    onChange={(event) =>
                                        setForm({
                                            ...form,
                                            source: event.target.value,
                                        })
                                    }
                                />
                            </label>
                            <label className="field">
                                <span>Confidence</span>
                                <input
                                    type="number"
                                    min="0"
                                    max="100"
                                    value={form.confidence}
                                    onChange={(event) =>
                                        setForm({
                                            ...form,
                                            confidence: Number(
                                                event.target.value,
                                            ),
                                        })
                                    }
                                />
                            </label>
                            <label className="field field--grow">
                                <span>Description</span>
                                <input
                                    maxLength={2048}
                                    value={form.description}
                                    onChange={(event) =>
                                        setForm({
                                            ...form,
                                            description: event.target.value,
                                        })
                                    }
                                />
                            </label>
                            <button
                                className="button button--primary"
                                disabled={
                                    busy ||
                                    !form.value.trim() ||
                                    !form.source.trim()
                                }
                                type="submit"
                            >
                                Add indicator
                            </button>
                        </form>
                    </section>
                )}
                {canMutate && (
                    <section className="panel">
                        <div className="section-heading">
                            <div>
                                <h2>Manual JSON import</h2>
                                <p>
                                    Maximum 100 validated indicators. Duplicate
                                    normalized values are skipped.
                                </p>
                            </div>
                        </div>
                        <label className="field">
                            <span>Indicator array</span>
                            <textarea
                                rows={5}
                                value={importText}
                                onChange={(event) =>
                                    setImportText(event.target.value)
                                }
                                placeholder='[{"indicator_type":"DOMAIN","value":"example.org","source":"Internal case","confidence":60}]'
                            />
                        </label>
                        <button
                            className="button button--secondary"
                            type="button"
                            disabled={busy || !importText.trim()}
                            onClick={() => {
                                void importIndicators();
                            }}
                        >
                            Import validated JSON
                        </button>
                    </section>
                )}
                <section className="panel">
                    <div className="section-heading">
                        <div>
                            <h2>Available-event matches</h2>
                            <p>
                                Last seven days; IP fields and explicitly named
                                domain/hash fields only.
                            </p>
                        </div>
                    </div>
                    {matches?.matches.length ? (
                        <ul className="audit-list">
                            {matches.matches.map((match) => (
                                <li
                                    key={`${match.indicator_id}-${match.event_id}-${match.matched_field}`}
                                >
                                    <div>
                                        <strong>{match.value}</strong>
                                        <TimeValue
                                            value={match.event_timestamp}
                                        />
                                    </div>
                                    <p>
                                        {match.matched_field} ·{" "}
                                        <button
                                            className="row-link mono"
                                            type="button"
                                            onClick={() =>
                                                onOpenEvent(match.event_id)
                                            }
                                        >
                                            {match.event_id}
                                        </button>
                                    </p>
                                </li>
                            ))}
                        </ul>
                    ) : (
                        <p className="muted-copy">
                            No IOC matches in available event fields.
                        </p>
                    )}
                    {matches?.truncated && (
                        <p className="trust-note">
                            Results are truncated at the configured bound.
                        </p>
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
            </section>
        </div>
    );
}
