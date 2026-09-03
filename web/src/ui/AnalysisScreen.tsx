import { useMemo, useState } from "react";

import type { Alert, AlertLevel } from "../analysis/alerts.js";
import { ALERT_LEVELS } from "../analysis/alerts.js";
import { ruleInventory } from "../analysis/report.js";
import type { useAnalysis } from "./use-analysis.js";

/**
 * Analysis results.
 *
 * Written so the two things that make a report defensible are visible on screen
 * and not buried in the JSON: what was checked (including checks that found
 * nothing), and which indicator set was in force. A screen that shows only
 * findings invites the reading that no findings means a clean device.
 */

type Analysis = ReturnType<typeof useAnalysis>;

const LEVEL_LABELS: Readonly<Record<AlertLevel, string>> = {
    critical: "Critical",
    high: "High",
    medium: "Medium",
    low: "Low",
    informational: "Informational",
};

/** Highest severity first, matching review order. */
const DISPLAY_LEVELS: readonly AlertLevel[] = [...ALERT_LEVELS].reverse();

export function AnalysisScreen({
    analysis,
    onBack,
}: {
    analysis: Analysis;
    onBack: () => void;
}) {
    const [levelFilter, setLevelFilter] = useState<AlertLevel | "all">("all");
    const [showRules, setShowRules] = useState(false);

    const alerts = analysis.alerts?.sorted ?? [];
    const counts = analysis.alerts?.counts;
    const rules = useMemo(() => ruleInventory(analysis.analyzers), [analysis.analyzers]);

    const visible =
        levelFilter === "all" ? alerts : alerts.filter((alert) => alert.level === levelFilter);

    const indicatorMatches = alerts.filter((alert) => alert.matchedIndicator !== undefined);

    return (
        <>
            {analysis.phase === "verifying" && (
                <div className="card">
                    <h2>Verifying archive integrity</h2>
                    <p>
                        Every entry's SHA-256 is being recomputed and compared with the archive's
                        own <code>hashes.csv</code>, before any finding is derived from it.
                    </p>
                    <p className="muted">{analysis.verifyDetail}</p>
                </div>
            )}

            {analysis.phase === "running" && analysis.progress !== undefined && (
                <div className="card">
                    <h2>Analysing</h2>
                    <div className="modules">
                        {analysis.progress.analyzers.map((analyzer) => (
                            <div key={analyzer.id} className={`module ${analyzer.status}`}>
                                <span className="glyph">{statusGlyph(analyzer.status)}</span>
                                <span>
                                    {analyzer.label}
                                    {analyzer.detail !== undefined && (
                                        <span className="detail">{analyzer.detail}</span>
                                    )}
                                </span>
                                <span className="count">{analyzer.status}</span>
                            </div>
                        ))}
                    </div>
                    <div className="actions">
                        <button className="danger" onClick={analysis.cancel}>
                            Stop analysis
                        </button>
                    </div>
                </div>
            )}

            {analysis.phase === "error" && (
                <div className="card">
                    <h2>Analysis failed</h2>
                    <div className="notice error">{analysis.error}</div>
                    <div className="actions">
                        <button onClick={onBack}>Back</button>
                    </div>
                </div>
            )}

            {analysis.verification !== undefined && (
                <IntegrityCard verification={analysis.verification} />
            )}

            {analysis.phase === "done" && counts !== undefined && (
                <>
                    <div className="card">
                        <h2>Findings</h2>

                        {alerts.length === 0 ? (
                            <div className="notice info">
                                No rule fired and no indicator matched. This is not evidence that
                                the device is uncompromised: it means none of the {rules.length}{" "}
                                conditions checked were present, and a competently implemented
                                implant leaves none of them.
                            </div>
                        ) : (
                            <div className="severity-summary">
                                {DISPLAY_LEVELS.map((level) => (
                                    <button
                                        key={level}
                                        className={`pill ${pillClass(level)}${
                                            levelFilter === level ? " selected" : ""
                                        }`}
                                        onClick={() =>
                                            setLevelFilter(levelFilter === level ? "all" : level)
                                        }
                                    >
                                        {counts[level]} {LEVEL_LABELS[level].toLowerCase()}
                                    </button>
                                ))}
                            </div>
                        )}

                        {indicatorMatches.length > 0 && (
                            <div className="notice error" style={{ marginTop: 16 }}>
                                <strong>
                                    {indicatorMatches.length} indicator{" "}
                                    {indicatorMatches.length === 1 ? "match" : "matches"} against
                                    published threat intelligence.
                                </strong>{" "}
                                These are the findings to triage first. Each cites the collection
                                and bundle it came from.
                            </div>
                        )}

                        <div className="alerts">
                            {visible.map((alert, index) => (
                                <AlertRow key={`${alert.ruleId ?? "ioc"}-${index}`} alert={alert} />
                            ))}
                        </div>
                    </div>

                    <AnalyzerCoverageCard analysis={analysis} />

                    <IndicatorSetCard analysis={analysis} />

                    <div className="card">
                        <h2>Rules in force</h2>
                        <p>
                            Every condition checked in this run, whether or not it fired. Without
                            this list, a report with no findings cannot be distinguished from a
                            report produced with an empty rule set.
                        </p>
                        <div className="actions">
                            <button onClick={() => setShowRules(!showRules)}>
                                {showRules ? "Hide" : `Show all ${rules.length} rules`}
                            </button>
                        </div>
                        {showRules && (
                            <div className="rule-list">
                                {rules.map((rule) => {
                                    const fired = alerts.some((alert) => alert.ruleId === rule.id);
                                    return (
                                        <div
                                            key={rule.id}
                                            className={fired ? "rule fired" : "rule"}
                                        >
                                            <span className={`pill ${pillClass(rule.level)}`}>
                                                {rule.level}
                                            </span>
                                            <div>
                                                <code>{rule.id}</code>
                                                <span className="detail">{rule.rationale}</span>
                                            </div>
                                            <span className="count">
                                                {fired ? "fired" : "not present"}
                                            </span>
                                        </div>
                                    );
                                })}
                            </div>
                        )}
                    </div>

                    {analysis.persisted.length > 0 && (
                        <div className="card">
                            <h2>Reports written</h2>
                            <p>
                                Analysis output has been written into the evidence store as derived
                                artifacts, alongside the collected evidence and never over it. They
                                are included in the acquisition ZIP and covered by its{" "}
                                <code>hashes.csv</code>.
                            </p>
                            <ul className="muted">
                                {analysis.persisted.map((name) => (
                                    <li key={name}>
                                        <code>{name}</code>
                                    </li>
                                ))}
                            </ul>
                        </div>
                    )}

                    <div className="actions">
                        <button onClick={onBack}>Back</button>
                    </div>
                </>
            )}
        </>
    );
}

function IntegrityCard({
    verification,
}: {
    verification: NonNullable<Analysis["verification"]>;
}) {
    return (
        <div className="card">
            <h2>Archive integrity</h2>

            {verification.status === "verified" && (
                <div className="notice ok">
                    All {verification.checked} artifacts match the SHA-256 recorded in the
                    archive's own <code>hashes.csv</code>. The archive is intact as sealed. This
                    attests to the bytes, not to what the device reported.
                </div>
            )}

            {verification.status === "unverifiable" && (
                <div className="notice warn">
                    <strong>Integrity could not be checked.</strong> {verification.reason} Findings
                    below are still derived from the content as supplied, but the archive's
                    provenance is unproven.
                </div>
            )}

            {verification.status === "failed" && (
                <div className="notice error">
                    <strong>This archive does not match its own manifest.</strong> Findings below
                    are derived from content that has changed since it was sealed and should not be
                    relied upon without explaining the discrepancy.
                </div>
            )}

            {verification.mismatches.length > 0 && (
                <>
                    <h3>Hash mismatches</h3>
                    <div className="errors">
                        {verification.mismatches.map((mismatch) => (
                            <div key={mismatch.name} className="unexpected">
                                {mismatch.name} — expected {mismatch.expected.slice(0, 16)}…, got{" "}
                                {mismatch.actual.slice(0, 16)}…
                            </div>
                        ))}
                    </div>
                </>
            )}

            {verification.missing.length > 0 && (
                <>
                    <h3>Listed in the manifest but absent</h3>
                    <div className="errors">
                        {verification.missing.map((name) => (
                            <div key={name} className="unexpected">
                                {name}
                            </div>
                        ))}
                    </div>
                </>
            )}

            {verification.unlisted.length > 0 && (
                <>
                    <h3>Present but not in the manifest</h3>
                    <p className="muted">
                        Content of unknown provenance. It is not corruption of what the manifest
                        covers, but it was not part of the sealed acquisition.
                    </p>
                    <div className="errors">
                        {verification.unlisted.map((name) => (
                            <div key={name}>{name}</div>
                        ))}
                    </div>
                </>
            )}
        </div>
    );
}

/**
 * What each analyzer actually managed to read.
 *
 * The distinction this card exists to make visible: an analyzer that found
 * nothing and an analyzer whose input was missing or unparseable both contribute
 * zero findings, and conflating them is how a tool reports a compromised device
 * as clean.
 */
function AnalyzerCoverageCard({ analysis }: { analysis: Analysis }) {
    const reports = analysis.outcome?.reports ?? [];
    const notApplicable = reports.filter((report) => report.status === "not-applicable");
    const failed = reports.filter((report) => report.status === "failed");

    return (
        <div className="card">
            <h2>Coverage</h2>

            {(notApplicable.length > 0 || failed.length > 0) && (
                <div className="notice warn">
                    Not every check ran. An analyzer whose input was absent or unreadable found
                    nothing because it could not look, which is not the same as finding nothing.
                </div>
            )}

            <div className="modules">
                {reports.map((report) => (
                    <div key={report.id} className={`module ${report.status}`}>
                        <span className="glyph">{statusGlyph(report.status)}</span>
                        <span>
                            {report.label}
                            <span className="detail">
                                {report.status === "not-applicable"
                                    ? "no matching artifact in this acquisition"
                                    : `${report.examined.length} of ${report.inputsFound.length} artifacts read, ` +
                                      `${report.alertCount} findings`}
                                {report.problems.length > 0 &&
                                    ` — ${report.problems
                                        .map((problem) => `${problem.artifact}: ${problem.problem}`)
                                        .join("; ")}`}
                            </span>
                        </span>
                        <span className="count">{report.status}</span>
                    </div>
                ))}
            </div>
        </div>
    );
}

function IndicatorSetCard({ analysis }: { analysis: Analysis }) {
    const { indicators } = analysis;
    const bundles = indicators.library.bundles;
    const unsupported = bundles.flatMap((bundle) => bundle.unsupportedPatterns);

    return (
        <div className="card">
            <h2>Indicator set</h2>

            {indicators.total === 0 ? (
                <div className="notice warn">
                    <strong>No indicator bundles were loaded.</strong> Configuration and rooting
                    checks still ran, but nothing was compared against known malware. The absence
                    of indicator matches in this report carries no information.
                </div>
            ) : (
                <p>
                    {indicators.total} indicators from {bundles.length}{" "}
                    {bundles.length === 1 ? "bundle" : "bundles"} were in force for this run.
                </p>
            )}

            {indicators.snapshot !== undefined && (
                <p className="muted">
                    Bundled snapshot pinned {indicators.snapshot.pinnedAt} from{" "}
                    {indicators.snapshot.upstream} at commit{" "}
                    <code>{indicators.snapshot.commit.slice(0, 12)}</code>.
                </p>
            )}

            {bundles.length > 0 && (
                <div className="rule-list">
                    {bundles.map((bundle) => (
                        <div key={`${bundle.filename}-${bundle.sha256}`} className="rule">
                            <span className="pill">{bundle.origin}</span>
                            <div>
                                <code>{bundle.filename}</code>
                                <span className="detail">
                                    sha256 {bundle.sha256.slice(0, 16)}… —{" "}
                                    {bundle.collections
                                        .map(
                                            (collection) =>
                                                `${collection.name} (${Object.values(
                                                    collection.counts,
                                                ).reduce((sum, count) => sum + count, 0)})`,
                                        )
                                        .join(", ")}
                                </span>
                            </div>
                            <span className="count">{bundle.total}</span>
                        </div>
                    ))}
                </div>
            )}

            {indicators.failures.length > 0 && (
                <>
                    <h3>Bundles not loaded</h3>
                    <div className="errors">
                        {indicators.failures.map((failure) => (
                            <div key={failure.filename} className="unexpected">
                                {failure.filename} — {failure.reason}
                            </div>
                        ))}
                    </div>
                </>
            )}

            {/* An indicator this reader could not interpret is a detection that
                will never fire. Reporting the count keeps that visible instead of
                letting it read as an indicator that simply did not match. */}
            {unsupported.length > 0 && (
                <>
                    <h3>Patterns not interpreted</h3>
                    <p className="muted">
                        {unsupported.length} indicator{" "}
                        {unsupported.length === 1 ? "pattern was" : "patterns were"} in a form this
                        reader does not support, so {unsupported.length === 1 ? "it" : "they"} were
                        not applied. Compound STIX expressions are the usual cause.
                    </p>
                    <div className="errors">
                        {unsupported.slice(0, 20).map((pattern, index) => (
                            <div key={`${pattern}-${index}`}>{pattern}</div>
                        ))}
                        {unsupported.length > 20 && (
                            <div className="muted">…and {unsupported.length - 20} more.</div>
                        )}
                    </div>
                </>
            )}
        </div>
    );
}

function AlertRow({ alert }: { alert: Alert }) {
    const [expanded, setExpanded] = useState(false);
    const indicator = alert.matchedIndicator;

    return (
        <div className={`alert ${alert.level}`}>
            <div className="alert-head" onClick={() => setExpanded(!expanded)}>
                <span className={`pill ${pillClass(alert.level)}`}>
                    {LEVEL_LABELS[alert.level]}
                </span>
                <span className="alert-message">{alert.message}</span>
                <span className="count">{alert.analyzer}</span>
            </div>

            {expanded && (
                <div className="alert-detail">
                    <dl className="facts">
                        {alert.ruleId !== undefined && (
                            <>
                                <dt>Rule</dt>
                                <dd>
                                    <code>{alert.ruleId}</code>
                                </dd>
                            </>
                        )}

                        {indicator !== undefined && (
                            <>
                                <dt>Indicator</dt>
                                <dd>
                                    <code>
                                        {indicator.type}={indicator.value}
                                    </code>
                                </dd>
                                <dt>Attributed to</dt>
                                <dd>{indicator.collection}</dd>
                                <dt>From bundle</dt>
                                <dd>
                                    <code>{indicator.source}</code>
                                </dd>
                            </>
                        )}

                        {alert.artifact !== undefined && (
                            <>
                                <dt>Artifact</dt>
                                <dd>
                                    <code>{alert.artifact}</code>
                                </dd>
                            </>
                        )}

                        {alert.eventTime !== undefined && (
                            <>
                                <dt>Event time</dt>
                                <dd>{alert.eventTime}</dd>
                            </>
                        )}

                        <dt>Observed</dt>
                        <dd>
                            <pre className="evidence">
                                {JSON.stringify(alert.evidence, undefined, 2)}
                            </pre>
                        </dd>
                    </dl>
                </div>
            )}
        </div>
    );
}

function pillClass(level: AlertLevel): string {
    return level === "critical" || level === "high"
        ? "error"
        : level === "medium"
          ? "warn"
          : level === "low"
            ? "warn"
            : "";
}

function statusGlyph(status: string): string {
    switch (status) {
        case "complete":
            return "✓";
        case "partial":
            return "!";
        case "not-applicable":
            return "–";
        case "failed":
            return "✕";
        case "running":
            return "…";
        default:
            return "·";
    }
}
