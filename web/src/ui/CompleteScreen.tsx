import { useMemo, useState } from "react";

import { formatBytes } from "../acquisition/engine.js";
import type { AcquisitionSummary } from "../acquisition/manifest.js";
import { exportArchive, planArchive } from "../evidence/package-zip.js";
import { EvidenceStore } from "../evidence/store.js";

interface CompleteScreenProps {
    summary: AcquisitionSummary;
    store: EvidenceStore;
    /** Non-null when the run failed after artifacts were already spooled. */
    runError: string | undefined;
    /** Drives the caveat about analysing with no indicators loaded. */
    indicatorCount: number;
    /** Suppresses that caveat while the bundled snapshot is still loading. */
    indicatorsLoading: boolean;
    /**
     * Analysis reports already written into the store.
     *
     * Passed in rather than read from the store so the archive is re-planned when
     * analysis adds artifacts. Without it the plan would be a snapshot taken
     * before analysis ran, and the reports would be missing from both the ZIP and
     * its `hashes.csv`.
     */
    persistedReports: readonly string[];
    onAnalyse: () => void;
    onDisconnect: () => void;
    onReset: () => void;
}

export function CompleteScreen({
    summary,
    store,
    runError,
    indicatorCount,
    indicatorsLoading,
    persistedReports,
    onAnalyse,
    onDisconnect,
    onReset,
}: CompleteScreenProps) {
    const [exporting, setExporting] = useState<string | undefined>(undefined);
    const [exported, setExported] = useState(false);
    const [exportError, setExportError] = useState<string | undefined>(undefined);
    const [discarded, setDiscarded] = useState(false);
    /**
     * Artifact names as of the last export, so a download taken before analysis
     * can be identified as stale rather than presumed complete.
     */
    const [exportedNames, setExportedNames] = useState<readonly string[]>([]);

    // Planned from the store's live records, not from the acquisition summary, so
    // artifacts written after collection — the analysis reports — are included in
    // the archive and covered by its hashes.csv. `persistedReports` is in the
    // dependency list because it is what changes when that happens.
    const plan = useMemo(
        () => planArchive(summary.acquisitionId, store.records),
        [summary.acquisitionId, store, persistedReports],
    );

    const collectedCount = summary.artifacts.length;
    const addedByAnalysis = plan.entries.filter(
        (entry) => !summary.artifacts.some((artifact) => artifact.name === entry.name),
    );

    const staleExport = plan.entries.some((entry) => !exportedNames.includes(entry.name));

    const allErrors = summary.modules.flatMap((module) =>
        module.errors.map((error) => ({ module: module.id, ...error })),
    );
    const unexpectedErrors = allErrors.filter((error) => !error.expected);
    const allVerified = summary.artifacts.every((artifact) => artifact.verified);
    const truncatedArtifacts = summary.artifacts.filter(
        (artifact) => artifact.truncated === true,
    );

    const onExport = async (): Promise<void> => {
        setExportError(undefined);
        setExporting("Packaging…");
        try {
            let entryLabel = "";
            const { method } = await exportArchive(
                store,
                plan,
                (name, index, total) => {
                    entryLabel = `Packaging ${index + 1} / ${total}: ${name}`;
                    setExporting(entryLabel);
                },
                (bytes) => {
                    // Against the planned total, so the examiner can see the
                    // export advancing through a single very large artifact.
                    const percent =
                        plan.totalBytes === 0
                            ? 0
                            : Math.min(100, Math.round((bytes / plan.totalBytes) * 100));
                    setExporting(`${entryLabel} — ${formatBytes(bytes)} (${percent}%)`);
                },
            );
            setExported(true);
            setExportedNames(plan.entries.map((entry) => entry.name));
            if (method === "blob-download") {
                setExportError(
                    "Packaged in memory because this browser lacks the File System Access API. " +
                        "Large acquisitions may fail this way; prefer Chrome, Chromium, or Edge.",
                );
            }
        } catch (error) {
            setExportError(error instanceof Error ? error.message : String(error));
        } finally {
            setExporting(undefined);
        }
    };

    const onDiscard = async (): Promise<void> => {
        await EvidenceStore.discard(summary.acquisitionId);
        setDiscarded(true);
    };

    return (
        <>
            <div className="card">
                <h2>
                    {summary.cancelled ? "Acquisition incomplete" : "Acquisition complete"}
                </h2>
                <p>
                    {summary.device.manufacturer ?? ""} {summary.device.model ?? ""} —{" "}
                    {summary.device.serial}
                </p>

                {summary.cancelled && (
                    <div className="notice warn">
                        <strong>
                            {summary.abortReason ?? "Acquisition was stopped before completion."}
                        </strong>{" "}
                        Artifacts collected before the interruption are complete and verified;
                        remaining modules were not run. The manifest records this.
                    </div>
                )}

                {runError !== undefined && (
                    <div className="notice error">
                        <strong>The acquisition did not finish cleanly: {runError}</strong>
                        <p style={{ margin: "8px 0 0" }}>
                            Artifacts already collected are complete and hash-verified, and can
                            still be exported. Do this before discarding the local copy.
                        </p>
                    </div>
                )}

                <dl className="facts">
                    <dt>Acquisition ID</dt>
                    <dd>{summary.acquisitionId}</dd>

                    <dt>Profile</dt>
                    <dd>{summary.profile}</dd>

                    <dt>Started</dt>
                    <dd>{summary.startedAt}</dd>

                    <dt>Completed</dt>
                    <dd>{summary.completedAt}</dd>

                    <dt>Artifacts</dt>
                    <dd>
                        {collectedCount} collected
                        {addedByAnalysis.length > 0 && (
                            <>
                                {", "}
                                {addedByAnalysis.length} derived by analysis
                                <div className="muted" style={{ marginTop: 6 }}>
                                    {addedByAnalysis.map((entry) => entry.name).join(", ")}. These
                                    are analysis output, not device data. They are included in the
                                    archive and covered by its <code>hashes.csv</code>.
                                </div>
                            </>
                        )}
                    </dd>

                    <dt>Total size</dt>
                    <dd>{formatBytes(plan.totalBytes)}</dd>

                    <dt>Clock offset</dt>
                    <dd>
                        {summary.clockStart.error === undefined ? (
                            <>
                                {`${summary.clockStart.bestOffsetMs} ms (device − host, ` +
                                    `${summary.clockStart.bestRoundTripMs} ms RTT)`}
                                {/* The offset is only meaningful to within about
                                    half the round trip, so a slow sample must not
                                    be read as a precise measurement. */}
                                {summary.clockStart.bestRoundTripMs > 500 && (
                                    <span className="pill warn" style={{ marginLeft: 8 }}>
                                        low confidence: ±
                                        {Math.round(summary.clockStart.bestRoundTripMs / 2)} ms
                                    </span>
                                )}
                            </>
                        ) : (
                            summary.clockStart.error
                        )}
                    </dd>

                    {truncatedArtifacts.length > 0 && (
                        <>
                            <dt>Truncated</dt>
                            <dd>
                                <span className="pill warn">
                                    {truncatedArtifacts.length} artifact
                                    {truncatedArtifacts.length === 1 ? "" : "s"} capped
                                </span>
                                <div className="muted" style={{ marginTop: 6 }}>
                                    {truncatedArtifacts
                                        .map(
                                            (artifact) =>
                                                `${artifact.name} (capped at ` +
                                                `${formatBytes(artifact.truncatedAt ?? 0)})`,
                                        )
                                        .join(", ")}
                                    . Hashes cover the stored bytes exactly, but these
                                    artifacts are not the complete source.
                                </div>
                            </dd>
                        </>
                    )}

                    <dt>Hash verification</dt>
                    <dd>
                        <span className={allVerified ? "pill ok" : "pill error"}>
                            {allVerified
                                ? "all artifacts verified"
                                : "verification failure — see below"}
                        </span>
                    </dd>

                    <dt>Errors</dt>
                    <dd>
                        <span className={unexpectedErrors.length === 0 ? "pill ok" : "pill warn"}>
                            {allErrors.length} total, {unexpectedErrors.length} unexpected
                        </span>
                    </dd>
                </dl>

                {allVerified && (
                    <div className="notice info" style={{ marginTop: 20 }}>
                        Each artifact was hashed while streaming from the device, then verified by
                        re-reading the stored bytes and hashing again independently. Both digests
                        matched for every artifact. This proves the bytes were stored intact; it
                        does not attest to what the device reported.
                    </div>
                )}

                <div className="actions">
                    <button className="primary" onClick={onAnalyse}>
                        {persistedReports.length > 0 ? "Re-run analysis" : "Analyse this acquisition"}
                    </button>
                    <button
                        disabled={exporting !== undefined || discarded}
                        onClick={() => void onExport()}
                    >
                        {exporting ?? (exported ? "Download again" : "Download acquisition ZIP")}
                    </button>
                    {/* Discard stays disabled until export succeeds, and until
                        that export covers everything currently in the store: this
                        is the only copy of the evidence. */}
                    <button
                        className="danger"
                        disabled={!exported || staleExport || discarded}
                        title={
                            exported
                                ? staleExport
                                    ? "The last download predates the current analysis. Download again first."
                                    : undefined
                                : "Export the acquisition first"
                        }
                        onClick={() => void onDiscard()}
                    >
                        Discard local copy
                    </button>
                    <button onClick={onDisconnect}>Disconnect device</button>
                    <button onClick={onReset}>New acquisition</button>
                </div>

                {/* Analysis writes its reports into the store, so an export taken
                    before it ran does not contain them. Saying so is necessary:
                    otherwise the examiner keeps a ZIP they believe is complete. */}
                {exported && staleExport && (
                    <div className="notice warn" style={{ marginTop: 16, marginBottom: 0 }}>
                        The archive was downloaded before the current analysis ran, so it does not
                        contain the analysis reports. Download it again to include them.
                    </div>
                )}

                {indicatorCount === 0 && !indicatorsLoading && (
                    <div className="notice warn" style={{ marginTop: 16, marginBottom: 0 }}>
                        No indicator bundles are loaded, so analysis will check configuration and
                        rooting but will not compare anything against known malware. Load bundles
                        from the start screen first if malware triage is in scope.
                    </div>
                )}

                {exportError !== undefined && (
                    <div className="notice warn" style={{ marginTop: 16, marginBottom: 0 }}>
                        {exportError}
                    </div>
                )}

                {discarded && (
                    <div className="notice info" style={{ marginTop: 16, marginBottom: 0 }}>
                        The local copy has been deleted from browser storage.
                    </div>
                )}
            </div>

            <div className="card">
                <h2>Cross-checking with MVT</h2>
                <p>
                    Analysis is built in and runs in this browser, so MVT is no longer required.
                    The archive does still use AndroidQF-compatible artifact names, so an examiner
                    who wants a second, independently implemented opinion can run:
                </p>
                <pre
                    style={{
                        fontFamily: "var(--mono)",
                        fontSize: 12,
                        background: "var(--bg)",
                        border: "1px solid var(--border)",
                        borderRadius: 6,
                        padding: 12,
                        overflowX: "auto",
                        margin: 0,
                    }}
                >
                    mvt-android check-androidqf {plan.filename}
                </pre>
                <p className="muted" style={{ marginTop: 12, marginBottom: 0 }}>
                    Corroboration by a separate tool is worth having, and the two will not agree
                    exactly: the rule sets are independent implementations, and MVT reports on
                    artifacts this collector does not gather.
                </p>
            </div>

            <div className="card">
                <h2>Module results</h2>
                <div className="modules">
                    {summary.modules.map((module) => (
                        <div key={module.id} className={`module ${module.status}`}>
                            <span className="glyph">
                                {module.status === "complete"
                                    ? "✓"
                                    : module.status === "partial"
                                      ? "!"
                                      : module.status === "skipped"
                                        ? "–"
                                        : "✕"}
                            </span>
                            <span>
                                {module.label}
                                <span className="detail">
                                    {module.artifacts.length} artifacts, {module.errors.length}{" "}
                                    errors, {module.durationMs} ms
                                </span>
                            </span>
                            <span className="count">{module.status}</span>
                        </div>
                    ))}
                </div>
            </div>

            {allErrors.length > 0 && (
                <div className="card">
                    <h2>Recorded errors</h2>
                    <p>
                        Permission denials and missing paths are normal on a production build and
                        are preserved in the manifest as findings. Unexpected errors are
                        highlighted.
                    </p>
                    <div className="errors">
                        {allErrors.map((error, index) => (
                            <div
                                key={`${error.module}-${error.artifact}-${index}`}
                                className={error.expected ? undefined : "unexpected"}
                            >
                                [{error.module}] {error.artifact} — {error.error}
                            </div>
                        ))}
                    </div>
                </div>
            )}
        </>
    );
}
