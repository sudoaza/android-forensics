import { useState } from "react";

import { formatBytes } from "../acquisition/engine.js";
import type { AcquisitionSummary } from "../acquisition/manifest.js";
import { exportArchive, planArchive } from "../evidence/package-zip.js";
import { EvidenceStore } from "../evidence/store.js";

interface CompleteScreenProps {
    summary: AcquisitionSummary;
    store: EvidenceStore;
    /** Non-null when the run failed after artifacts were already spooled. */
    runError: string | undefined;
    onDisconnect: () => void;
    onReset: () => void;
}

export function CompleteScreen({
    summary,
    store,
    runError,
    onDisconnect,
    onReset,
}: CompleteScreenProps) {
    const [exporting, setExporting] = useState<string | undefined>(undefined);
    const [exported, setExported] = useState(false);
    const [exportError, setExportError] = useState<string | undefined>(undefined);
    const [discarded, setDiscarded] = useState(false);

    const plan = planArchive(summary.acquisitionId, summary.artifacts);

    const allErrors = summary.modules.flatMap((module) =>
        module.errors.map((error) => ({ module: module.id, ...error })),
    );
    const unexpectedErrors = allErrors.filter((error) => !error.expected);
    const allVerified = summary.artifacts.every((artifact) => artifact.verified);

    const onExport = async (): Promise<void> => {
        setExportError(undefined);
        setExporting("Packaging…");
        try {
            const { method } = await exportArchive(store, plan, (name, index, total) => {
                setExporting(`Packaging ${index + 1} / ${total}: ${name}`);
            });
            setExported(true);
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
                    <dd>{summary.artifacts.length}</dd>

                    <dt>Total size</dt>
                    <dd>{formatBytes(plan.totalBytes)}</dd>

                    <dt>Clock offset</dt>
                    <dd>
                        {summary.clockStart.error === undefined
                            ? `${summary.clockStart.bestOffsetMs} ms (device − host, ` +
                              `${summary.clockStart.bestRoundTripMs} ms RTT)`
                            : summary.clockStart.error}
                    </dd>

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
                    <button
                        className="primary"
                        disabled={exporting !== undefined || discarded}
                        onClick={() => void onExport()}
                    >
                        {exporting ?? (exported ? "Download again" : "Download acquisition ZIP")}
                    </button>
                    {/* Discard stays disabled until export succeeds: this is the
                        only copy of the evidence. */}
                    <button
                        className="danger"
                        disabled={!exported || discarded}
                        title={exported ? undefined : "Export the acquisition first"}
                        onClick={() => void onDiscard()}
                    >
                        Discard local copy
                    </button>
                    <button onClick={onDisconnect}>Disconnect device</button>
                    <button onClick={onReset}>New acquisition</button>
                </div>

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
                <h2>Analyse with MVT</h2>
                <p>
                    The archive uses AndroidQF-compatible artifact names, so MVT can consume it
                    directly:
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
                    MVT will report modules it does not recognize. Compatibility is being built
                    artifact-by-artifact and is not yet complete.
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
