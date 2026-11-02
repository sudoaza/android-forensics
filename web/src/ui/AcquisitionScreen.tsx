import { useEffect, useState } from "react";

import { formatBytes, type AcquisitionProgress, type ModuleProgress } from "../acquisition/engine.js";

interface AcquisitionScreenProps {
    deviceLabel: string;
    progress: AcquisitionProgress;
    error: string | undefined;
    onCancel: () => void;
}

const GLYPHS: Record<ModuleProgress["status"], string> = {
    pending: "○",
    running: "→",
    complete: "✓",
    partial: "!",
    failed: "✕",
    skipped: "–",
};

const TERMINAL: readonly ModuleProgress["status"][] = [
    "complete",
    "partial",
    "failed",
    "skipped",
];

function formatDuration(ms: number): string {
    const seconds = Math.floor(ms / 1000);
    const minutes = Math.floor(seconds / 60);
    if (minutes === 0) {
        return `${seconds}s`;
    }
    return `${minutes}m ${String(seconds % 60).padStart(2, "0")}s`;
}

export function AcquisitionScreen({
    deviceLabel,
    progress,
    error,
    onCancel,
}: AcquisitionScreenProps) {
    const [cancelling, setCancelling] = useState(false);

    // Progress events are driven by device activity, which can be quiet for
    // tens of seconds during a large transfer. A local tick keeps the elapsed
    // clock moving so the UI never looks frozen.
    const [now, setNow] = useState(() => Date.now());
    useEffect(() => {
        const timer = setInterval(() => setNow(Date.now()), 1000);
        return () => clearInterval(timer);
    }, []);

    const finished = progress.modules.filter((module) =>
        TERMINAL.includes(module.status),
    ).length;
    const total = progress.modules.length;
    // Modules, not bytes: total volume is unknown until collection ends, and a
    // byte-based bar would jump backwards as each new artifact is discovered.
    const percent = total === 0 ? 0 : Math.round((finished / total) * 100);

    return (
        <div className="card">
            <h2>Acquiring {deviceLabel}</h2>
            <p>
                <code>{progress.acquisitionId}</code>
            </p>

            {error !== undefined && (
                <div className="notice error">
                    <strong>{error}</strong>
                </div>
            )}

            <div className="overall">
                <div className="overall-head">
                    <span>
                        {finished} of {total} modules
                    </span>
                    <span className="muted">
                        {formatDuration(now - progress.startedAtMs)} elapsed
                    </span>
                </div>
                <span className="meter large">
                    <div style={{ width: `${percent}%` }} />
                </span>
            </div>

            <div className="modules">
                {progress.modules.map((module) => (
                    <div key={module.moduleId} className={`module ${module.status}`}>
                        <span className="glyph">{GLYPHS[module.status]}</span>
                        <span>
                            {module.label}
                            {module.status === "running" && module.detail !== undefined && (
                                <span className="detail">{module.detail}</span>
                            )}
                            {module.status === "running" &&
                                module.total !== undefined &&
                                module.total > 0 && (
                                    <span className="meter">
                                        <div
                                            style={{
                                                width: `${Math.min(
                                                    100,
                                                    ((module.completed ?? 0) / module.total) * 100,
                                                )}%`,
                                            }}
                                        />
                                    </span>
                                )}
                        </span>
                        <span className="count">
                            {module.status === "running" &&
                            module.total !== undefined &&
                            module.completed !== undefined
                                ? `${module.completed} / ${module.total}`
                                : ""}
                        </span>
                    </div>
                ))}
            </div>

            <div className="totals">
                <div>
                    <div className="label">Transferred</div>
                    <div className="value">{formatBytes(progress.transferredBytes)}</div>
                </div>
                <div>
                    <div className="label">Verified</div>
                    <div className="value">{formatBytes(progress.verifiedBytes)}</div>
                </div>
                <div>
                    <div className="label">Artifacts</div>
                    <div className="value">{progress.artifactCount}</div>
                </div>
                <div>
                    <div className="label">Errors</div>
                    <div className="value">{progress.errorCount}</div>
                </div>
            </div>

            <div className="actions">
                <button
                    className="danger"
                    onClick={() => {
                        setCancelling(true);
                        onCancel();
                    }}
                    disabled={cancelling}
                >
                    {cancelling ? "Cancelling…" : "Cancel acquisition"}
                </button>
            </div>

            <p className="muted" style={{ marginTop: 16, marginBottom: 0 }}>
                {cancelling
                    ? "Finishing the artifact in flight, then writing the manifest. " +
                      "A large transfer can take some seconds to unwind; everything " +
                      "collected so far is kept."
                    : "Keep this tab open and the cable connected. Every artifact is hashed " +
                      "as it streams, then verified by re-reading it from local storage."}
            </p>
        </div>
    );
}
