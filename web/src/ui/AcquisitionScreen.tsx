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

export function AcquisitionScreen({
    deviceLabel,
    progress,
    error,
    onCancel,
}: AcquisitionScreenProps) {
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
                <button className="danger" onClick={onCancel}>
                    Cancel acquisition
                </button>
            </div>

            <p className="muted" style={{ marginTop: 16, marginBottom: 0 }}>
                Keep this tab open and the cable connected. Every artifact is hashed as it
                streams, then verified by re-reading it from local storage.
            </p>
        </div>
    );
}
