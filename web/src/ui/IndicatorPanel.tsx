import { useRef } from "react";

import type { useAnalysis } from "./use-analysis.js";

/**
 * Indicator loading and the analyse-an-existing-archive entry point.
 *
 * Both live on the connect screen because neither needs a device: an examiner
 * re-running analysis against an updated indicator set, or triaging an archive
 * collected on another workstation, has no phone to plug in.
 */

export function IndicatorPanel({
    analysis,
    onAnalyseArchive,
}: {
    analysis: ReturnType<typeof useAnalysis>;
    onAnalyseArchive: (file: File) => void;
}) {
    const bundleInput = useRef<HTMLInputElement>(null);
    const archiveInput = useRef<HTMLInputElement>(null);

    const { indicators } = analysis;

    return (
        <div className="card">
            <h2>Analysis</h2>
            <p>
                Analysis runs in this browser, against rules and indicators held locally. No data
                about the device or the case leaves this machine, and no indicator is fetched from a
                third party at run time.
            </p>

            <dl className="facts">
                <dt>Indicators loaded</dt>
                <dd>
                    {indicators.loading ? (
                        <span className="pill">loading…</span>
                    ) : (
                        <span className={indicators.total === 0 ? "pill warn" : "pill ok"}>
                            {indicators.total} from {indicators.library.bundles.length}{" "}
                            {indicators.library.bundles.length === 1 ? "bundle" : "bundles"}
                        </span>
                    )}
                    {/* Only stated once the load has settled: during it the count
                        is legitimately zero, and saying detection is unavailable
                        would be false. */}
                    {!indicators.loading && indicators.total === 0 && (
                        <div className="muted" style={{ marginTop: 6 }}>
                            Configuration and rooting checks work without indicators. Known-malware
                            detection does not: with none loaded, the absence of matches means
                            nothing.
                        </div>
                    )}
                </dd>

                {indicators.snapshot !== undefined && (
                    <>
                        <dt>Bundled set</dt>
                        <dd className="muted">
                            pinned {indicators.snapshot.pinnedAt}, commit{" "}
                            <code>{indicators.snapshot.commit.slice(0, 12)}</code>
                        </dd>
                    </>
                )}
            </dl>

            <div className="actions">
                <button onClick={() => bundleInput.current?.click()}>
                    Add indicator bundles (STIX2)
                </button>
                <button onClick={() => archiveInput.current?.click()}>
                    Analyse an existing archive
                </button>
            </div>

            {/* Directory selection is offered as well as individual files:
                indicator sets are normally distributed as a directory of
                bundles, and picking them one at a time is error-prone. */}
            <input
                ref={bundleInput}
                type="file"
                accept=".stix2,.json"
                multiple
                hidden
                onChange={(event) => {
                    const files = [...(event.target.files ?? [])];
                    if (files.length > 0) {
                        void analysis.addIndicatorFiles(files);
                    }
                    event.target.value = "";
                }}
            />

            <input
                ref={archiveInput}
                type="file"
                accept=".zip"
                hidden
                onChange={(event) => {
                    const file = event.target.files?.[0];
                    if (file !== undefined) {
                        onAnalyseArchive(file);
                    }
                    event.target.value = "";
                }}
            />

            {indicators.failures.length > 0 && (
                <div className="notice warn" style={{ marginTop: 16, marginBottom: 0 }}>
                    <strong>
                        {indicators.failures.length}{" "}
                        {indicators.failures.length === 1 ? "bundle" : "bundles"} could not be
                        loaded:
                    </strong>
                    <div className="errors" style={{ marginTop: 8 }}>
                        {indicators.failures.map((failure) => (
                            <div key={failure.filename}>
                                {failure.filename} — {failure.reason}
                            </div>
                        ))}
                    </div>
                </div>
            )}
        </div>
    );
}
