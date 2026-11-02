import { useCallback, useEffect, useRef, useState } from "react";

import type { AlertStore } from "../analysis/alerts.js";
import type { Analyzer } from "../analysis/analyzer.js";
import { defaultAnalyzers } from "../analysis/analyzers/index.js";
import {
    AnalysisEngine,
    type AnalysisOutcome,
    type AnalysisProgress,
} from "../analysis/engine.js";
import {
    describeIndicatorSources,
    loadBundledSnapshot,
    loadSuppliedBundles,
} from "../analysis/indicators/library.js";
import { IndicatorLibrary } from "../analysis/indicators/matcher.js";
import {
    ALERTS_FILENAME,
    ANALYSIS_FILENAME,
    TIMELINE_FILENAME,
    buildAlertsCsv,
    buildAnalysisReport,
    buildTimelineCsv,
} from "../analysis/report.js";
import {
    StoreSource,
    ZipSource,
    type ArtifactSource,
    type VerificationReport,
} from "../analysis/source.js";
import { EvidenceStore } from "../evidence/store.js";

/**
 * Analysis orchestration.
 *
 * Deliberately separate from `useAcquisition`: analysis must be reachable
 * without a device. An examiner who imported an archive collected elsewhere, or
 * who is re-running analysis with an updated indicator set, has no phone to
 * connect, and coupling the two would make that impossible.
 */

export type AnalysisPhase = "idle" | "verifying" | "running" | "done" | "error";

export interface IndicatorState {
    readonly library: IndicatorLibrary;
    readonly failures: readonly { readonly filename: string; readonly reason: string }[];
    /** Provenance of the pinned snapshot, when one is deployed. */
    readonly snapshot:
        | { readonly pinnedAt: string; readonly commit: string; readonly upstream: string }
        | undefined;
    readonly total: number;
    /**
     * True until the bundled snapshot has finished loading.
     *
     * Distinguished from `total === 0` deliberately. During the load the count is
     * legitimately zero, and rendering that as "no indicators are loaded, so the
     * absence of matches means nothing" tells the examiner something false about
     * the tool's capability.
     */
    readonly loading: boolean;
}

export interface AnalysisState {
    readonly phase: AnalysisPhase;
    readonly progress: AnalysisProgress | undefined;
    readonly verification: VerificationReport | undefined;
    readonly verifyDetail: string | undefined;
    readonly alerts: AlertStore | undefined;
    readonly outcome: AnalysisOutcome | undefined;
    readonly analyzers: readonly Analyzer[];
    readonly source: ArtifactSource | undefined;
    readonly error: string | undefined;
    /** Names of the reports written back into the evidence store, if any. */
    readonly persisted: readonly string[];
}

const IDLE: AnalysisState = {
    phase: "idle",
    progress: undefined,
    verification: undefined,
    verifyDetail: undefined,
    alerts: undefined,
    outcome: undefined,
    analyzers: [],
    source: undefined,
    error: undefined,
    persisted: [],
};

export function useAnalysis() {
    const [state, setState] = useState<AnalysisState>(IDLE);
    const [indicators, setIndicators] = useState<IndicatorState>(() => ({
        library: new IndicatorLibrary(),
        failures: [],
        snapshot: undefined,
        total: 0,
        loading: true,
    }));

    const engineRef = useRef<AnalysisEngine | undefined>(undefined);
    const libraryRef = useRef<IndicatorLibrary>(indicators.library);
    /**
     * The in-flight snapshot load.
     *
     * Held so that starting an analysis can await it. Without this an examiner who
     * clicks Analyse in the first second after load runs against an empty
     * indicator set and gets a report stating no indicators were in force — a
     * wrong answer produced by a race, in a report that would look entirely
     * legitimate.
     */
    const snapshotLoad = useRef<Promise<void> | undefined>(undefined);

    // The pinned snapshot is loaded once, at start-up, from our own origin.
    useEffect(() => {
        let cancelled = false;

        const load = (async () => {
            const result = await loadBundledSnapshot(libraryRef.current);
            if (cancelled) {
                return;
            }
            setIndicators({
                library: libraryRef.current,
                failures: result.failures,
                snapshot:
                    result.index === undefined
                        ? undefined
                        : {
                              pinnedAt: result.index.pinned_at,
                              commit: result.index.commit,
                              upstream: result.index.upstream,
                          },
                total: libraryRef.current.total,
                loading: false,
            });
        })();

        snapshotLoad.current = load;

        return () => {
            cancelled = true;
        };
    }, []);

    /** Adds examiner-supplied bundles to the library already loaded. */
    const addIndicatorFiles = useCallback(async (files: readonly File[]) => {
        const failures = await loadSuppliedBundles(files, libraryRef.current);
        setIndicators((previous) => ({
            ...previous,
            library: libraryRef.current,
            failures: [...previous.failures, ...failures],
            total: libraryRef.current.total,
        }));
    }, []);

    const analyse = useCallback(
        async (
            source: ArtifactSource,
            options?: { verify?: boolean; persistTo?: EvidenceStore },
        ) => {
            const analyzers = defaultAnalyzers();

            // The snapshot load is awaited before the engine is built, so a run
            // started moments after page load still has the bundled indicators in
            // force. A failed load is not fatal: it is already reported as a
            // bundle failure and stated in the report.
            if (snapshotLoad.current !== undefined) {
                setState({ ...IDLE, phase: "verifying", analyzers, source, verifyDetail: "Loading indicators…" });
                await snapshotLoad.current.catch(() => undefined);
            }

            let verification: VerificationReport | undefined;

            // Verification runs before analysis, not after: findings drawn from
            // an archive that no longer matches its own manifest are not worth
            // computing, and the examiner needs to know that first.
            if (options?.verify === true && source instanceof ZipSource) {
                setState({
                    ...IDLE,
                    phase: "verifying",
                    analyzers,
                    source,
                    verifyDetail: "Recomputing hashes…",
                });
                try {
                    verification = await source.verify((name, index, total) => {
                        setState((previous) => ({
                            ...previous,
                            verifyDetail: `Verifying ${index + 1} / ${total}: ${name}`,
                        }));
                    });
                } catch (error) {
                    setState((previous) => ({
                        ...previous,
                        phase: "error",
                        error: error instanceof Error ? error.message : String(error),
                    }));
                    return;
                }
            }

            const engine = new AnalysisEngine({
                source,
                analyzers,
                indicators: libraryRef.current,
            });
            engineRef.current = engine;

            const unsubscribe = engine.onProgress((progress) => {
                setState((previous) => ({ ...previous, progress }));
            });

            setState({
                ...IDLE,
                phase: "running",
                analyzers,
                source,
                verification,
                progress: engine.progress,
            });

            try {
                const outcome = await engine.run();

                // Reports are written back into the store only for an
                // acquisition still held locally. An imported ZIP is read-only
                // evidence, and its `hashes.csv` already covers its contents —
                // adding files would invalidate the manifest it was sealed with.
                let persisted: readonly string[] = [];
                if (options?.persistTo !== undefined) {
                    persisted = await persistReports({
                        store: options.persistTo,
                        source,
                        analyzers,
                        outcome,
                        verification,
                        indicatorSources: describeIndicatorSources(libraryRef.current),
                    });
                }

                setState((previous) => ({
                    ...previous,
                    phase: "done",
                    alerts: outcome.alerts,
                    outcome,
                    progress: engine.progress,
                    persisted,
                }));
            } catch (error) {
                setState((previous) => ({
                    ...previous,
                    phase: "error",
                    error: error instanceof Error ? error.message : String(error),
                }));
            } finally {
                unsubscribe();
            }
        },
        [],
    );

    /** Analyses an acquisition still held in browser storage. */
    const analyseStore = useCallback(
        async (store: EvidenceStore) => {
            await analyse(new StoreSource(store, store.records), { persistTo: store });
        },
        [analyse],
    );

    /** Analyses an archive the examiner selected, verifying it first. */
    const analyseArchive = useCallback(
        async (file: File) => {
            try {
                const source = await ZipSource.open(file, file.name);
                await analyse(source, { verify: true });
            } catch (error) {
                setState({
                    ...IDLE,
                    phase: "error",
                    error:
                        error instanceof Error
                            ? `${file.name} could not be read as an acquisition archive: ${error.message}`
                            : String(error),
                });
            }
        },
        [analyse],
    );

    const cancel = useCallback(() => {
        engineRef.current?.cancel();
    }, []);

    const reset = useCallback(() => {
        setState(IDLE);
    }, []);

    return {
        ...state,
        indicators,
        addIndicatorFiles,
        analyseStore,
        analyseArchive,
        cancel,
        reset,
    };
}

/**
 * Writes the analysis output into the evidence store.
 *
 * Rewritten on each run rather than appended to, so the store always holds the
 * analysis for the current rule and indicator set rather than a pile of
 * historical ones with no way to tell which produced what.
 */
async function persistReports(input: {
    store: EvidenceStore;
    source: ArtifactSource;
    analyzers: readonly Analyzer[];
    outcome: AnalysisOutcome;
    verification: VerificationReport | undefined;
    indicatorSources: ReturnType<typeof describeIndicatorSources>;
}): Promise<readonly string[]> {
    const store = input.store;

    const files: readonly [string, string][] = [
        [
            ANALYSIS_FILENAME,
            buildAnalysisReport({
                acquisitionId: store.acquisitionId,
                sourceOrigin: input.source.origin,
                startedAt: input.outcome.startedAt,
                completedAt: input.outcome.completedAt,
                cancelled: input.outcome.cancelled,
                analyzers: input.analyzers,
                reports: input.outcome.reports,
                alerts: input.outcome.alerts,
                indicatorSources: input.indicatorSources,
                verification: input.verification,
            }),
        ],
        [ALERTS_FILENAME, buildAlertsCsv(input.outcome.alerts)],
        [TIMELINE_FILENAME, buildTimelineCsv(input.outcome.alerts)],
    ];

    const written: string[] = [];
    for (const [name, content] of files) {
        await store.writeText(name, content);
        written.push(name);
    }

    return written;
}
