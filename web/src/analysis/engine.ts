import { AlertStore } from "./alerts.js";
import type {
    AnalysisContext,
    Analyzer,
    AnalyzerReport,
    AnalyzerStatus,
    IndicatorMatcher,
} from "./analyzer.js";
import type { ArtifactSource } from "./source.js";

/**
 * Analysis engine.
 *
 * Runs analyzers sequentially over one source. Unlike acquisition, this is not
 * forced by a shared transport — it is for determinism: the same archive and the
 * same rule set must produce the same report, in the same order, every time, or
 * two examiners comparing reports cannot tell a real difference from scheduling
 * noise.
 *
 * Each analyzer is isolated. An analyzer that throws is recorded as `failed` and
 * the run continues, because a parser defect on one surface must not be able to
 * suppress findings on every other.
 */

export interface AnalysisProgress {
    readonly analyzers: readonly {
        readonly id: string;
        readonly label: string;
        readonly status: "pending" | "running" | AnalyzerStatus;
        readonly detail?: string;
        readonly completed?: number;
        readonly total?: number;
    }[];
    readonly currentId: string | undefined;
    readonly alertCount: number;
}

export type AnalysisProgressListener = (progress: AnalysisProgress) => void;

export interface AnalysisOutcome {
    readonly alerts: AlertStore;
    readonly reports: readonly AnalyzerReport[];
    readonly startedAt: string;
    readonly completedAt: string;
    readonly cancelled: boolean;
}

export class AnalysisEngine {
    readonly #analyzers: readonly Analyzer[];
    readonly #source: ArtifactSource;
    readonly #indicators: IndicatorMatcher | undefined;
    readonly #alerts = new AlertStore();
    readonly #abort = new AbortController();
    readonly #listeners = new Set<AnalysisProgressListener>();

    #states: AnalysisProgress["analyzers"];
    #reports: AnalyzerReport[] = [];

    constructor(options: {
        source: ArtifactSource;
        analyzers: readonly Analyzer[];
        indicators?: IndicatorMatcher;
    }) {
        this.#source = options.source;
        this.#analyzers = options.analyzers;
        this.#indicators = options.indicators;
        this.#states = options.analyzers.map((analyzer) => ({
            id: analyzer.id,
            label: analyzer.label,
            status: "pending" as const,
        }));
    }

    onProgress(listener: AnalysisProgressListener): () => void {
        this.#listeners.add(listener);
        return () => this.#listeners.delete(listener);
    }

    cancel(): void {
        this.#abort.abort(new Error("Analysis cancelled"));
    }

    get progress(): AnalysisProgress {
        return {
            analyzers: this.#states,
            currentId: this.#states.find((state) => state.status === "running")?.id,
            alertCount: this.#alerts.alerts.length,
        };
    }

    async run(): Promise<AnalysisOutcome> {
        const startedAt = new Date().toISOString();

        for (const analyzer of this.#analyzers) {
            if (this.#abort.signal.aborted) {
                break;
            }
            this.#reports.push(await this.#runAnalyzer(analyzer));
            this.#emit();
        }

        return {
            alerts: this.#alerts,
            reports: this.#reports,
            startedAt,
            completedAt: new Date().toISOString(),
            cancelled: this.#abort.signal.aborted,
        };
    }

    async #runAnalyzer(analyzer: Analyzer): Promise<AnalyzerReport> {
        const started = Date.now();

        // An analyzer whose inputs are absent is reported as not-applicable
        // rather than clean. The Quick profile has no `dumpsys.txt`, and "we did
        // not look" must never read as "we looked and found nothing".
        const inputsFound = analyzer.inputs.flatMap((pattern) => [
            ...this.#source.match(pattern),
        ]);
        if (inputsFound.length === 0) {
            this.#setState(analyzer.id, "not-applicable");
            return {
                id: analyzer.id,
                label: analyzer.label,
                status: "not-applicable",
                inputsFound: [],
                examined: [],
                alertCount: 0,
                problems: [],
                durationMs: Date.now() - started,
            };
        }

        this.#setState(analyzer.id, "running");
        this.#emit();

        const problems: { artifact: string; problem: string }[] = [];
        const examined: string[] = [];
        const alertsBefore = this.#alerts.alerts.length;
        let threw: string | undefined;

        try {
            await analyzer.run(this.#createContext(analyzer, problems, examined));
        } catch (error) {
            if (this.#abort.signal.aborted) {
                threw = "Cancelled";
            } else {
                threw = error instanceof Error ? error.message : String(error);
                problems.push({ artifact: analyzer.id, problem: threw });
            }
        }

        const alertCount = this.#alerts.alerts.length - alertsBefore;

        // Status is derived from what was examined, not from what was found. A
        // clean device and an unparseable artifact both yield zero alerts, and
        // reporting the second as `complete` would present a parser failure as a
        // negative finding — the single most dangerous mistake this engine could
        // make.
        const status: AnalyzerStatus =
            examined.length === 0
                ? "failed"
                : problems.length > 0
                  ? "partial"
                  : "complete";

        this.#setState(analyzer.id, status);
        return {
            id: analyzer.id,
            label: analyzer.label,
            status,
            inputsFound,
            examined,
            alertCount,
            problems,
            durationMs: Date.now() - started,
        };
    }

    #createContext(
        analyzer: Analyzer,
        problems: { artifact: string; problem: string }[],
        examined: string[],
    ): AnalysisContext {
        const engine = this;
        return {
            source: this.#source,
            alerts: this.#alerts,
            indicators: this.#indicators,
            signal: this.#abort.signal,

            progress(message: string, completed?: number, total?: number): void {
                engine.#states = engine.#states.map((state) =>
                    state.id === analyzer.id
                        ? {
                              ...state,
                              detail: message,
                              ...(completed === undefined ? {} : { completed }),
                              ...(total === undefined ? {} : { total }),
                          }
                        : state,
                );
                engine.#emit();
            },

            examined(artifact: string): void {
                examined.push(artifact);
            },

            note(artifact: string, problem: string): void {
                problems.push({ artifact, problem });
            },
        };
    }

    #setState(id: string, status: AnalysisProgress["analyzers"][number]["status"]): void {
        this.#states = this.#states.map((state) =>
            state.id === id ? { ...state, status } : state,
        );
    }

    #emit(): void {
        const snapshot = this.progress;
        for (const listener of this.#listeners) {
            listener(snapshot);
        }
    }
}
