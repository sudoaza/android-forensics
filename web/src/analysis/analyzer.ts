import type { AlertStore, Rule } from "./alerts.js";
import type { ArtifactSource } from "./source.js";

/**
 * The analyzer contract.
 *
 * Deliberately parallel to `AcquisitionModule`: one declaration per forensic
 * surface, run in isolation, with failures recorded rather than propagated. The
 * reasoning is the same as during acquisition — a parser that throws on one
 * OEM's unexpected `dumpsys` layout must not silence every other finding.
 */
export interface Analyzer {
    readonly id: string;
    readonly label: string;

    /**
     * fnmatch patterns this analyzer reads, e.g. `*​/settings_*.txt`. Used to
     * report `not-applicable` without running, and to document in the report
     * which surfaces were examined.
     */
    readonly inputs: readonly string[];

    /** Every rule this analyzer can fire, for rule-set provenance. */
    readonly rules: readonly Rule[];

    run(context: AnalysisContext): Promise<void>;
}

export interface AnalysisContext {
    readonly source: ArtifactSource;
    readonly alerts: AlertStore;
    readonly indicators: IndicatorMatcher | undefined;
    readonly signal: AbortSignal;

    /** Reports intra-analyzer progress for long inputs. */
    progress(message: string, completed?: number, total?: number): void;

    /**
     * Records that an artifact was successfully read and parsed.
     *
     * This is what lets the engine tell a clean result from a failed one: both
     * produce no alerts, and only the count of surfaces actually examined
     * distinguishes "looked, found nothing" from "could not look". Mirrors
     * `ResultBuilder.artifact()` in the acquisition engine, for the same reason.
     */
    examined(artifact: string): void;

    /**
     * Records a parse problem.
     *
     * Not an alert: that a `dumpsys` section could not be parsed is a fact about
     * this tool, not about the device, and conflating the two would let a broken
     * parser masquerade as a clean device.
     */
    note(artifact: string, problem: string): void;
}

/**
 * The subset of indicator matching analyzers use.
 *
 * Declared here so analyzers do not depend on the STIX2 loader, and so the
 * engine can run the whole configuration rule set with no indicators loaded at
 * all.
 */
export interface IndicatorMatcher {
    checkAppId(appId: string): IndicatorHit | undefined;
    checkFileHash(hash: string): IndicatorHit | undefined;
    checkAppCertificateHash(hash: string): IndicatorHit | undefined;
    checkProcess(name: string): IndicatorHit | undefined;
    checkFileName(name: string): IndicatorHit | undefined;
    checkFilePath(path: string): IndicatorHit | undefined;
    checkDomain(value: string): IndicatorHit | undefined;
    checkAndroidPropertyName(name: string): IndicatorHit | undefined;
}

export interface IndicatorHit {
    readonly type: string;
    readonly value: string;
    readonly collection: string;
    readonly source: string;
    readonly message: string;
}

export type AnalyzerStatus = "complete" | "partial" | "failed" | "not-applicable";

export interface AnalyzerReport {
    readonly id: string;
    readonly label: string;
    readonly status: AnalyzerStatus;
    /** Artifacts matched by this analyzer's input patterns. */
    readonly inputsFound: readonly string[];
    /**
     * Artifacts actually read and parsed. Narrower than `inputsFound` when a file
     * was present but unusable, which is the distinction that makes a `failed`
     * status meaningful.
     */
    readonly examined: readonly string[];
    readonly alertCount: number;
    readonly problems: readonly { readonly artifact: string; readonly problem: string }[];
    readonly durationMs: number;
}
