import type { AdbClient, CommandResult } from "../adb/client.js";
import { CommandFailedError, isExpectedRefusal } from "../adb/errors.js";
import type { ArtifactRecord, EvidenceStore } from "../evidence/store.js";
import type { CommandLog } from "./command-log.js";
import type { DeviceContext } from "./device-context.js";

/**
 * Execution context handed to every module.
 *
 * Modules never touch the evidence store or the command log directly; they go
 * through these helpers so that hashing, logging and error classification
 * happen identically for every artifact.
 */

export interface ModuleError {
    /** The device path or command the failure relates to. */
    readonly artifact: string;
    readonly error: string;
    /** True for routine device refusals (permission denied, missing path). */
    readonly expected: boolean;
}

export type ModuleStatus = "complete" | "partial" | "failed" | "skipped";

export interface ModuleResult {
    readonly status: ModuleStatus;
    readonly artifacts: readonly string[];
    readonly errors: readonly ModuleError[];
    /** Free-form findings surfaced in the UI, e.g. root indicators. */
    readonly notes?: Readonly<Record<string, unknown>>;
}

export interface AcquisitionContext {
    readonly client: AdbClient;
    readonly device: DeviceContext;
    readonly store: EvidenceStore;
    readonly log: CommandLog;
    readonly signal: AbortSignal;

    /** Current module id; used to attribute log entries. */
    readonly module: string;

    /** Reports intra-module progress, e.g. "17 / 43 APKs". */
    progress(message: string, completed?: number, total?: number): void;

    /**
     * Runs a command and writes its stdout to `artifactName`.
     *
     * Buffers output, so it is for artifacts of bounded size. Use
     * `streamToArtifact` for logcat, dumpsys and bugreport.
     */
    runToArtifact(
        command: readonly string[],
        artifactName: string,
        options?: { allowEmpty?: boolean },
    ): Promise<ArtifactRecord>;

    /** Runs a command and returns its output without writing an artifact. */
    /**
     * Runs a command and returns its result.
     *
     * `tolerateFailure` suppresses the throw-on-nonzero-exit contract for
     * existence probes, where a non-zero exit is the answer (`which su`
     * returning 1 means "absent") rather than a collection failure.
     */
    run(command: readonly string[], options?: { tolerateFailure?: boolean }): Promise<CommandResult>;

    /**
     * Streams stdout straight into the evidence store without buffering.
     *
     * `maxBytes` caps the stored size, marking the artifact truncated instead of
     * failing it. Used by the connection-test profile to keep unbounded sources
     * like logcat bounded.
     */
    streamToArtifact(
        command: readonly string[],
        artifactName: string,
        options?: { maxBytes?: number },
    ): Promise<ArtifactRecord>;

    /** Pulls a device file into the store over the ADB sync service. */
    pullToArtifact(remotePath: string, artifactName: string): Promise<ArtifactRecord>;

    /** Writes a derived artifact (parsed JSON, summaries) into the store. */
    writeText(artifactName: string, text: string): Promise<ArtifactRecord>;
}

export interface AcquisitionModule {
    readonly id: string;
    readonly label: string;

    /**
     * Whether this module applies to the connected device. Returning false
     * records `skipped` rather than an error.
     */
    supports?(device: DeviceContext): boolean;

    run(ctx: AcquisitionContext): Promise<ModuleResult>;
}

/** Accumulates artifacts and errors, then derives the module's overall status. */
export class ResultBuilder {
    readonly #artifacts: string[] = [];
    readonly #errors: ModuleError[] = [];
    #notes: Record<string, unknown> | undefined;

    artifact(name: string): void {
        this.#artifacts.push(name);
    }

    error(artifact: string, error: unknown, expected?: boolean): void {
        const message = error instanceof Error ? error.message : String(error);
        this.#errors.push({
            artifact,
            error: message,
            expected:
                expected ??
                (error instanceof CommandFailedError
                    ? error.expected
                    : isExpectedRefusal(message)),
        });
    }

    note(key: string, value: unknown): void {
        this.#notes ??= {};
        this.#notes[key] = value;
    }

    /**
     * `complete` only when nothing failed. A module that collected some
     * artifacts and hit refusals is `partial`; one that collected nothing at
     * all is `failed`, even if every refusal was expected.
     */
    build(): ModuleResult {
        let status: ModuleStatus;
        if (this.#errors.length === 0) {
            status = "complete";
        } else if (this.#artifacts.length > 0) {
            status = "partial";
        } else {
            status = "failed";
        }

        return {
            status,
            artifacts: [...this.#artifacts],
            errors: [...this.#errors],
            ...(this.#notes === undefined ? {} : { notes: this.#notes }),
        };
    }

    static skipped(reason: string): ModuleResult {
        return {
            status: "skipped",
            artifacts: [],
            errors: [{ artifact: "-", error: reason, expected: true }],
        };
    }
}
