import type { AdbClient, CommandResult } from "../adb/client.js";
import { CommandFailedError, isExpectedRefusal, toAcquisitionError } from "../adb/errors.js";
import type { ArtifactRecord } from "../evidence/store.js";
import { EvidenceStore } from "../evidence/store.js";
import type { AcquisitionContext, AcquisitionModule, ModuleResult } from "./artifact.js";
import { ResultBuilder } from "./artifact.js";
import { correlateClocks, type ClockCorrelation } from "./clock.js";
import { CommandLog } from "./command-log.js";
import type { DeviceContext } from "./device-context.js";
import {
    buildHashManifest,
    buildManifest,
    type AcquisitionSummary,
    type ModuleReport,
} from "./manifest.js";
import { profileFor, type ProfileId } from "./profiles.js";

/**
 * Acquisition engine.
 *
 * Runs modules sequentially. This is intentional: ADB multiplexes every logical
 * stream over one USB connection, so concurrent modules would contend for
 * bandwidth, interleave unpredictably in the command log, and make the record
 * harder to defend. Sequential execution also makes progress meaningful.
 */

export interface AcquisitionOptions {
    readonly client: AdbClient;
    readonly device: DeviceContext;
    readonly profile: ProfileId;
    readonly station: string;
    readonly caseId?: string;
    readonly examiner?: string;
    readonly hostPublicKey: string;
    readonly credentialProtection: string;
}

export interface ModuleProgress {
    readonly moduleId: string;
    readonly label: string;
    readonly status: "pending" | "running" | ModuleReport["status"];
    readonly detail?: string;
    readonly completed?: number;
    readonly total?: number;
}

export interface AcquisitionProgress {
    readonly acquisitionId: string;
    readonly modules: readonly ModuleProgress[];
    readonly currentModuleId: string | undefined;
    readonly transferredBytes: number;
    readonly verifiedBytes: number;
    readonly artifactCount: number;
    readonly errorCount: number;
    /**
     * Epoch milliseconds when the run began, so the UI can show elapsed time.
     *
     * Elapsed time only; no completion estimate is offered. Artifact volume and
     * per-command latency vary by more than an order of magnitude across devices
     * — a 443-package inventory and a 101 MB logcat were both observed on one
     * phone — so any "time remaining" would be misleading precision.
     */
    readonly startedAtMs: number;
}

export type ProgressListener = (progress: AcquisitionProgress) => void;

/** `AQ-YYYYMMDD-HHMMSS-XXXX`: sorts chronologically and is safe as a filename. */
function newAcquisitionId(): string {
    const now = new Date();
    const stamp = now.toISOString().replaceAll(/[-:T]/g, "").slice(0, 15);
    const random = Math.floor(Math.random() * 0xffff)
        .toString(16)
        .padStart(4, "0");
    return `AQ-${stamp}-${random}`;
}

export interface AcquisitionOutcome {
    readonly summary: AcquisitionSummary;
    readonly store: EvidenceStore;
}

export class AcquisitionEngine {
    readonly acquisitionId = newAcquisitionId();

    readonly #options: AcquisitionOptions;
    readonly #log = new CommandLog();
    readonly #abort = new AbortController();
    readonly #listeners = new Set<ProgressListener>();

    #store: EvidenceStore | undefined;
    #moduleStates: ModuleProgress[] = [];
    #reports: ModuleReport[] = [];
    #transferredBytes = 0;
    #abortReason: string | undefined;
    #startedAt: string | undefined;
    #startedAtMs = Date.now();
    #clockStart: ClockCorrelation | undefined;

    constructor(options: AcquisitionOptions) {
        this.#options = options;
        this.#moduleStates = profileFor(options.profile).modules.map((module) => ({
            moduleId: module.id,
            label: module.label,
            status: "pending",
        }));
    }

    onProgress(listener: ProgressListener): () => void {
        this.#listeners.add(listener);
        return () => this.#listeners.delete(listener);
    }

    /** Stops after the current device operation unwinds. */
    cancel(reason = "Cancelled by examiner"): void {
        this.#abortReason = reason;
        this.#abort.abort(new Error(reason));
    }

    get progress(): AcquisitionProgress {
        return {
            acquisitionId: this.acquisitionId,
            modules: this.#moduleStates,
            currentModuleId: this.#moduleStates.find((state) => state.status === "running")
                ?.moduleId,
            transferredBytes: this.#transferredBytes,
            verifiedBytes: this.#store?.verifiedBytes ?? 0,
            artifactCount: this.#store?.records.length ?? 0,
            errorCount: this.#reports.reduce((sum, report) => sum + report.errors.length, 0),
            startedAtMs: this.#startedAtMs,
        };
    }

    /**
     * Best-effort outcome for a run that threw.
     *
     * Artifacts already in the store are complete and verified even if the
     * manifest write failed, so the UI needs a summary to offer export. Returns
     * `undefined` only when the store was never opened, meaning nothing was
     * collected.
     */
    partialOutcome(): AcquisitionOutcome | undefined {
        const store = this.#store;
        if (store === undefined) {
            return undefined;
        }

        const now = new Date().toISOString();
        return {
            store,
            summary: {
                acquisitionId: this.acquisitionId,
                caseId: this.#options.caseId,
                examiner: this.#options.examiner,
                station: this.#options.station,
                profile: this.#options.profile,
                startedAt: this.#startedAt ?? now,
                completedAt: now,
                device: this.#options.device,
                hostPublicKey: this.#options.hostPublicKey,
                credentialProtection: this.#options.credentialProtection,
                clockStart: this.#clockStart ?? {
                    at: now,
                    samples: [],
                    bestOffsetMs: 0,
                    bestRoundTripMs: 0,
                    error: "Acquisition failed before clock correlation.",
                },
                clockEnd: undefined,
                modules: this.#reports,
                artifacts: store.records,
                cancelled: true,
                abortReason:
                    this.#abortReason ??
                    "Acquisition failed before the manifest could be written. " +
                        "Artifacts listed here are complete and verified.",
            },
        };
    }

    async run(): Promise<AcquisitionOutcome> {
        const { client, device, profile } = this.#options;
        const startedAt = new Date().toISOString();
        this.#startedAt = startedAt;
        this.#startedAtMs = Date.now();

        const store = await EvidenceStore.open(this.acquisitionId);
        this.#store = store;

        // Measured before any collection so the offset applies to every
        // subsequent device timestamp.
        const clockStart = await correlateClocks(client);
        this.#clockStart = clockStart;
        let clockEnd: ClockCorrelation | undefined;

        // The host public key must be in the archive even if the manifest is
        // later unreadable; MVT falls back to this file.
        await store.writeText("adb_host_key.pub", `${this.#options.hostPublicKey}\n`);

        const modules = profileFor(profile).modules;
        let cancelled = false;

        for (const module of modules) {
            if (this.#abort.signal.aborted) {
                cancelled = true;
                break;
            }

            const report = await this.#runModule(module, store, device);
            this.#reports.push(report);
            this.#emit();

            // A transport failure invalidates everything after it, so stop.
            if (report.status === "failed" && report.errors.some((error) => !error.expected)) {
                if (client.closed) {
                    this.#abortReason ??= "Device disconnected during acquisition";
                    cancelled = true;
                    break;
                }
            }
        }

        if (!client.closed) {
            clockEnd = await correlateClocks(client);
        }

        const completedAt = new Date().toISOString();

        // Ordering matters, and each step widens what the record covers:
        //
        //   1. command.log(.json)  — every device interaction
        //   2. acquisition.json    — manifest, whose artifact totals must
        //                            include the command logs written above
        //   3. manifest.sha256.json — per-artifact hashes, incl. the manifest
        //   4. hashes.csv          — written last, at export time, covering all
        //
        // The manifest is therefore built AFTER the command logs exist, so its
        // counts agree with hashes.csv rather than under-reporting.
        await store.writeText("command.log", this.#log.render());
        await store.writeText("command.log.json", this.#log.toJson());

        const summary: AcquisitionSummary = {
            acquisitionId: this.acquisitionId,
            caseId: this.#options.caseId,
            examiner: this.#options.examiner,
            station: this.#options.station,
            profile,
            startedAt,
            completedAt,
            device,
            hostPublicKey: this.#options.hostPublicKey,
            credentialProtection: this.#options.credentialProtection,
            clockStart,
            clockEnd,
            modules: this.#reports,
            artifacts: store.records,
            cancelled: cancelled || this.#abort.signal.aborted,
            abortReason: this.#abortReason,
        };

        await store.writeText("acquisition.json", buildManifest(summary));
        // Written after acquisition.json so it covers it too.
        await store.writeText("manifest.sha256.json", buildHashManifest(store.records));

        // `artifacts` is re-read so the returned summary reflects the manifest
        // files themselves; `acquisition.json` necessarily cannot count the two
        // artifacts written after it, which is noted in the manifest schema.
        const finalSummary: AcquisitionSummary = { ...summary, artifacts: store.records };
        this.#emit();

        return { summary: finalSummary, store };
    }

    async #runModule(
        module: AcquisitionModule,
        store: EvidenceStore,
        device: DeviceContext,
    ): Promise<ModuleReport> {
        const startedAt = new Date().toISOString();
        const started = Date.now();

        if (module.supports?.(device) === false) {
            const result = ResultBuilder.skipped(
                `Not supported on this device (${device.androidRelease ?? "unknown Android"})`,
            );
            this.#setModuleState(module.id, "skipped");
            return this.#toReport(module, result, startedAt, started);
        }

        this.#setModuleState(module.id, "running");
        this.#emit();

        let result: ModuleResult;
        try {
            result = await module.run(this.#createContext(module.id, store, device));
        } catch (error) {
            // A module that throws instead of reporting must not take down the
            // acquisition; the failure is recorded and the run continues.
            const builder = new ResultBuilder();
            builder.error(module.id, toAcquisitionError(error));
            result = builder.build();
        }

        this.#setModuleState(module.id, result.status);
        return this.#toReport(module, result, startedAt, started);
    }

    #toReport(
        module: AcquisitionModule,
        result: ModuleResult,
        startedAt: string,
        startedMs: number,
    ): ModuleReport {
        return {
            id: module.id,
            label: module.label,
            status: result.status,
            startedAt,
            completedAt: new Date().toISOString(),
            durationMs: Date.now() - startedMs,
            artifacts: result.artifacts,
            errors: result.errors,
            ...(result.notes === undefined ? {} : { notes: result.notes }),
        };
    }

    #setModuleState(moduleId: string, status: ModuleProgress["status"], detail?: string): void {
        this.#moduleStates = this.#moduleStates.map((state) =>
            state.moduleId === moduleId
                ? { ...state, status, ...(detail === undefined ? {} : { detail }) }
                : state,
        );
    }

    #emit(): void {
        const snapshot = this.progress;
        for (const listener of this.#listeners) {
            listener(snapshot);
        }
    }

    #createContext(
        moduleId: string,
        store: EvidenceStore,
        device: DeviceContext,
    ): AcquisitionContext {
        const client = this.#options.client;
        const log = this.#log;
        const signal = this.#abort.signal;
        const engine = this;

        /**
         * Classifies a completed command and logs it.
         *
         * Under shell protocol v2 the exit code is authoritative. Under the
         * legacy none-protocol there is no exit code and stderr is merged into
         * stdout, so refusal has to be inferred from the text — which is why
         * `isExpectedRefusal` exists.
         */
        const evaluate = (
            result: CommandResult,
            startedAt: string,
            startedMs: number,
            artifact: ArtifactRecord | undefined,
            bytes: number,
            tolerateFailure?: boolean,
        ): void => {
            const combined = `${result.stdout}\n${result.stderr}`;
            const failedByExit = result.exitCode !== undefined && result.exitCode !== 0;
            const failedByText = result.exitCode === undefined && isExpectedRefusal(combined);
            const failed = failedByExit || failedByText;

            log.append({
                module: moduleId,
                command: result.command,
                startedAt,
                completedAt: new Date().toISOString(),
                durationMs: Date.now() - startedMs,
                deviceTime: undefined,
                exitCode: result.exitCode,
                protocol: result.protocol,
                bytes,
                artifact: artifact?.name,
                sha256: artifact?.sha256,
                stderr: result.stderr,
                // A tolerated failure is a negative answer from a probe, not a
                // collection fault, so it is logged without an error field.
                error:
                    failed && tolerateFailure !== true
                        ? `Command reported failure: ${combined.trim().slice(0, 200)}`
                        : undefined,
            });

            if (failed && tolerateFailure !== true) {
                throw new CommandFailedError(
                    result.command,
                    result.exitCode,
                    result.stderr.length > 0 ? result.stderr : result.stdout,
                    isExpectedRefusal(combined),
                );
            }
        };

        return {
            client,
            device,
            store,
            log,
            signal,
            module: moduleId,

            progress(message: string, completed?: number, total?: number): void {
                engine.#setModuleState(moduleId, "running", message);
                engine.#moduleStates = engine.#moduleStates.map((state) =>
                    state.moduleId === moduleId
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

            async run(
                command: readonly string[],
                options?: { tolerateFailure?: boolean },
            ): Promise<CommandResult> {
                signal.throwIfAborted();
                const startedAt = new Date().toISOString();
                const startedMs = Date.now();
                const result = await client.exec(command, signal);
                evaluate(
                    result,
                    startedAt,
                    startedMs,
                    undefined,
                    result.stdout.length,
                    options?.tolerateFailure,
                );
                return result;
            },

            async runToArtifact(
                command: readonly string[],
                artifactName: string,
                options?: { allowEmpty?: boolean },
            ): Promise<ArtifactRecord> {
                signal.throwIfAborted();
                const startedAt = new Date().toISOString();
                const startedMs = Date.now();

                const result = await client.exec(command, signal);

                // Write before classifying: output produced by a command that
                // then reported failure is still evidence.
                const hasOutput = result.stdout.length > 0;
                let record: ArtifactRecord | undefined;
                if (hasOutput || options?.allowEmpty === true) {
                    record = await store.writeText(artifactName, result.stdout);
                    engine.#transferredBytes += record.size;
                }

                evaluate(result, startedAt, startedMs, record, result.stdout.length);

                if (record === undefined) {
                    throw new CommandFailedError(
                        command,
                        result.exitCode,
                        "Command produced no output",
                        true,
                    );
                }
                return record;
            },

            async streamToArtifact(
                command: readonly string[],
                artifactName: string,
                options?: { maxBytes?: number },
            ): Promise<ArtifactRecord> {
                signal.throwIfAborted();
                const startedAt = new Date().toISOString();
                const startedMs = Date.now();

                const stream = await client.execStream(command, signal);

                let record: ArtifactRecord;
                try {
                    record = await store.writeStream(artifactName, stream.stdout, {
                        signal,
                        ...(options?.maxBytes === undefined ? {} : { maxBytes: options.maxBytes }),
                        onProgress: (bytes) => {
                            engine.#setModuleState(
                                moduleId,
                                "running",
                                `${artifactName} — ${formatBytes(bytes)}`,
                            );
                            engine.#emit();
                        },
                    });
                } catch (error) {
                    // stdout must be cancelled BEFORE awaiting the process
                    // promises. `writeStream` may have failed before it ever
                    // consumed stdout (path resolution, OPFS quota), and while
                    // stdout is unread the demultiplexer stops draining, so the
                    // exit packet never arrives and `exitCode` never settles —
                    // hanging this module and stalling the shared transport.
                    await stream.stdout.cancel().catch(() => undefined);

                    const stderr = await stream.stderr.catch(() => "");
                    const exitCode = await stream.exitCode.catch(() => undefined);
                    log.append({
                        module: moduleId,
                        command,
                        startedAt,
                        completedAt: new Date().toISOString(),
                        durationMs: Date.now() - startedMs,
                        deviceTime: undefined,
                        exitCode,
                        protocol: stream.protocol,
                        bytes: 0,
                        artifact: undefined,
                        sha256: undefined,
                        stderr,
                        error: error instanceof Error ? error.message : String(error),
                    });
                    throw error;
                }

                engine.#transferredBytes += record.size;

                const [exitCode, stderr] = await Promise.all([
                    stream.exitCode.catch(() => undefined),
                    stream.stderr.catch(() => ""),
                ]);

                evaluate(
                    {
                        command,
                        stdout: "",
                        stderr,
                        exitCode,
                        protocol: stream.protocol,
                    },
                    startedAt,
                    startedMs,
                    record,
                    record.size,
                    // A capped transfer cancels the device stream, so a non-zero
                    // exit here reports our own cancellation rather than a device
                    // fault. The cap itself is recorded on the artifact.
                    record.truncated,
                );

                return record;
            },

            async pullToArtifact(
                remotePath: string,
                artifactName: string,
            ): Promise<ArtifactRecord> {
                signal.throwIfAborted();
                const startedAt = new Date().toISOString();
                const startedMs = Date.now();

                try {
                    const source = await client.pull(remotePath, signal);
                    const record = await store.writeStream(artifactName, source, {
                        signal,
                        onProgress: (bytes) => {
                            engine.#setModuleState(
                                moduleId,
                                "running",
                                `${remotePath} — ${formatBytes(bytes)}`,
                            );
                            engine.#emit();
                        },
                    });
                    engine.#transferredBytes += record.size;

                    log.append({
                        module: moduleId,
                        command: ["sync:recv", remotePath],
                        startedAt,
                        completedAt: new Date().toISOString(),
                        durationMs: Date.now() - startedMs,
                        deviceTime: undefined,
                        exitCode: 0,
                        protocol: "shell-v2",
                        bytes: record.size,
                        artifact: record.name,
                        sha256: record.sha256,
                        stderr: "",
                        error: undefined,
                    });

                    return record;
                } catch (error) {
                    log.append({
                        module: moduleId,
                        command: ["sync:recv", remotePath],
                        startedAt,
                        completedAt: new Date().toISOString(),
                        durationMs: Date.now() - startedMs,
                        deviceTime: undefined,
                        exitCode: undefined,
                        protocol: "shell-v2",
                        bytes: 0,
                        artifact: undefined,
                        sha256: undefined,
                        stderr: "",
                        error: error instanceof Error ? error.message : String(error),
                    });
                    throw error;
                }
            },

            async writeText(artifactName: string, text: string): Promise<ArtifactRecord> {
                const record = await store.writeText(artifactName, text);
                engine.#transferredBytes += record.size;
                return record;
            },
        };
    }
}

export function formatBytes(bytes: number): string {
    if (bytes < 1024) {
        return `${bytes} B`;
    }
    const units = ["KB", "MB", "GB", "TB"];
    let value = bytes / 1024;
    let unitIndex = 0;
    while (value >= 1024 && unitIndex < units.length - 1) {
        value /= 1024;
        unitIndex += 1;
    }
    return `${value.toFixed(value < 10 ? 1 : 0)} ${units[unitIndex]}`;
}
