import { hashStream, hashText, hashingStream } from "./hasher.js";

/**
 * Local evidence store.
 *
 * Everything runs in the browser, so acquisitions spool to the Origin Private
 * File System instead of being uploaded. OPFS is used rather than IndexedDB
 * because `createWritable()` accepts a `WritableStream`, letting an APK flow
 * device -> hash -> disk without ever being fully resident in memory.
 *
 * The design's "browser hash must equal server hash" rule is preserved without
 * a server by hashing twice through independent paths:
 *
 *   1. write hash  computed on bytes in flight from the device
 *   2. read hash   computed by re-reading the persisted file afterwards
 *
 * They must match. A mismatch means the bytes did not survive the write, which
 * is exactly the class of silent corruption the two-party check exists to
 * catch. It does not, and cannot, prove the device sent the truth.
 */

export interface ArtifactRecord {
    /** Path inside the acquisition archive, e.g. "security/appops.txt". */
    readonly name: string;
    readonly sha256: string;
    readonly size: number;
    readonly acquiredAt: string;
    readonly verified: boolean;
    /** Set when the write and verification hashes disagree. */
    readonly verificationError?: string;
    /**
     * Set when a size cap stopped the transfer before the source ended.
     *
     * The artifact is still internally consistent — `sha256` covers exactly the
     * bytes stored — but it is not the whole source. This must be recorded, since
     * an analyst cannot otherwise distinguish a capped log from a short one.
     */
    readonly truncated?: true;
    /** The cap that was applied, in bytes. Only set when `truncated`. */
    readonly truncatedAt?: number;
}

const ROOT_DIRECTORY = "acquisitions";

async function resolveDirectory(
    root: FileSystemDirectoryHandle,
    segments: readonly string[],
    create: boolean,
): Promise<FileSystemDirectoryHandle> {
    let handle = root;
    for (const segment of segments) {
        handle = await handle.getDirectoryHandle(segment, { create });
    }
    return handle;
}

function splitPath(name: string): { directories: string[]; filename: string } {
    const parts = name.split("/").filter((part) => part.length > 0);
    const filename = parts.pop();
    if (filename === undefined) {
        throw new Error(`Invalid artifact name: ${name}`);
    }
    if (parts.includes("..")) {
        throw new Error(`Artifact name must not traverse directories: ${name}`);
    }
    return { directories: parts, filename };
}

export class EvidenceStore {
    readonly acquisitionId: string;

    readonly #directory: FileSystemDirectoryHandle;
    readonly #records = new Map<string, ArtifactRecord>();

    private constructor(acquisitionId: string, directory: FileSystemDirectoryHandle) {
        this.acquisitionId = acquisitionId;
        this.#directory = directory;
    }

    static async open(acquisitionId: string): Promise<EvidenceStore> {
        if (navigator.storage?.getDirectory === undefined) {
            throw new Error(
                "This browser has no Origin Private File System. Use Chromium, Chrome, or Edge.",
            );
        }

        // Best-effort: keeps the browser from evicting evidence under pressure.
        // Denial is not fatal, so the result is deliberately ignored.
        await navigator.storage.persist?.().catch(() => false);

        const opfsRoot = await navigator.storage.getDirectory();
        const root = await opfsRoot.getDirectoryHandle(ROOT_DIRECTORY, { create: true });
        const directory = await root.getDirectoryHandle(acquisitionId, { create: true });

        return new EvidenceStore(acquisitionId, directory);
    }

    /** Artifacts in acquisition order. `hashes.csv` ordering depends on this. */
    get records(): readonly ArtifactRecord[] {
        return [...this.#records.values()];
    }

    get totalBytes(): number {
        let total = 0;
        for (const record of this.#records.values()) {
            total += record.size;
        }
        return total;
    }

    get verifiedBytes(): number {
        let total = 0;
        for (const record of this.#records.values()) {
            if (record.verified) {
                total += record.size;
            }
        }
        return total;
    }

    /**
     * Streams `source` into the store, hashing in flight, then verifies by
     * re-reading the persisted bytes.
     *
     * On failure the partial file and its record are both removed, and `source`
     * is cancelled. A truncated artifact that looks complete is worse than a
     * recorded failure, and an abandoned source stream would stall the entire
     * multiplexed ADB transport.
     */
    async writeStream(
        name: string,
        source: ReadableStream<Uint8Array>,
        options?: {
            signal?: AbortSignal;
            onProgress?: (bytes: number) => void;
            /**
             * Stops the transfer once this many bytes have been stored, marking
             * the artifact truncated rather than failing it.
             */
            maxBytes?: number;
        },
    ): Promise<ArtifactRecord> {
        const acquiredAt = new Date().toISOString();
        const hashing = hashingStream();

        // Everything before `pipeTo` can throw (path resolution, quota,
        // OPFS locks) while `source` is still unread. `piped` is only set once
        // the hashing transform owns the source, which determines whether
        // cancelling `source` or `piped` is the correct cleanup.
        let piped: ReadableStream<Uint8Array> | undefined;
        let parent: FileSystemDirectoryHandle | undefined;
        let filename: string | undefined;
        let truncated: number | undefined;

        try {
            const split = splitPath(name);
            filename = split.filename;
            parent = await resolveDirectory(this.#directory, split.directories, true);
            const fileHandle = await parent.getFileHandle(filename, { create: true });

            // Note: this truncates any existing file, so a previously verified
            // artifact of the same name is already unrecoverable past this point.
            const writable = await fileHandle.createWritable();

            piped = source.pipeThrough(hashing.stream);

            const maxBytes = options?.maxBytes;
            if (maxBytes !== undefined) {
                // Placed after the hashing transform so the digest covers exactly
                // the bytes that reach the file, keeping the re-read
                // verification meaningful for a capped artifact.
                let stored = 0;
                piped = piped.pipeThrough(
                    new TransformStream<Uint8Array, Uint8Array>({
                        transform(chunk, controller) {
                            const remaining = maxBytes - stored;
                            if (remaining <= 0) {
                                return;
                            }
                            if (chunk.byteLength <= remaining) {
                                stored += chunk.byteLength;
                                controller.enqueue(chunk);
                                return;
                            }
                            // Store the partial chunk so the cap is exact rather
                            // than rounded to a chunk boundary.
                            stored += remaining;
                            truncated = maxBytes;
                            controller.enqueue(chunk.subarray(0, remaining));
                            controller.terminate();
                        },
                    }),
                );
            }

            if (options?.onProgress !== undefined) {
                const onProgress = options.onProgress;
                let seen = 0;
                piped = piped.pipeThrough(
                    new TransformStream<Uint8Array, Uint8Array>({
                        transform(chunk, controller) {
                            controller.enqueue(chunk);
                            seen += chunk.byteLength;
                            onProgress(seen);
                        },
                    }),
                );
            }

            // `pipeTo` propagates back-pressure from OPFS to the USB read, and
            // closes the writable exactly once on success.
            await piped.pipeTo(
                writable as unknown as WritableStream<Uint8Array>,
                options?.signal !== undefined ? { signal: options.signal } : {},
            );
        } catch (error) {
            // Release the device stream so the shared ADB connection does not
            // stall for every later module.
            await (piped ?? source).cancel().catch(() => undefined);
            await this.#discardArtifact(name, parent, filename);
            throw error;
        }

        if (truncated !== undefined) {
            // `terminate()` ends the pipe but leaves the device still producing,
            // so the source must be released explicitly or the transport stalls.
            await source.cancel().catch(() => undefined);
        }

        const written = hashing.result();
        const fileHandle = await parent.getFileHandle(filename);
        const record = await this.#verify(
            name,
            fileHandle,
            written,
            acquiredAt,
            truncated === undefined ? undefined : { truncated: true, truncatedAt: truncated },
        );

        if (!record.verified) {
            await this.#discardArtifact(name, parent, filename);
            throw new Error(record.verificationError);
        }

        this.#records.set(name, record);
        return record;
    }

    /**
     * Removes a failed artifact and any record of it.
     *
     * Deleting the file without dropping the record would leave the manifest,
     * `manifest.sha256.json` and `hashes.csv` referencing a file that no longer
     * exists, which then aborts ZIP export part-way through. This matters
     * because several callers legitimately write the same artifact name more
     * than once (`fallbackCommandArtifact`, `packages.txt`).
     */
    async #discardArtifact(
        name: string,
        parent: FileSystemDirectoryHandle | undefined,
        filename: string | undefined,
    ): Promise<void> {
        this.#records.delete(name);
        if (parent !== undefined && filename !== undefined) {
            await parent.removeEntry(filename).catch(() => undefined);
        }
    }

    /** Convenience path for small text artifacts (command output, manifests). */
    async writeText(name: string, text: string): Promise<ArtifactRecord> {
        const bytes = new TextEncoder().encode(text);
        const stream = new Blob([bytes]).stream() as ReadableStream<Uint8Array>;
        const record = await this.writeStream(name, stream);

        // Independent third check: hashing the source string directly must
        // agree with the streamed write hash.
        const expected = hashText(text);
        if (record.sha256 !== expected) {
            const split = splitPath(name);
            const parent = await resolveDirectory(this.#directory, split.directories, false).catch(
                () => undefined,
            );
            await this.#discardArtifact(name, parent, split.filename);
            throw new Error(
                `Hash mismatch writing ${name}: in-memory ${expected} vs streamed ${record.sha256}`,
            );
        }
        return record;
    }

    async #verify(
        name: string,
        fileHandle: FileSystemFileHandle,
        written: { sha256: string; size: number },
        acquiredAt: string,
        extra?: { truncated?: true; truncatedAt?: number },
    ): Promise<ArtifactRecord> {
        const file = await fileHandle.getFile();
        const reread = await hashStream(file.stream() as ReadableStream<Uint8Array>);

        if (reread.sha256 !== written.sha256 || reread.size !== written.size) {
            return {
                name,
                sha256: written.sha256,
                size: written.size,
                acquiredAt,
                verified: false,
                verificationError:
                    `Verification failed for ${name}: wrote ${written.size} bytes ` +
                    `(${written.sha256}) but re-read ${reread.size} bytes (${reread.sha256}).`,
                ...extra,
            };
        }

        return {
            name,
            sha256: written.sha256,
            size: written.size,
            acquiredAt,
            verified: true,
            ...extra,
        };
    }

    async openFile(name: string): Promise<File> {
        const { directories, filename } = splitPath(name);
        const parent = await resolveDirectory(this.#directory, directories, false);
        const handle = await parent.getFileHandle(filename);
        return await handle.getFile();
    }

    has(name: string): boolean {
        return this.#records.has(name);
    }

    /** Discards the entire local spool. Irreversible. */
    static async discard(acquisitionId: string): Promise<void> {
        const opfsRoot = await navigator.storage.getDirectory();
        const root = await opfsRoot.getDirectoryHandle(ROOT_DIRECTORY, { create: true });
        await root.removeEntry(acquisitionId, { recursive: true });
    }

    static async list(): Promise<readonly string[]> {
        const opfsRoot = await navigator.storage.getDirectory();
        const root = await opfsRoot.getDirectoryHandle(ROOT_DIRECTORY, { create: true });
        const names: string[] = [];
        for await (const [name, handle] of root as unknown as AsyncIterable<
            [string, FileSystemHandle]
        >) {
            if (handle.kind === "directory") {
                names.push(name);
            }
        }
        return names;
    }
}

export async function storageEstimate(): Promise<{ usage: number; quota: number } | undefined> {
    const estimate = await navigator.storage?.estimate?.();
    if (estimate?.quota === undefined || estimate.usage === undefined) {
        return undefined;
    }
    return { usage: estimate.usage, quota: estimate.quota };
}
