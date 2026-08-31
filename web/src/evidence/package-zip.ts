import { makeZip } from "client-zip";

import type { ArtifactRecord, EvidenceStore } from "./store.js";

/**
 * Archive assembly.
 *
 * `client-zip` stores entries without compression, which is what the hash
 * semantics require: `hashes.csv` records the SHA-256 of each entry's plaintext
 * bytes, so an archive reader can recompute them directly. APKs and
 * bugreport.zip are already compressed, so store-only costs little.
 *
 * Entries are emitted from a lazy async generator, so bytes flow
 * OPFS -> ZIP -> disk without the archive ever being buffered. This matters at
 * the hundreds-of-megabytes scale a Full profile reaches.
 */

export const HASHES_FILENAME = "hashes.csv";

/**
 * Builds `hashes.csv` with AndroidQF's semantics: every other archive entry is
 * hashed, and the file never hashes itself. It is therefore always the final
 * entry, after the manifest and command log have been written.
 */
export function buildHashesCsv(records: readonly ArtifactRecord[]): string {
    const lines = ["SHA256,FILE"];
    for (const record of records) {
        if (record.name === HASHES_FILENAME) {
            continue;
        }
        // Quote the path and escape embedded quotes, per RFC 4180.
        lines.push(`${record.sha256},"${record.name.replaceAll('"', '""')}"`);
    }
    return `${lines.join("\n")}\n`;
}

export interface ArchivePlan {
    readonly filename: string;
    /** Entries in archive order; `hashes.csv` last. */
    readonly entries: readonly ArtifactRecord[];
    readonly hashesCsv: string;
    readonly totalBytes: number;
}

export function planArchive(
    acquisitionId: string,
    records: readonly ArtifactRecord[],
): ArchivePlan {
    const entries = records.filter((record) => record.name !== HASHES_FILENAME);
    const hashesCsv = buildHashesCsv(entries);

    return {
        filename: `${acquisitionId}.zip`,
        entries,
        hashesCsv,
        totalBytes: entries.reduce((sum, entry) => sum + entry.size, 0),
    };
}

async function* archiveEntries(
    store: EvidenceStore,
    plan: ArchivePlan,
    onEntry?: (name: string, index: number, total: number) => void,
): AsyncGenerator<{ name: string; input: ReadableStream<Uint8Array> | string; lastModified: Date }> {
    const total = plan.entries.length + 1;

    for (const [index, record] of plan.entries.entries()) {
        onEntry?.(record.name, index, total);
        const file = await store.openFile(record.name);
        yield {
            name: record.name,
            input: file.stream() as ReadableStream<Uint8Array>,
            lastModified: new Date(record.acquiredAt),
        };
    }

    // Last, so it can cover every preceding entry without covering itself.
    onEntry?.(HASHES_FILENAME, total - 1, total);
    yield {
        name: HASHES_FILENAME,
        input: plan.hashesCsv,
        lastModified: new Date(),
    };
}

export function archiveStream(
    store: EvidenceStore,
    plan: ArchivePlan,
    onEntry?: (name: string, index: number, total: number) => void,
): ReadableStream<Uint8Array> {
    return makeZip(archiveEntries(store, plan, onEntry));
}

interface SaveFilePickerOptions {
    suggestedName?: string;
    types?: readonly { description: string; accept: Record<string, readonly string[]> }[];
}

type SaveFilePicker = (options: SaveFilePickerOptions) => Promise<FileSystemFileHandle>;

/**
 * Writes the archive to a location the examiner chooses.
 *
 * Prefers the File System Access API so the ZIP streams straight to disk. Falls
 * back to an in-memory blob download only when the picker is unavailable,
 * which is memory-bound and therefore reported as a limitation rather than
 * used silently for large acquisitions.
 */
export async function exportArchive(
    store: EvidenceStore,
    plan: ArchivePlan,
    onEntry?: (name: string, index: number, total: number) => void,
): Promise<{ method: "stream-to-disk" | "blob-download" }> {
    const picker = (globalThis as { showSaveFilePicker?: SaveFilePicker }).showSaveFilePicker;

    if (picker !== undefined) {
        const handle = await picker({
            suggestedName: plan.filename,
            types: [{ description: "Acquisition archive", accept: { "application/zip": [".zip"] } }],
        });
        const writable = await handle.createWritable();
        await archiveStream(store, plan, onEntry).pipeTo(
            writable as unknown as WritableStream<Uint8Array>,
        );
        return { method: "stream-to-disk" };
    }

    const blob = await collectBlob(archiveStream(store, plan, onEntry));
    const url = URL.createObjectURL(blob);
    try {
        const anchor = document.createElement("a");
        anchor.href = url;
        anchor.download = plan.filename;
        anchor.click();
    } finally {
        // Revoked on the next task so the navigation has started.
        setTimeout(() => URL.revokeObjectURL(url), 60_000);
    }
    return { method: "blob-download" };
}

/**
 * Buffers a stream into a Blob by draining it explicitly.
 *
 * `new Response(stream).blob()` is the obvious spelling, but it fails with
 * "Failed to fetch" on large bodies (observed on a real 111 MB acquisition in
 * Chrome 148): the fetch body path imposes limits the Streams API does not.
 * Reading chunks and handing them to the Blob constructor lets the browser spill
 * to disk-backed storage instead, which is what makes a multi-hundred-megabyte
 * export survive the fallback path.
 */
async function collectBlob(stream: ReadableStream<Uint8Array>): Promise<Blob> {
    const chunks: Uint8Array[] = [];
    const reader = stream.getReader();
    try {
        for (;;) {
            const { done, value } = await reader.read();
            if (done) {
                break;
            }
            chunks.push(value);
        }
    } finally {
        reader.releaseLock();
    }
    return new Blob(chunks as BlobPart[], { type: "application/zip" });
}
