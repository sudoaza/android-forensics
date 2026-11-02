import { describe, expect, it } from "vitest";

import {
    ALERTS_FILENAME,
    ANALYSIS_FILENAME,
    TIMELINE_FILENAME,
} from "../analysis/report.js";
import { hashStream, hashingStream, hashText } from "./hasher.js";
import { HASHES_FILENAME, planArchive } from "./package-zip.js";
import type { ArtifactRecord } from "./store.js";

/**
 * Regression tests for the evidence-integrity invariants that a real device
 * cannot be relied upon to exercise.
 *
 * `EvidenceStore` needs OPFS, which is unavailable in Node, so these cover the
 * stream-handling contract it depends on. The specific hazard: a source stream
 * that is abandoned rather than cancelled stalls the shared ADB connection,
 * because ADB multiplexes every logical stream over one USB link. A single
 * abandoned stream therefore hangs every subsequent module.
 */

/**
 * A stream that stays open until cancelled, modelling a device stream.
 *
 * A source that closes itself in `start()` is already finished, so cancelling it
 * is a no-op and would make these tests pass vacuously.
 */
function openEndedSource(chunk = "x"): {
    stream: ReadableStream<Uint8Array>;
    cancelled: () => boolean;
    cancelReason: () => unknown;
} {
    let wasCancelled = false;
    let reason: unknown;
    const encoder = new TextEncoder();

    const stream = new ReadableStream<Uint8Array>({
        pull(controller) {
            controller.enqueue(encoder.encode(chunk));
        },
        cancel(cancelReason) {
            wasCancelled = true;
            reason = cancelReason;
        },
    });

    return {
        stream,
        cancelled: () => wasCancelled,
        cancelReason: () => reason,
    };
}

/** Yields to the macrotask queue, where `pipeThrough` cancellation propagates. */
async function flush(): Promise<void> {
    await new Promise((resolve) => setTimeout(resolve, 0));
}

describe("source stream cleanup contract", () => {
    it("cancelling a piped-through stream propagates to the still-open source", async () => {
        // The path writeStream takes when failure occurs after pipeThrough.
        //
        // Propagation through the transform is asynchronous: it completes on a
        // later macrotask, not synchronously when `cancel()` resolves. Verified
        // against Node's implementation. Production code does not depend on
        // synchronous release, only that the source is released rather than
        // abandoned, so a flush here is correct rather than a papered-over race.
        const source = openEndedSource();
        const hashing = hashingStream();
        const piped = source.stream.pipeThrough(hashing.stream);

        await piped.cancel(new Error("write failed"));
        await flush();

        expect(source.cancelled()).toBe(true);
    });

    it("cancelling an un-piped source propagates directly", async () => {
        // The path taken when setup fails before the source is consumed at all
        // (path resolution, OPFS quota, createWritable lock).
        const source = openEndedSource();

        await source.stream.cancel(new Error("createWritable failed"));

        expect(source.cancelled()).toBe(true);
    });

    it("propagates the cancellation reason for diagnosis", async () => {
        const source = openEndedSource();
        const reason = new Error("quota exceeded");

        await source.stream.cancel(reason);

        expect(source.cancelReason()).toBe(reason);
    });

    it("cancelling a locked stream rejects, which is why cleanup must tolerate it", async () => {
        // writeStream/streamToArtifact wrap their cancel() calls in .catch()
        // precisely because the stream may already be locked by a pipe.
        const source = openEndedSource();
        const reader = source.stream.getReader();

        await expect(source.stream.cancel()).rejects.toThrow();

        reader.releaseLock();
    });

    it("a fully consumed stream reports no cancellation", async () => {
        const encoder = new TextEncoder();
        const stream = new ReadableStream<Uint8Array>({
            start(controller) {
                controller.enqueue(encoder.encode("done"));
                controller.close();
            },
            cancel() {
                throw new Error("should not be cancelled");
            },
        });

        await expect(hashStream(stream)).resolves.toMatchObject({ size: 4 });
    });
});

describe("truncation detection", () => {
    it("a truncated transfer hashes differently from the complete content", async () => {
        // This is what makes the re-read verification able to catch truncation:
        // the write hash covers only the bytes that actually passed through.
        const partial = await hashStream(streamOf("abc"));
        const complete = await hashStream(streamOf("abcdef"));

        expect(partial.size).toBe(3);
        expect(complete.size).toBe(6);
        expect(partial.sha256).not.toBe(complete.sha256);
        expect(partial.sha256).toBe(hashText("abc"));
    });

    it("counts bytes across an interrupted pipe", async () => {
        // Cancelling mid-pipe must leave the hasher reflecting only what flowed,
        // never the digest of the intended full content.
        const encoder = new TextEncoder();
        const source = new ReadableStream<Uint8Array>({
            start(controller) {
                controller.enqueue(encoder.encode("aaaa"));
                controller.enqueue(encoder.encode("bbbb"));
                controller.close();
            },
        });

        const hashing = hashingStream();
        const reader = source.pipeThrough(hashing.stream).getReader();

        await reader.read();
        await reader.cancel();

        const result = hashing.result();
        expect(result.size).toBeLessThan(8);
        expect(result.sha256).not.toBe(hashText("aaaabbbb"));
    });
});

/**
 * The size cap is the mechanism the connection-test profile relies on to stay
 * small against an unbounded source. `EvidenceStore` needs OPFS, so these
 * exercise the capping transform in isolation, mirroring how `writeStream`
 * composes it after the hashing stage.
 */
describe("size cap transform", () => {
    function capStream(maxBytes: number): {
        stream: TransformStream<Uint8Array, Uint8Array>;
        truncated: () => number | undefined;
    } {
        let stored = 0;
        let truncated: number | undefined;
        const stream = new TransformStream<Uint8Array, Uint8Array>({
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
                stored += remaining;
                truncated = maxBytes;
                controller.enqueue(chunk.subarray(0, remaining));
                controller.terminate();
            },
        });
        return { stream, truncated: () => truncated };
    }

    async function drain(stream: ReadableStream<Uint8Array>): Promise<number> {
        const reader = stream.getReader();
        let bytes = 0;
        for (;;) {
            const chunk = await reader.read();
            if (chunk.done) break;
            bytes += chunk.value.byteLength;
        }
        return bytes;
    }

    it("caps at an exact byte count, not a chunk boundary", async () => {
        const encoder = new TextEncoder();
        const source = new ReadableStream<Uint8Array>({
            start(controller) {
                controller.enqueue(encoder.encode("aaaaa"));
                controller.enqueue(encoder.encode("bbbbb"));
                controller.close();
            },
        });

        const cap = capStream(7);
        expect(await drain(source.pipeThrough(cap.stream))).toBe(7);
        expect(cap.truncated()).toBe(7);
    });

    it("leaves a source under the cap untouched and unflagged", async () => {
        const cap = capStream(1024);
        expect(await drain(streamOf("abcdef").pipeThrough(cap.stream))).toBe(6);
        expect(cap.truncated()).toBeUndefined();
    });

    it("the stored digest covers exactly the capped bytes", async () => {
        // The cap sits after the hashing stage in writeStream, so the recorded
        // hash must match the stored prefix — otherwise re-read verification
        // would fail on every capped artifact.
        const hashing = hashingStream();
        const cap = capStream(3);
        await drain(streamOf("abcdef").pipeThrough(cap.stream).pipeThrough(hashing.stream));

        expect(hashing.result().sha256).toBe(hashText("abc"));
        expect(cap.truncated()).toBe(3);
    });

    it("cancels an open-ended source once the cap is reached", async () => {
        // terminate() ends the pipe but leaves a device stream producing, so
        // writeStream cancels the source explicitly. Without that the shared ADB
        // transport stalls for every later module.
        const source = openEndedSource("0123456789");
        const cap = capStream(25);

        await drain(source.stream.pipeThrough(cap.stream));
        await source.stream.cancel().catch(() => undefined);
        await flush();

        expect(cap.truncated()).toBe(25);
        expect(source.cancelled()).toBe(true);
    });
});

describe("archive planning after analysis", () => {
    /**
     * Analysis writes its reports into the store after collection, so the plan
     * must be built from the store's live records rather than from the
     * acquisition summary. This is the invariant with evidentiary consequences:
     * a plan taken from the summary omits the reports, so they appear neither in
     * the ZIP nor in `hashes.csv`, and the examiner keeps an archive they
     * believe is complete.
     */
    const record = (name: string, content: string): ArtifactRecord => ({
        name,
        sha256: hashText(content),
        size: new TextEncoder().encode(content).length,
        acquiredAt: "2026-09-01T12:00:00.000Z",
        verified: true,
    });

    const collected: readonly ArtifactRecord[] = [
        record("getprop.txt", "[ro.build.type]: [user]"),
        record("acquisition.json", "{}"),
    ];

    const derived: readonly ArtifactRecord[] = [
        record(ANALYSIS_FILENAME, '{"format":"webadb-forensics-analysis"}'),
        record(ALERTS_FILENAME, "Level,Analyzer\n"),
        record(TIMELINE_FILENAME, "Event Time,Level\n"),
    ];

    it("includes the analysis reports in the archive and in hashes.csv", () => {
        const plan = planArchive("AQ-1", [...collected, ...derived]);

        for (const report of derived) {
            expect(plan.entries.some((entry) => entry.name === report.name)).toBe(true);
            expect(plan.hashesCsv).toContain(`${report.sha256},"${report.name}"`);
        }
    });

    it("nests reports under the acquisition directory like every other entry", () => {
        // Reports must be reachable by the same `*/name` globbing as collected
        // artifacts, so they cannot be exempt from the prefix.
        const plan = planArchive("AQ-1", [...collected, ...derived]);

        expect(plan.prefix).toBe("AQ-1/");
        // hashes.csv paths stay relative to that directory, so `sha256sum -c`
        // works from the extracted directory.
        expect(plan.hashesCsv).not.toContain("AQ-1/");
    });

    it("omits the reports when planned from the pre-analysis records", () => {
        // The regression this guards against directly: this is what the previous
        // code did, and it must not silently become true again.
        const stale = planArchive("AQ-1", collected);

        expect(stale.entries.some((entry) => entry.name === ANALYSIS_FILENAME)).toBe(false);
        expect(stale.hashesCsv).not.toContain(ANALYSIS_FILENAME);
    });

    it("never lets hashes.csv hash itself", () => {
        const plan = planArchive("AQ-1", [
            ...collected,
            ...derived,
            record(HASHES_FILENAME, "stale"),
        ]);

        expect(plan.entries.some((entry) => entry.name === HASHES_FILENAME)).toBe(false);
        expect(plan.hashesCsv).not.toContain(HASHES_FILENAME);
    });
});

function streamOf(text: string): ReadableStream<Uint8Array> {
    return new Blob([new TextEncoder().encode(text)]).stream() as ReadableStream<Uint8Array>;
}
