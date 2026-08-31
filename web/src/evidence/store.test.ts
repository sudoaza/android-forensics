import { describe, expect, it } from "vitest";

import { hashStream, hashingStream, hashText } from "./hasher.js";

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

function streamOf(text: string): ReadableStream<Uint8Array> {
    return new Blob([new TextEncoder().encode(text)]).stream() as ReadableStream<Uint8Array>;
}
