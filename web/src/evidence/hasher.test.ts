import { describe, expect, it } from "vitest";

import { Sha256Stream, hashBytes, hashStream, hashText, hashingStream } from "./hasher.js";

// NIST-published SHA-256 test vectors, so a broken hash implementation cannot
// pass by agreeing with itself.
const EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const ABC_SHA256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

function chunks(...parts: string[]): ReadableStream<Uint8Array> {
    const encoder = new TextEncoder();
    return new ReadableStream<Uint8Array>({
        start(controller) {
            for (const part of parts) {
                controller.enqueue(encoder.encode(part));
            }
            controller.close();
        },
    });
}

describe("SHA-256 correctness", () => {
    it("matches known vectors", () => {
        expect(hashText("")).toBe(EMPTY_SHA256);
        expect(hashText("abc")).toBe(ABC_SHA256);
    });

    it("is independent of chunk boundaries", async () => {
        const oneChunk = await hashStream(chunks("abc"));
        const threeChunks = await hashStream(chunks("a", "b", "c"));

        expect(oneChunk.sha256).toBe(ABC_SHA256);
        expect(threeChunks.sha256).toBe(ABC_SHA256);
        expect(threeChunks.size).toBe(3);
    });

    it("hashes an empty stream", async () => {
        const result = await hashStream(chunks());

        expect(result.sha256).toBe(EMPTY_SHA256);
        expect(result.size).toBe(0);
    });
});

describe("Sha256Stream", () => {
    it("counts bytes as it hashes", () => {
        const hasher = new Sha256Stream();
        hasher.update(new TextEncoder().encode("abc"));

        expect(hasher.bytes).toBe(3);
        expect(hasher.digest()).toBe(ABC_SHA256);
    });

    it("returns a stable digest across calls", () => {
        const hasher = new Sha256Stream();
        hasher.update(new TextEncoder().encode("abc"));

        expect(hasher.digest()).toBe(hasher.digest());
    });

    it("refuses updates after finalization, rather than silently diverging", () => {
        const hasher = new Sha256Stream();
        hasher.update(new TextEncoder().encode("abc"));
        hasher.digest();

        expect(() => hasher.update(new Uint8Array([1]))).toThrow(/finalized/);
    });
});

describe("hashingStream", () => {
    it("passes bytes through unmodified while hashing", async () => {
        const hashing = hashingStream();
        const output = await new Response(
            chunks("a", "b", "c").pipeThrough(hashing.stream),
        ).text();

        expect(output).toBe("abc");
        expect(hashing.result()).toEqual({ sha256: ABC_SHA256, size: 3 });
    });

    it("handles a large multi-chunk payload", async () => {
        const block = "x".repeat(64 * 1024);
        const parts = Array.from({ length: 40 }, () => block);

        const hashing = hashingStream();
        await new Response(chunks(...parts).pipeThrough(hashing.stream)).arrayBuffer();

        const result = hashing.result();
        expect(result.size).toBe(block.length * 40);
        expect(result.sha256).toBe(hashText(parts.join("")));
    });
});

describe("hashBytes", () => {
    it("agrees with hashText for the same content", () => {
        expect(hashBytes(new TextEncoder().encode("abc"))).toBe(hashText("abc"));
    });
});
