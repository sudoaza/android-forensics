import { sha256 } from "@noble/hashes/sha2.js";

/**
 * Incremental SHA-256 over streamed bytes.
 *
 * Artifacts are never materialized in memory: an APK or bugreport can be
 * hundreds of megabytes, and `crypto.subtle.digest` is one-shot only, so it
 * cannot be used on a stream without buffering the whole thing.
 */
export class Sha256Stream {
    #hash = sha256.create();
    #bytes = 0;
    #digest: string | undefined;

    update(chunk: Uint8Array): void {
        if (this.#digest !== undefined) {
            throw new Error("Sha256Stream already finalized");
        }
        this.#hash.update(chunk);
        this.#bytes += chunk.byteLength;
    }

    get bytes(): number {
        return this.#bytes;
    }

    /** Lowercase hex digest. Idempotent after the first call. */
    digest(): string {
        this.#digest ??= toHex(this.#hash.digest());
        return this.#digest;
    }
}

export function toHex(bytes: Uint8Array): string {
    let hex = "";
    for (const byte of bytes) {
        hex += byte.toString(16).padStart(2, "0");
    }
    return hex;
}

/**
 * A `TransformStream` that hashes and counts bytes as they pass through
 * untouched.
 *
 * Chunks are forwarded before hashing so back-pressure stays driven by the
 * consumer (the OPFS writer) rather than by hashing throughput.
 */
export function hashingStream(): {
    readonly stream: TransformStream<Uint8Array, Uint8Array>;
    /** Valid only after the stream completes. */
    result(): { sha256: string; size: number };
} {
    const hasher = new Sha256Stream();

    const stream = new TransformStream<Uint8Array, Uint8Array>({
        transform(chunk, controller) {
            controller.enqueue(chunk);
            hasher.update(chunk);
        },
    });

    return {
        stream,
        result: () => ({ sha256: hasher.digest(), size: hasher.bytes }),
    };
}

/** Hashes an entire stream, discarding the bytes. Used for verification reads. */
export async function hashStream(
    source: ReadableStream<Uint8Array>,
): Promise<{ sha256: string; size: number }> {
    const hasher = new Sha256Stream();
    const reader = source.getReader();
    try {
        for (;;) {
            const { done, value } = await reader.read();
            if (done) {
                break;
            }
            hasher.update(value);
        }
    } finally {
        reader.releaseLock();
    }
    return { sha256: hasher.digest(), size: hasher.bytes };
}

export function hashBytes(bytes: Uint8Array): string {
    return toHex(sha256(bytes));
}

export function hashText(text: string): string {
    return hashBytes(new TextEncoder().encode(text));
}
