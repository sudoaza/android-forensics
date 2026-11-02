import { makeZip } from "client-zip";
import { describe, expect, it } from "vitest";

import { Crc32, ZipArchive, ZipIntegrityError, fnmatchToRegExp } from "./zip-reader.js";

/**
 * The reader is exercised against archives produced by `client-zip`, the same
 * writer the export path uses. Hand-built byte fixtures would test this file
 * against my own understanding of the format rather than against the archives
 * examiners actually receive.
 *
 * A deflated fixture is built by hand, because `client-zip` only stores.
 */

async function zipBlob(
    files: readonly { name: string; input: string | Uint8Array }[],
): Promise<Blob> {
    const stream = makeZip(
        files.map((file) => ({ ...file, lastModified: new Date("2026-01-02T03:04:06Z") })),
    );
    return new Response(stream as ReadableStream<Uint8Array>).blob();
}

describe("fnmatch translation", () => {
    it("treats * as matching across separators, as fnmatch does", () => {
        // This is the whole reason MVT cannot see a flat archive: `*` spans `/`,
        // so the pattern demands a directory component that is not there.
        expect(fnmatchToRegExp("*/getprop.txt").test("AQ-1/getprop.txt")).toBe(true);
        expect(fnmatchToRegExp("*/getprop.txt").test("a/b/c/getprop.txt")).toBe(true);
        expect(fnmatchToRegExp("*/getprop.txt").test("getprop.txt")).toBe(false);
    });

    it("matches the settings and logs patterns MVT uses", () => {
        expect(fnmatchToRegExp("*/settings_*.txt").test("AQ-1/settings_secure.txt")).toBe(true);
        expect(fnmatchToRegExp("*/logs/*").test("AQ-1/logs/dmesg.txt")).toBe(true);
        expect(fnmatchToRegExp("*/logs/*").test("AQ-1/logcat.txt")).toBe(false);
    });

    it("escapes regex metacharacters in literal segments", () => {
        expect(fnmatchToRegExp("a.b+c.txt").test("a.b+c.txt")).toBe(true);
        expect(fnmatchToRegExp("a.b+c.txt").test("axbxc.txt")).toBe(false);
    });

    it("treats ? as exactly one character", () => {
        expect(fnmatchToRegExp("logcat?.txt").test("logcat1.txt")).toBe(true);
        expect(fnmatchToRegExp("logcat?.txt").test("logcat.txt")).toBe(false);
    });
});

describe("CRC-32", () => {
    it("matches the standard check value for \"123456789\"", () => {
        // The canonical CRC-32 test vector: 0xcbf43926.
        const crc = new Crc32();
        crc.update(new TextEncoder().encode("123456789"));
        expect(crc.digest()).toBe(0xcbf4_3926);
    });

    it("is unaffected by chunk boundaries", () => {
        const whole = new Crc32();
        whole.update(new TextEncoder().encode("the quick brown fox"));

        const split = new Crc32();
        split.update(new TextEncoder().encode("the quick "));
        split.update(new TextEncoder().encode("brown fox"));

        expect(split.digest()).toBe(whole.digest());
    });

    it("reports the empty-input identity", () => {
        expect(new Crc32().digest()).toBe(0);
    });
});

describe("ZipArchive", () => {
    it("lists entries and reads stored text", async () => {
        const archive = await ZipArchive.open(
            await zipBlob([
                { name: "AQ-1/getprop.txt", input: "[ro.build.version.sdk]: [33]\n" },
                { name: "AQ-1/settings_secure.txt", input: "accessibility_enabled=1\n" },
            ]),
        );

        expect(archive.names).toEqual(["AQ-1/getprop.txt", "AQ-1/settings_secure.txt"]);
        expect(await archive.text("AQ-1/getprop.txt")).toBe("[ro.build.version.sdk]: [33]\n");
    });

    it("matches entries with MVT's own patterns", async () => {
        const archive = await ZipArchive.open(
            await zipBlob([
                { name: "AQ-1/getprop.txt", input: "x" },
                { name: "AQ-1/settings_global.txt", input: "x" },
                { name: "AQ-1/settings_secure.txt", input: "x" },
                { name: "AQ-1/logs/dmesg.txt", input: "x" },
            ]),
        );

        expect(archive.match("*/settings_*.txt")).toEqual([
            "AQ-1/settings_global.txt",
            "AQ-1/settings_secure.txt",
        ]);
        expect(archive.match("*/logs/*")).toEqual(["AQ-1/logs/dmesg.txt"]);
    });

    it("reads an entry larger than a single chunk intact", async () => {
        // Exercises the streaming path across chunk boundaries, and the
        // length/CRC check at flush.
        const payload = "0123456789abcdef".repeat(64 * 1024);
        const archive = await ZipArchive.open(
            await zipBlob([{ name: "AQ-1/logcat.txt", input: payload }]),
        );

        const text = await archive.text("AQ-1/logcat.txt");
        expect(text.length).toBe(payload.length);
        expect(text).toBe(payload);
    });

    it("preserves bytes that are not valid UTF-8 rather than refusing the entry", async () => {
        // Real logcat and tombstone artifacts contain arbitrary bytes.
        const bytes = new Uint8Array([0x41, 0xff, 0xfe, 0x42]);
        const archive = await ZipArchive.open(
            await zipBlob([{ name: "AQ-1/logs/tombstone", input: bytes }]),
        );

        expect(await archive.bytes("AQ-1/logs/tombstone")).toEqual(bytes);
        expect(await archive.text("AQ-1/logs/tombstone")).toContain("A");
    });

    it("reports the entry's recorded size and CRC", async () => {
        const archive = await ZipArchive.open(
            await zipBlob([{ name: "AQ-1/x.txt", input: "123456789" }]),
        );

        const entry = archive.entry("AQ-1/x.txt");
        expect(entry?.uncompressedSize).toBe(9);
        expect(entry?.crc32).toBe(0xcbf4_3926);
    });

    it("rejects a file that is not a ZIP archive", async () => {
        await expect(ZipArchive.open(new Blob(["not a zip"]))).rejects.toThrow(
            /not a ZIP archive/,
        );
    });

    it("rejects reads of entries that do not exist", async () => {
        const archive = await ZipArchive.open(
            await zipBlob([{ name: "AQ-1/x.txt", input: "x" }]),
        );
        await expect(archive.text("AQ-1/missing.txt")).rejects.toThrow(/No such entry/);
    });

    it("detects a corrupted entry payload via CRC-32", async () => {
        // The integrity guarantee that matters: analysing bytes the device never
        // sent would produce findings about fiction. Flipping a payload byte
        // leaves a structurally valid archive whose CRC no longer agrees.
        const original = new Uint8Array(
            await (await zipBlob([{ name: "AQ-1/x.txt", input: "0123456789" }])).arrayBuffer(),
        );

        // Stored entries put the payload straight after the local header, so the
        // plaintext can be located and altered directly.
        const needle = new TextEncoder().encode("0123456789");
        const payloadOffset = original.findIndex(
            (_byte, index) =>
                index + needle.length <= original.length &&
                needle.every((value, cursor) => original[index + cursor] === value),
        );
        expect(payloadOffset).toBeGreaterThan(0);

        const corrupted = original.slice();
        corrupted[payloadOffset] = 0x58;

        const archive = await ZipArchive.open(new Blob([corrupted as BlobPart]));
        await expect(archive.text("AQ-1/x.txt")).rejects.toThrow(ZipIntegrityError);
    });

    it("reads deflated entries", async () => {
        // client-zip only stores, so this fixture is compressed explicitly to
        // cover the DecompressionStream path that bugreport.zip will need.
        const payload = "compress me ".repeat(512);
        const archive = await ZipArchive.open(await deflatedZip("AQ-1/c.txt", payload));

        expect(archive.entry("AQ-1/c.txt")?.compressionMethod).toBe(8);
        expect(await archive.text("AQ-1/c.txt")).toBe(payload);
    });
});

/**
 * Builds a single-entry archive with one deflated member.
 *
 * Written by hand because no dependency here can produce compressed output, and
 * `bugreport.zip` — the archive that motivates deflate support — is always
 * compressed.
 */
async function deflatedZip(name: string, content: string): Promise<Blob> {
    const raw = new TextEncoder().encode(content);
    const compressed = new Uint8Array(
        await new Response(
            new Blob([raw as BlobPart])
                .stream()
                .pipeThrough(new CompressionStream("deflate-raw")),
        ).arrayBuffer(),
    );

    const crc = new Crc32();
    crc.update(raw);
    const checksum = crc.digest();
    const nameBytes = new TextEncoder().encode(name);

    const local = new Uint8Array(30 + nameBytes.length);
    const localView = new DataView(local.buffer);
    localView.setUint32(0, 0x0403_4b50, true);
    localView.setUint16(4, 20, true);
    localView.setUint16(8, 8, true);
    localView.setUint32(14, checksum, true);
    localView.setUint32(18, compressed.length, true);
    localView.setUint32(22, raw.length, true);
    localView.setUint16(26, nameBytes.length, true);
    local.set(nameBytes, 30);

    const central = new Uint8Array(46 + nameBytes.length);
    const centralView = new DataView(central.buffer);
    centralView.setUint32(0, 0x0201_4b50, true);
    centralView.setUint16(4, 20, true);
    centralView.setUint16(6, 20, true);
    centralView.setUint16(10, 8, true);
    centralView.setUint32(16, checksum, true);
    centralView.setUint32(20, compressed.length, true);
    centralView.setUint32(24, raw.length, true);
    centralView.setUint16(28, nameBytes.length, true);
    centralView.setUint32(42, 0, true);
    central.set(nameBytes, 46);

    const centralOffset = local.length + compressed.length;
    const eocd = new Uint8Array(22);
    const eocdView = new DataView(eocd.buffer);
    eocdView.setUint32(0, 0x0605_4b50, true);
    eocdView.setUint16(8, 1, true);
    eocdView.setUint16(10, 1, true);
    eocdView.setUint32(12, central.length, true);
    eocdView.setUint32(16, centralOffset, true);

    return new Blob([local, compressed, central, eocd] as BlobPart[]);
}
