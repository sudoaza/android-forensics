import type { ArtifactRecord, EvidenceStore } from "../evidence/store.js";
import { hashStream } from "../evidence/hasher.js";
import { HASHES_FILENAME } from "../evidence/package-zip.js";
import { ZipArchive, fnmatchToRegExp } from "./zip-reader.js";

/**
 * The read interface analysis runs against.
 *
 * Two things must be analysable through exactly one code path:
 *
 *   1. the acquisition just collected, still in OPFS
 *   2. an archive imported from disk — one of ours from a previous run, or
 *      another collector's AndroidQF output
 *
 * If those diverged, analysis would only ever be exercised on the live path and
 * the offline path would rot. Everything downstream therefore sees only this
 * interface, and never learns which it has.
 *
 * Names are always archive-relative and prefixed, e.g.
 * `AQ-20260901-101500-1a2b/getprop.txt`. The prefix is not cosmetic: MVT selects
 * files with `fnmatch` patterns like `*​/getprop.txt`, where `*` also spans `/`,
 * so a flat layout matches nothing. Keeping the same shape here means a pattern
 * behaves identically in this analyzer and in MVT.
 */
export interface ArtifactSource {
    /** Identifies the acquisition, for the report. */
    readonly acquisitionId: string;
    /** Where this source came from, recorded in the report's provenance. */
    readonly origin: "opfs" | "zip";
    /** Every entry name, prefixed. */
    readonly names: readonly string[];

    /** Names matching an fnmatch pattern, in archive order. */
    match(pattern: string): readonly string[];
    text(name: string): Promise<string>;
    bytes(name: string): Promise<Uint8Array>;
    stream(name: string): Promise<ReadableStream<Uint8Array>>;
    /** Uncompressed size, without reading the entry. */
    size(name: string): number | undefined;
}

/**
 * The single entry a pattern is expected to match.
 *
 * Returns `undefined` when absent, because a missing artifact is a normal
 * condition — the Quick profile has no `dumpsys.txt`, and not every device
 * yields a bugreport. Analyzers must distinguish "not collected" from "collected
 * and clean", so this never throws.
 */
export function firstMatch(source: ArtifactSource, pattern: string): string | undefined {
    return source.match(pattern)[0];
}

const ARCHIVE_ROOT_PATTERN = /^[^/]+/;

/** Reads an acquisition spooled in OPFS, presenting it with an archive prefix. */
export class StoreSource implements ArtifactSource {
    readonly acquisitionId: string;
    readonly origin = "opfs" as const;

    readonly #store: EvidenceStore;
    readonly #records: ReadonlyMap<string, ArtifactRecord>;
    readonly #prefix: string;

    constructor(store: EvidenceStore, records: readonly ArtifactRecord[]) {
        this.#store = store;
        this.acquisitionId = store.acquisitionId;
        this.#prefix = `${store.acquisitionId}/`;
        this.#records = new Map(records.map((record) => [`${this.#prefix}${record.name}`, record]));
    }

    get names(): readonly string[] {
        return [...this.#records.keys()];
    }

    match(pattern: string): readonly string[] {
        const expression = fnmatchToRegExp(pattern);
        return this.names.filter((name) => expression.test(name));
    }

    size(name: string): number | undefined {
        return this.#records.get(name)?.size;
    }

    /** Strips the presentation prefix to get the store's own artifact name. */
    #storeName(name: string): string {
        if (!name.startsWith(this.#prefix)) {
            throw new Error(`Name is outside this acquisition: ${name}`);
        }
        return name.slice(this.#prefix.length);
    }

    async stream(name: string): Promise<ReadableStream<Uint8Array>> {
        const file = await this.#store.openFile(this.#storeName(name));
        return file.stream() as ReadableStream<Uint8Array>;
    }

    async bytes(name: string): Promise<Uint8Array> {
        const file = await this.#store.openFile(this.#storeName(name));
        return new Uint8Array(await file.arrayBuffer());
    }

    async text(name: string): Promise<string> {
        const file = await this.#store.openFile(this.#storeName(name));
        return file.text();
    }
}

/** Reads an acquisition from an imported ZIP. */
export class ZipSource implements ArtifactSource {
    readonly acquisitionId: string;
    readonly origin = "zip" as const;

    readonly #archive: ZipArchive;

    private constructor(archive: ZipArchive, acquisitionId: string) {
        this.#archive = archive;
        this.acquisitionId = acquisitionId;
    }

    static async open(blob: Blob, filename?: string): Promise<ZipSource> {
        const archive = await ZipArchive.open(blob);
        return new ZipSource(archive, await deriveAcquisitionId(archive, filename));
    }

    get names(): readonly string[] {
        return this.#archive.entries.filter((entry) => !entry.directory).map((entry) => entry.name);
    }

    match(pattern: string): readonly string[] {
        const expression = fnmatchToRegExp(pattern);
        return this.names.filter((name) => expression.test(name));
    }

    size(name: string): number | undefined {
        return this.#archive.entry(name)?.uncompressedSize;
    }

    async stream(name: string): Promise<ReadableStream<Uint8Array>> {
        return this.#archive.stream(name);
    }

    async bytes(name: string): Promise<Uint8Array> {
        return this.#archive.bytes(name);
    }

    async text(name: string): Promise<string> {
        return this.#archive.text(name);
    }

    /**
     * Recomputes every entry's SHA-256 and compares it with the archive's own
     * `hashes.csv`.
     *
     * Run before analysis on an imported archive. Findings derived from an
     * archive whose contents no longer match its manifest would be
     * indefensible, and the archive is the only thing an examiner has at this
     * point — there is no device left to re-ask.
     */
    async verify(
        onProgress?: (name: string, index: number, total: number) => void,
    ): Promise<VerificationReport> {
        const hashesEntry = this.match(`*/${HASHES_FILENAME}`)[0] ?? this.match(HASHES_FILENAME)[0];
        if (hashesEntry === undefined) {
            return {
                status: "unverifiable",
                reason: `The archive contains no ${HASHES_FILENAME}, so its contents cannot be checked against a manifest.`,
                checked: 0,
                mismatches: [],
                missing: [],
                unlisted: [],
            };
        }

        const expected = parseHashesCsv(await this.text(hashesEntry));
        const root = ARCHIVE_ROOT_PATTERN.exec(hashesEntry)?.[0] ?? "";
        const prefix = root === "" ? "" : `${root}/`;

        const mismatches: HashMismatch[] = [];
        const missing: string[] = [];
        const present = new Set(this.names);

        let index = 0;
        for (const [relative, sha256] of expected) {
            const name = `${prefix}${relative}`;
            onProgress?.(relative, index, expected.size);
            index += 1;

            if (!present.has(name)) {
                missing.push(relative);
                continue;
            }

            const actual = await hashStream(await this.stream(name));
            if (actual.sha256 !== sha256) {
                mismatches.push({ name: relative, expected: sha256, actual: actual.sha256 });
            }
        }

        // Entries present but absent from the manifest. Not a corruption of what
        // the manifest covers, but content of unknown provenance that analysis
        // would otherwise treat as evidence.
        const unlisted = this.names
            .map((name) => (prefix === "" ? name : name.slice(prefix.length)))
            .filter((relative) => relative !== HASHES_FILENAME && !expected.has(relative));

        return {
            status: mismatches.length === 0 && missing.length === 0 ? "verified" : "failed",
            reason: undefined,
            checked: expected.size,
            mismatches,
            missing,
            unlisted,
        };
    }
}

export interface HashMismatch {
    readonly name: string;
    readonly expected: string;
    readonly actual: string;
}

export interface VerificationReport {
    /**
     * `unverifiable` is distinct from `failed`: an archive with no manifest has
     * not been shown to be wrong, only unproven, and an examiner must be able to
     * tell those apart.
     */
    readonly status: "verified" | "failed" | "unverifiable";
    readonly reason: string | undefined;
    readonly checked: number;
    readonly mismatches: readonly HashMismatch[];
    /** Listed in the manifest but absent from the archive. */
    readonly missing: readonly string[];
    /** Present in the archive but absent from the manifest. */
    readonly unlisted: readonly string[];
}

/**
 * Parses `hashes.csv` (`SHA256,FILE`, path quoted per RFC 4180).
 *
 * Written to accept AndroidQF's output as well as ours, so an archive from the
 * original collector can be verified and analysed here too.
 */
export function parseHashesCsv(content: string): Map<string, string> {
    const entries = new Map<string, string>();

    for (const line of content.split("\n")) {
        const trimmed = line.trim();
        if (trimmed === "" || trimmed === "SHA256,FILE") {
            continue;
        }

        const comma = trimmed.indexOf(",");
        if (comma < 0) {
            continue;
        }

        const sha256 = trimmed.slice(0, comma).trim().toLowerCase();
        let path = trimmed.slice(comma + 1).trim();
        if (path.startsWith('"') && path.endsWith('"') && path.length >= 2) {
            path = path.slice(1, -1).replaceAll('""', '"');
        }

        if (/^[0-9a-f]{64}$/.test(sha256) && path !== "") {
            entries.set(path, sha256);
        }
    }

    return entries;
}

/**
 * Determines the acquisition's identity.
 *
 * `acquisition.json`'s `uuid` is authoritative, since it is what the collector
 * recorded. The archive's root directory and then the filename are fallbacks,
 * for an archive whose manifest is unreadable — which is precisely when an
 * examiner most needs the analysis to still run.
 */
function deriveAcquisitionId(archive: ZipArchive, filename?: string): Promise<string> {
    return (async () => {
        const manifestPattern = fnmatchToRegExp("*acquisition.json");
        const manifest = archive.entries.find(
            (entry) => !entry.directory && manifestPattern.test(entry.name),
        );
        if (manifest !== undefined) {
            try {
                const parsed: unknown = JSON.parse(await archive.text(manifest.name));
                if (typeof parsed === "object" && parsed !== null) {
                    const uuid = (parsed as { uuid?: unknown }).uuid;
                    if (typeof uuid === "string" && uuid !== "") {
                        return uuid;
                    }
                }
            } catch {
                // An unreadable or corrupt manifest is exactly when the fallbacks
                // below matter, so this is not fatal.
            }
        }

        const roots = new Set<string>();
        for (const entry of archive.entries) {
            const root = ARCHIVE_ROOT_PATTERN.exec(entry.name)?.[0];
            if (root !== undefined && root !== entry.name) {
                roots.add(root);
            }
        }
        if (roots.size === 1) {
            const [only] = roots;
            if (only !== undefined) {
                return only;
            }
        }

        if (filename !== undefined && filename !== "") {
            return filename.replace(/\.zip$/i, "");
        }
        return "imported-acquisition";
    })();
}
