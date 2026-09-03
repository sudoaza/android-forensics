/**
 * Random-access ZIP reader.
 *
 * Analysis has to read acquisitions that are already archives: an imported
 * `<id>.zip` from a previous run, another collector's AndroidQF output, and
 * eventually the `bugreport.zip` nested inside one. `client-zip` only writes,
 * so reading is implemented here rather than adding a dependency — the two
 * primitives needed are already native:
 *
 *   - `Blob.slice()`                     random access without loading the file
 *   - `DecompressionStream("deflate-raw")`  inflate, streaming
 *
 * Only the central directory is parsed up front, so opening a multi-hundred-
 * megabyte archive costs one small tail read regardless of its size.
 *
 * Entries are read through the central directory's recorded sizes rather than
 * the local header's, because an archive written by a streaming producer may
 * legitimately leave the local header's sizes zero (general-purpose bit 3) and
 * carry the real values in a trailing data descriptor.
 */

const EOCD_SIGNATURE = 0x0605_4b50;
const ZIP64_LOCATOR_SIGNATURE = 0x0706_4b50;
const ZIP64_EOCD_SIGNATURE = 0x0606_4b50;
const CENTRAL_ENTRY_SIGNATURE = 0x0201_4b50;
const LOCAL_HEADER_SIGNATURE = 0x0403_4b50;

const EOCD_FIXED_SIZE = 22;
const ZIP64_LOCATOR_SIZE = 20;
const CENTRAL_ENTRY_FIXED_SIZE = 46;
const LOCAL_HEADER_FIXED_SIZE = 30;

/** ZIP comments are length-prefixed with 16 bits, bounding the backwards scan. */
const MAX_COMMENT_SIZE = 0xffff;

const METHOD_STORE = 0;
const METHOD_DEFLATE = 8;

/** Sentinel written into 32-bit fields when the real value lives in a ZIP64 record. */
const U32_MAX = 0xffff_ffff;
const U16_MAX = 0xffff;

export interface ZipEntry {
    /** Entry name exactly as recorded in the archive. */
    readonly name: string;
    readonly compressedSize: number;
    readonly uncompressedSize: number;
    readonly compressionMethod: number;
    readonly crc32: number;
    readonly lastModified: Date;
    /** True for entries the archive marks as directories rather than files. */
    readonly directory: boolean;
}

interface CentralEntry extends ZipEntry {
    readonly localHeaderOffset: number;
}

export class ZipFormatError extends Error {
    constructor(message: string) {
        super(message);
        this.name = "ZipFormatError";
    }
}

export class ZipIntegrityError extends Error {
    constructor(message: string) {
        super(message);
        this.name = "ZipIntegrityError";
    }
}

function view(bytes: Uint8Array): DataView {
    return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
}

async function readSlice(blob: Blob, start: number, end: number): Promise<Uint8Array> {
    const clampedStart = Math.max(0, start);
    const clampedEnd = Math.min(blob.size, end);
    if (clampedEnd <= clampedStart) {
        return new Uint8Array(0);
    }
    return new Uint8Array(await blob.slice(clampedStart, clampedEnd).arrayBuffer());
}

/**
 * Reads a 64-bit little-endian value as a JS number.
 *
 * Sizes beyond `Number.MAX_SAFE_INTEGER` are rejected rather than silently
 * losing precision: a wrong offset would read the wrong bytes and produce a
 * plausible-looking artifact, which is the worst possible failure here.
 */
function readU64(data: DataView, offset: number): number {
    const value = data.getBigUint64(offset, true);
    if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
        throw new ZipFormatError(`ZIP64 value ${value} exceeds safe integer range`);
    }
    return Number(value);
}

/** MS-DOS date/time, interpreted as local time because the format carries no zone. */
function parseDosDateTime(time: number, date: number): Date {
    const day = date & 0x1f;
    const month = ((date >> 5) & 0x0f) - 1;
    const year = ((date >> 9) & 0x7f) + 1980;
    const seconds = (time & 0x1f) * 2;
    const minutes = (time >> 5) & 0x3f;
    const hours = (time >> 11) & 0x1f;
    return new Date(year, month, day, hours, minutes, seconds);
}

interface CentralDirectoryLocation {
    readonly offset: number;
    readonly size: number;
    readonly entryCount: number;
}

async function locateCentralDirectory(blob: Blob): Promise<CentralDirectoryLocation> {
    const tailSize = Math.min(blob.size, EOCD_FIXED_SIZE + MAX_COMMENT_SIZE);
    const tail = await readSlice(blob, blob.size - tailSize, blob.size);
    const tailView = view(tail);

    let eocdOffsetInTail = -1;
    for (let index = tail.byteLength - EOCD_FIXED_SIZE; index >= 0; index -= 1) {
        if (tailView.getUint32(index, true) === EOCD_SIGNATURE) {
            eocdOffsetInTail = index;
            break;
        }
    }

    if (eocdOffsetInTail < 0) {
        throw new ZipFormatError(
            "No end-of-central-directory record found. The file is not a ZIP archive, " +
                "or it is truncated.",
        );
    }

    let entryCount = tailView.getUint16(eocdOffsetInTail + 10, true);
    let size = tailView.getUint32(eocdOffsetInTail + 12, true);
    let offset = tailView.getUint32(eocdOffsetInTail + 16, true);

    const needsZip64 = entryCount === U16_MAX || size === U32_MAX || offset === U32_MAX;
    if (!needsZip64) {
        return { offset, size, entryCount };
    }

    const locatorOffsetInTail = eocdOffsetInTail - ZIP64_LOCATOR_SIZE;
    if (
        locatorOffsetInTail < 0 ||
        tailView.getUint32(locatorOffsetInTail, true) !== ZIP64_LOCATOR_SIGNATURE
    ) {
        throw new ZipFormatError(
            "Archive uses ZIP64 sentinel values but has no ZIP64 locator record.",
        );
    }

    const zip64EocdOffset = readU64(tailView, locatorOffsetInTail + 8);
    const zip64Eocd = await readSlice(blob, zip64EocdOffset, zip64EocdOffset + 56);
    const zip64View = view(zip64Eocd);

    if (
        zip64Eocd.byteLength < 56 ||
        zip64View.getUint32(0, true) !== ZIP64_EOCD_SIGNATURE
    ) {
        throw new ZipFormatError("ZIP64 end-of-central-directory record is missing or malformed.");
    }

    entryCount = readU64(zip64View, 32);
    size = readU64(zip64View, 40);
    offset = readU64(zip64View, 48);

    return { offset, size, entryCount };
}

/**
 * Reads the ZIP64 extended information extra field, when present.
 *
 * Fields appear in a fixed order but only when the corresponding 32-bit field
 * held the sentinel, so which values are present depends on the header.
 */
function readZip64Extra(
    extra: Uint8Array,
    present: { uncompressedSize: boolean; compressedSize: boolean; localHeaderOffset: boolean },
): { uncompressedSize?: number; compressedSize?: number; localHeaderOffset?: number } {
    const extraView = view(extra);
    let cursor = 0;

    while (cursor + 4 <= extra.byteLength) {
        const headerId = extraView.getUint16(cursor, true);
        const dataSize = extraView.getUint16(cursor + 2, true);
        const dataStart = cursor + 4;

        if (headerId !== 0x0001) {
            cursor = dataStart + dataSize;
            continue;
        }

        const result: {
            uncompressedSize?: number;
            compressedSize?: number;
            localHeaderOffset?: number;
        } = {};
        let fieldCursor = dataStart;

        if (present.uncompressedSize && fieldCursor + 8 <= dataStart + dataSize) {
            result.uncompressedSize = readU64(extraView, fieldCursor);
            fieldCursor += 8;
        }
        if (present.compressedSize && fieldCursor + 8 <= dataStart + dataSize) {
            result.compressedSize = readU64(extraView, fieldCursor);
            fieldCursor += 8;
        }
        if (present.localHeaderOffset && fieldCursor + 8 <= dataStart + dataSize) {
            result.localHeaderOffset = readU64(extraView, fieldCursor);
        }

        return result;
    }

    return {};
}

const utf8Decoder = new TextDecoder("utf-8");

/**
 * Decodes an entry name.
 *
 * Bit 11 of the general-purpose flags declares UTF-8. Anything else is legacy
 * CP437, but every producer that matters here (androidqf, this collector,
 * Android's `bugreportz`) writes ASCII names, for which the two encodings
 * agree, so UTF-8 is used throughout and the flag is not consulted.
 */
function decodeName(bytes: Uint8Array): string {
    return utf8Decoder.decode(bytes);
}

const CRC32_TABLE = (() => {
    const table = new Int32Array(256);
    for (let index = 0; index < 256; index += 1) {
        let value = index;
        for (let bit = 0; bit < 8; bit += 1) {
            value = value & 1 ? 0xedb8_8320 ^ (value >>> 1) : value >>> 1;
        }
        table[index] = value;
    }
    return table;
})();

/** Incremental CRC-32, so entry integrity is checked without buffering. */
export class Crc32 {
    #state = 0xffff_ffff;

    update(chunk: Uint8Array): void {
        let state = this.#state;
        for (const byte of chunk) {
            // Non-null assertion is safe: the index is masked to 0..255.
            state = CRC32_TABLE[(state ^ byte) & 0xff]! ^ (state >>> 8);
        }
        this.#state = state;
    }

    digest(): number {
        return (this.#state ^ 0xffff_ffff) >>> 0;
    }
}

/**
 * Translates an fnmatch pattern to a regular expression.
 *
 * fnmatch semantics are used deliberately, not glob semantics: MVT selects
 * acquisition files with `fnmatch.filter`, where `*` also matches `/`. Patterns
 * such as `*​/settings_*.txt` therefore require a directory component, which is
 * exactly why a flat archive is invisible to it. Matching MVT here means a
 * pattern behaves identically in both tools.
 */
export function fnmatchToRegExp(pattern: string): RegExp {
    let source = "";
    for (const character of pattern) {
        if (character === "*") {
            source += ".*";
        } else if (character === "?") {
            source += ".";
        } else {
            source += character.replaceAll(/[.*+?^${}()|[\]\\]/g, "\\$&");
        }
    }
    return new RegExp(`^${source}$`);
}

export class ZipArchive {
    readonly #blob: Blob;
    readonly #entries: ReadonlyMap<string, CentralEntry>;

    private constructor(blob: Blob, entries: ReadonlyMap<string, CentralEntry>) {
        this.#blob = blob;
        this.#entries = entries;
    }

    static async open(blob: Blob): Promise<ZipArchive> {
        const location = await locateCentralDirectory(blob);
        const directory = await readSlice(blob, location.offset, location.offset + location.size);
        const directoryView = view(directory);

        const entries = new Map<string, CentralEntry>();
        let cursor = 0;

        for (let index = 0; index < location.entryCount; index += 1) {
            if (cursor + CENTRAL_ENTRY_FIXED_SIZE > directory.byteLength) {
                throw new ZipFormatError(
                    `Central directory ends after ${index} of ${location.entryCount} entries.`,
                );
            }
            if (directoryView.getUint32(cursor, true) !== CENTRAL_ENTRY_SIGNATURE) {
                throw new ZipFormatError(`Malformed central directory entry at offset ${cursor}.`);
            }

            const compressionMethod = directoryView.getUint16(cursor + 10, true);
            const modTime = directoryView.getUint16(cursor + 12, true);
            const modDate = directoryView.getUint16(cursor + 14, true);
            const crc32 = directoryView.getUint32(cursor + 16, true);
            let compressedSize = directoryView.getUint32(cursor + 20, true);
            let uncompressedSize = directoryView.getUint32(cursor + 24, true);
            const nameLength = directoryView.getUint16(cursor + 28, true);
            const extraLength = directoryView.getUint16(cursor + 30, true);
            const commentLength = directoryView.getUint16(cursor + 32, true);
            const externalAttributes = directoryView.getUint32(cursor + 38, true);
            let localHeaderOffset = directoryView.getUint32(cursor + 42, true);

            const nameStart = cursor + CENTRAL_ENTRY_FIXED_SIZE;
            const extraStart = nameStart + nameLength;
            const name = decodeName(directory.subarray(nameStart, extraStart));

            const zip64 = readZip64Extra(directory.subarray(extraStart, extraStart + extraLength), {
                uncompressedSize: uncompressedSize === U32_MAX,
                compressedSize: compressedSize === U32_MAX,
                localHeaderOffset: localHeaderOffset === U32_MAX,
            });
            uncompressedSize = zip64.uncompressedSize ?? uncompressedSize;
            compressedSize = zip64.compressedSize ?? compressedSize;
            localHeaderOffset = zip64.localHeaderOffset ?? localHeaderOffset;

            // A directory is signalled by a trailing slash, or by the MS-DOS
            // directory attribute in the high byte of the external attributes.
            const directoryEntry = name.endsWith("/") || (externalAttributes & 0x10) !== 0;

            entries.set(name, {
                name,
                compressedSize,
                uncompressedSize,
                compressionMethod,
                crc32,
                lastModified: parseDosDateTime(modTime, modDate),
                directory: directoryEntry,
                localHeaderOffset,
            });

            cursor = extraStart + extraLength + commentLength;
        }

        return new ZipArchive(blob, entries);
    }

    get entries(): readonly ZipEntry[] {
        return [...this.#entries.values()];
    }

    /** Entry names in central-directory order. */
    get names(): readonly string[] {
        return [...this.#entries.keys()];
    }

    has(name: string): boolean {
        return this.#entries.has(name);
    }

    entry(name: string): ZipEntry | undefined {
        return this.#entries.get(name);
    }

    /** Names matching an fnmatch pattern, in central-directory order. */
    match(pattern: string): readonly string[] {
        const expression = fnmatchToRegExp(pattern);
        return this.names.filter((name) => expression.test(name));
    }

    #require(name: string): CentralEntry {
        const entry = this.#entries.get(name);
        if (entry === undefined) {
            throw new ZipFormatError(`No such entry in archive: ${name}`);
        }
        if (entry.directory) {
            throw new ZipFormatError(`Entry is a directory, not a file: ${name}`);
        }
        return entry;
    }

    /**
     * Locates an entry's payload.
     *
     * The local header must be read even though the central directory already
     * has the metadata: the name and extra fields there can differ in length
     * from their central-directory counterparts, and the payload begins after
     * them.
     */
    async #dataRange(entry: CentralEntry): Promise<{ start: number; end: number }> {
        const header = await readSlice(
            this.#blob,
            entry.localHeaderOffset,
            entry.localHeaderOffset + LOCAL_HEADER_FIXED_SIZE,
        );
        if (header.byteLength < LOCAL_HEADER_FIXED_SIZE) {
            throw new ZipFormatError(`Truncated local header for ${entry.name}.`);
        }

        const headerView = view(header);
        if (headerView.getUint32(0, true) !== LOCAL_HEADER_SIGNATURE) {
            throw new ZipFormatError(
                `Local header signature missing for ${entry.name}; the archive is corrupt or ` +
                    "the central directory offsets are wrong.",
            );
        }

        const nameLength = headerView.getUint16(26, true);
        const extraLength = headerView.getUint16(28, true);
        const start = entry.localHeaderOffset + LOCAL_HEADER_FIXED_SIZE + nameLength + extraLength;

        return { start, end: start + entry.compressedSize };
    }

    /**
     * Streams an entry's decompressed bytes, verifying CRC-32 and length at end
     * of stream.
     *
     * Verification is not optional: an entry that inflates to plausible content
     * but disagrees with its recorded CRC is corrupt, and analysing it would
     * produce findings about bytes the device never sent. The error surfaces on
     * the stream rather than the call, since it is only knowable at the end.
     */
    async stream(name: string): Promise<ReadableStream<Uint8Array>> {
        const entry = this.#require(name);
        const { start, end } = await this.#dataRange(entry);

        if (
            entry.compressionMethod !== METHOD_STORE &&
            entry.compressionMethod !== METHOD_DEFLATE
        ) {
            throw new ZipFormatError(
                `Entry ${name} uses unsupported compression method ${entry.compressionMethod}. ` +
                    "Only stored and deflated entries can be read.",
            );
        }

        const raw = this.#blob.slice(start, end).stream() as ReadableStream<Uint8Array>;
        // `DecompressionStream.writable` is typed as accepting `BufferSource`,
        // which is wider than `Uint8Array` and so not a valid `pipeThrough` pair.
        // The cast narrows it; what actually flows through is always `Uint8Array`.
        const decompressed =
            entry.compressionMethod === METHOD_DEFLATE
                ? raw.pipeThrough(
                      new DecompressionStream(
                          "deflate-raw",
                      ) as unknown as ReadableWritablePair<Uint8Array, Uint8Array>,
                  )
                : raw;

        const crc = new Crc32();
        let bytes = 0;

        return decompressed.pipeThrough(
            new TransformStream<Uint8Array, Uint8Array>({
                transform(chunk, controller) {
                    controller.enqueue(chunk);
                    crc.update(chunk);
                    bytes += chunk.byteLength;
                },
                flush() {
                    if (bytes !== entry.uncompressedSize) {
                        throw new ZipIntegrityError(
                            `Entry ${name} inflated to ${bytes} bytes but the archive records ` +
                                `${entry.uncompressedSize}.`,
                        );
                    }
                    const actual = crc.digest();
                    if (actual !== entry.crc32) {
                        throw new ZipIntegrityError(
                            `Entry ${name} failed its CRC-32 check: computed ` +
                                `${actual.toString(16)}, archive records ` +
                                `${entry.crc32.toString(16)}.`,
                        );
                    }
                },
            }),
        );
    }

    /** Reads an entry fully into memory. For bounded artifacts only. */
    async bytes(name: string): Promise<Uint8Array> {
        const stream = await this.stream(name);
        const chunks: Uint8Array[] = [];
        let total = 0;

        const reader = stream.getReader();
        try {
            for (;;) {
                const { done, value } = await reader.read();
                if (done) {
                    break;
                }
                chunks.push(value);
                total += value.byteLength;
            }
        } finally {
            reader.releaseLock();
        }

        const result = new Uint8Array(total);
        let offset = 0;
        for (const chunk of chunks) {
            result.set(chunk, offset);
            offset += chunk.byteLength;
        }
        return result;
    }

    async text(name: string): Promise<string> {
        // `fatal: false` deliberately: log artifacts routinely contain bytes
        // that are not valid UTF-8, and replacing them is better than refusing
        // to analyse the file at all.
        return new TextDecoder("utf-8").decode(await this.bytes(name));
    }
}
