import { hashBytes } from "../../evidence/hasher.js";

/**
 * STIX2 indicator loading.
 *
 * The format is adopted rather than invented so that the published indicator
 * sets — Amnesty's and others distributed as `.stix2` bundles — can be consumed
 * unchanged, and so indicators written for MVT work here without translation.
 *
 * Only the subset carrying actual indicators is interpreted: `indicator`
 * objects, plus `malware` and `report` objects used to name the collection each
 * indicator belongs to. Relationships attribute an indicator to its collection.
 * The rest of STIX2 is ignored, deliberately: a partial reader that is honest
 * about what it read beats a complete one nobody can audit.
 *
 * Patterns are read in the narrow form these bundles actually use — a single
 * comparison, `[<object>:<property>=<value>]`. A full STIX pattern grammar
 * (booleans, qualifiers, multiple comparisons) is not supported, and anything
 * unrecognised is counted and reported rather than silently dropped, so a bundle
 * whose indicators did not load cannot be mistaken for one with no matches.
 */

export type IndicatorType =
    | "domain"
    | "url"
    | "email"
    | "process"
    | "file_name"
    | "file_path"
    | "file_md5"
    | "file_sha1"
    | "file_sha256"
    | "app_id"
    | "app_cert_hash"
    | "android_property"
    | "ios_profile_id";

/** STIX pattern property to internal type. Keys are normalised before lookup. */
const PATTERN_TYPES: Readonly<Record<string, IndicatorType>> = {
    "domain-name:value": "domain",
    // IP addresses are held with domains: every consumer checks a network
    // endpoint against both, and separating them would only add a second lookup.
    "ipv4-addr:value": "domain",
    "ipv6-addr:value": "domain",
    "url:value": "url",
    "email-addr:value": "email",
    "process:name": "process",
    "file:name": "file_name",
    "file:path": "file_path",
    "file:hashes.md5": "file_md5",
    "file:hashes.sha1": "file_sha1",
    "file:hashes.sha256": "file_sha256",
    "app:id": "app_id",
    "app:cert.md5": "app_cert_hash",
    "app:cert.sha1": "app_cert_hash",
    "app:cert.sha256": "app_cert_hash",
    "android-property:name": "android_property",
    "configuration-profile:id": "ios_profile_id",
};

export interface Indicator {
    readonly type: IndicatorType;
    readonly value: string;
    /** Collection name, e.g. the malware family or report. */
    readonly collection: string;
    /** Bundle filename, for provenance. */
    readonly source: string;
}

export interface IndicatorCollection {
    readonly name: string;
    readonly description: string;
    readonly counts: Readonly<Record<string, number>>;
    readonly total: number;
}

export interface LoadedBundle {
    readonly filename: string;
    readonly sha256: string;
    readonly origin: "bundled" | "supplied";
    readonly indicators: readonly Indicator[];
    readonly collections: readonly IndicatorCollection[];
    /**
     * Patterns present in the bundle that this reader could not interpret.
     *
     * Surfaced rather than swallowed: an unread indicator is a detection that
     * will never fire, and the examiner has to be able to see that it happened.
     */
    readonly unsupportedPatterns: readonly string[];
    readonly total: number;
}

/**
 * Normalises a STIX pattern key.
 *
 * The spec requires quoting for hash algorithm names containing a hyphen
 * (`file:hashes.'SHA-256'`), while bundles in the wild also use the unquoted
 * lowercase form. Both are folded to one spelling so a legitimate indicator is
 * never dropped over punctuation.
 */
function normalisePatternKey(key: string): string {
    const trimmed = key.trim();
    for (const separator of ["hashes.", "cert."]) {
        const index = trimmed.indexOf(separator);
        if (index >= 0) {
            const prefix = trimmed.slice(0, index + separator.length);
            const algorithm = trimmed
                .slice(index + separator.length)
                .replaceAll("'", "")
                .replaceAll('"', "")
                .replaceAll("-", "")
                .toLowerCase();
            return `${prefix}${algorithm}`;
        }
    }
    return trimmed;
}

/** Strips the quoting and brackets around a pattern's value. */
function normalisePatternValue(value: string): string {
    return value.trim().replace(/^['"]/, "").replace(/['"]$/, "").trim();
}

interface ParsedPattern {
    readonly type: IndicatorType;
    readonly value: string;
}

/**
 * Parses a single-comparison STIX pattern.
 *
 * Returns `undefined` for anything else — a compound pattern, an unsupported
 * object type, or a malformed string — so the caller can record it as
 * unsupported.
 */
export function parsePattern(pattern: string): ParsedPattern | undefined {
    const inner = pattern.trim().replace(/^\[/, "").replace(/\]$/, "");

    // Compound patterns are not interpreted; a partial reading of one would be
    // worse than declining it, since it would match on the wrong condition.
    if (/\b(AND|OR|FOLLOWEDBY)\b/i.test(inner)) {
        return undefined;
    }

    const equals = inner.indexOf("=");
    if (equals <= 0) {
        return undefined;
    }

    const key = normalisePatternKey(inner.slice(0, equals));
    const type = PATTERN_TYPES[key];
    if (type === undefined) {
        return undefined;
    }

    const value = normalisePatternValue(inner.slice(equals + 1));
    if (value === "") {
        return undefined;
    }

    // Domains, emails and property names are compared case-insensitively, so
    // they are folded once here rather than at every comparison.
    const folded = type === "domain" || type === "email" ? value.toLowerCase() : value;
    return { type, value: folded };
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
    return typeof value === "object" && value !== null && !Array.isArray(value)
        ? (value as Record<string, unknown>)
        : undefined;
}

function asString(value: unknown): string | undefined {
    return typeof value === "string" ? value : undefined;
}

const DEFAULT_COLLECTION = "Ungrouped indicators";

/**
 * Parses a STIX2 bundle.
 *
 * `origin` distinguishes indicators shipped with this application from those the
 * examiner supplied, because the two carry different authority and the report
 * must say which was used.
 */
export function parseStix2Bundle(
    filename: string,
    content: string,
    origin: "bundled" | "supplied",
): LoadedBundle {
    const sha256 = hashBytes(new TextEncoder().encode(content));

    let parsed: unknown;
    try {
        parsed = JSON.parse(content);
    } catch (error) {
        throw new Error(
            `${filename} is not valid JSON: ${error instanceof Error ? error.message : String(error)}`,
        );
    }

    const objects = asRecord(parsed)?.["objects"];
    if (!Array.isArray(objects)) {
        throw new Error(`${filename} is not a STIX2 bundle: no "objects" array.`);
    }

    // Collection names, keyed by the id an indicator can be related to.
    const collectionNames = new Map<string, string>();
    const indicatorObjects: Record<string, unknown>[] = [];
    const relationships: Record<string, unknown>[] = [];
    /** Report id -> the object ids it references. */
    const reportRefs = new Map<string, Set<string>>();

    for (const raw of objects) {
        const entry = asRecord(raw);
        const type = asString(entry?.["type"]);
        const id = asString(entry?.["id"]);
        if (entry === undefined || type === undefined) {
            continue;
        }

        if ((type === "malware" || type === "report" || type === "intrusion-set") && id !== undefined) {
            collectionNames.set(id, asString(entry["name"]) ?? id);

            const refs = entry["object_refs"];
            if (type === "report" && Array.isArray(refs)) {
                reportRefs.set(
                    id,
                    new Set(refs.filter((ref): ref is string => typeof ref === "string")),
                );
            }
            continue;
        }

        if (type === "indicator") {
            indicatorObjects.push(entry);
        } else if (type === "relationship") {
            relationships.push(entry);
        }
    }

    /** indicator id -> collection id, from `indicates` relationships. */
    const attribution = new Map<string, string>();
    for (const relationship of relationships) {
        const source = asString(relationship["source_ref"]);
        const target = asString(relationship["target_ref"]);
        if (source !== undefined && target !== undefined && collectionNames.has(target)) {
            attribution.set(source, target);
        }
    }

    const indicators: Indicator[] = [];
    const unsupportedPatterns: string[] = [];
    const perCollection = new Map<string, Map<string, number>>();
    const descriptions = new Map<string, string>();

    for (const entry of indicatorObjects) {
        const pattern = asString(entry["pattern"]);
        const id = asString(entry["id"]);
        if (pattern === undefined) {
            continue;
        }

        const parsedPattern = parsePattern(pattern);
        if (parsedPattern === undefined) {
            unsupportedPatterns.push(pattern);
            continue;
        }

        // A report referencing the indicator takes precedence over a
        // relationship, matching how these bundles are authored: the report is
        // the publication the indicator was disclosed in.
        let collectionId: string | undefined;
        if (id !== undefined) {
            for (const [reportId, refs] of reportRefs) {
                if (refs.has(id)) {
                    collectionId = reportId;
                    break;
                }
            }
            collectionId ??= attribution.get(id);
        }

        const collection =
            collectionId === undefined
                ? DEFAULT_COLLECTION
                : (collectionNames.get(collectionId) ?? DEFAULT_COLLECTION);

        indicators.push({
            type: parsedPattern.type,
            value: parsedPattern.value,
            collection,
            source: filename,
        });

        const counts = perCollection.get(collection) ?? new Map<string, number>();
        counts.set(parsedPattern.type, (counts.get(parsedPattern.type) ?? 0) + 1);
        perCollection.set(collection, counts);

        if (collectionId !== undefined && !descriptions.has(collection)) {
            const described = objects
                .map((raw) => asRecord(raw))
                .find((entry) => asString(entry?.["id"]) === collectionId);
            descriptions.set(collection, asString(described?.["description"]) ?? "");
        }
    }

    const collections: IndicatorCollection[] = [...perCollection.entries()].map(
        ([name, counts]) => ({
            name,
            description: descriptions.get(name) ?? "",
            counts: Object.fromEntries(counts),
            total: [...counts.values()].reduce((sum, count) => sum + count, 0),
        }),
    );

    return {
        filename,
        sha256,
        origin,
        indicators,
        collections,
        unsupportedPatterns,
        total: indicators.length,
    };
}
