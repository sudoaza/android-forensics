import { IndicatorLibrary } from "./matcher.js";
import { parseStix2Bundle } from "./stix2.js";

/**
 * Indicator sources.
 *
 * Two paths, both offline:
 *
 *   1. **A pinned snapshot** shipped as static assets under `indicators/`. Served
 *      from the application's own origin, so the existing `connect-src 'self'`
 *      policy is unchanged and the tool still works air-gapped. `index.json`
 *      records each bundle's expected SHA-256 and the upstream commit it came
 *      from, so its provenance is stated rather than assumed.
 *
 *   2. **Files the examiner supplies**, through a file or directory picker. This
 *      is what makes case-specific and embargoed indicators usable, which is
 *      often the only way current indicators are available.
 *
 * No indicator is ever fetched from a third-party origin at runtime. That is a
 * deliberate constraint, not a limitation to work around: a forensic workstation
 * examining a seized device should not emit network traffic, and an indicator set
 * that changes silently between runs cannot be cited in a report.
 */

/** Shape of `public/indicators/index.json`. */
export interface SnapshotIndex {
    readonly pinned_at: string;
    readonly upstream: string;
    readonly commit: string;
    readonly bundles: readonly {
        readonly filename: string;
        readonly sha256: string;
        readonly description?: string;
    }[];
}

export interface SnapshotLoadResult {
    readonly library: IndicatorLibrary;
    /** Bundles that failed to load, with the reason. Never silently dropped. */
    readonly failures: readonly { readonly filename: string; readonly reason: string }[];
    readonly index: SnapshotIndex | undefined;
}

/**
 * Location of the pinned snapshot.
 *
 * Anchored to Vite's configured base rather than fetched as a bare relative
 * path. The build uses `base: "./"` so the bundle stays portable across project
 * pages, custom domains and file-served copies; a bare `indicators/...` would
 * resolve against the document URL, which silently becomes the server root if
 * the app is ever served without a trailing slash.
 */
const SNAPSHOT_BASE = `${import.meta.env.BASE_URL}indicators`;

/**
 * Loads the bundled snapshot.
 *
 * A missing snapshot is not an error: a deployment may deliberately ship none,
 * and the report already states when no indicators were loaded. A bundle whose
 * content does not match the hash recorded in the index *is* an error, and is
 * refused — a modified indicator set would silently change what this tool
 * detects.
 */
export async function loadBundledSnapshot(
    library: IndicatorLibrary = new IndicatorLibrary(),
): Promise<SnapshotLoadResult> {
    const failures: { filename: string; reason: string }[] = [];

    let index: SnapshotIndex | undefined;
    try {
        const response = await fetch(`${SNAPSHOT_BASE}/index.json`);
        if (!response.ok) {
            return { library, failures, index: undefined };
        }
        index = (await response.json()) as SnapshotIndex;
    } catch {
        // No snapshot deployed.
        return { library, failures, index: undefined };
    }

    if (!Array.isArray(index?.bundles)) {
        return { library, failures, index: undefined };
    }

    for (const entry of index.bundles) {
        try {
            const response = await fetch(`${SNAPSHOT_BASE}/${entry.filename}`);
            if (!response.ok) {
                failures.push({
                    filename: entry.filename,
                    reason: `Could not be retrieved (HTTP ${response.status}).`,
                });
                continue;
            }

            const content = await response.text();
            const bundle = parseStix2Bundle(entry.filename, content, "bundled");

            if (bundle.sha256 !== entry.sha256) {
                failures.push({
                    filename: entry.filename,
                    reason:
                        `Content does not match the hash recorded in index.json ` +
                        `(expected ${entry.sha256}, got ${bundle.sha256}). It was not loaded.`,
                });
                continue;
            }

            library.add(bundle);
        } catch (error) {
            failures.push({
                filename: entry.filename,
                reason: error instanceof Error ? error.message : String(error),
            });
        }
    }

    return { library, failures, index };
}

/**
 * Loads indicator bundles the examiner selected.
 *
 * Every file is attempted, and failures are returned rather than thrown, so one
 * malformed bundle in a directory does not discard the rest.
 */
export async function loadSuppliedBundles(
    files: readonly File[],
    library: IndicatorLibrary,
): Promise<readonly { readonly filename: string; readonly reason: string }[]> {
    const failures: { filename: string; reason: string }[] = [];

    for (const file of files) {
        // Accept the conventional extensions plus `.json`, since bundles are
        // frequently distributed with either.
        if (!/\.(stix2|json)$/i.test(file.name)) {
            continue;
        }

        try {
            library.add(parseStix2Bundle(file.name, await file.text(), "supplied"));
        } catch (error) {
            failures.push({
                filename: file.name,
                reason: error instanceof Error ? error.message : String(error),
            });
        }
    }

    return failures;
}

/** Provenance for the report, derived from the loaded library. */
export function describeIndicatorSources(library: IndicatorLibrary): readonly {
    filename: string;
    sha256: string;
    origin: "bundled" | "supplied";
    collections: readonly { name: string; counts: Readonly<Record<string, number>> }[];
    totalIndicators: number;
}[] {
    return library.bundles.map((bundle) => ({
        filename: bundle.filename,
        sha256: bundle.sha256,
        origin: bundle.origin,
        collections: bundle.collections.map((collection) => ({
            name: collection.name,
            counts: collection.counts,
        })),
        totalIndicators: bundle.total,
    }));
}
