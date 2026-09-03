import { describe, expect, it } from "vitest";

import { IndicatorLibrary } from "./matcher.js";
import { parseStix2Bundle } from "./stix2.js";

/**
 * The pinned snapshot, parsed as shipped.
 *
 * This is the test that matters most for the indicator path: the synthetic
 * fixtures elsewhere prove the parser handles the shapes I expected, which is not
 * the same as handling the shapes real published bundles actually use. Every
 * pattern form exercised here came from a real threat-intelligence report.
 *
 * It also guards the snapshot itself. If `tools/pin-indicators.mjs` is re-run and
 * upstream has adopted a pattern form this reader does not implement, the
 * unsupported count rises and this fails — rather than the tool quietly losing
 * detections.
 *
 * The files are read through `import.meta.glob` rather than `node:fs` so this
 * suite needs no Node types. That keeps `tsconfig.types` narrow to the browser
 * surface, which is what stops application code from reaching for a Node API and
 * still typechecking.
 */

const BUNDLE_FILES: Record<string, string> = import.meta.glob(
    "../../../public/indicators/**/*.stix2",
    { query: "?raw", import: "default", eager: true },
);

const INDEX_FILES: Record<string, string> = import.meta.glob(
    "../../../public/indicators/index.json",
    { query: "?raw", import: "default", eager: true },
);

// Globbed as a directory listing rather than by name: `LICENSE` has no
// extension, which the glob compiler rejects as a bare pattern.
const ROOT_FILES: Record<string, string> = import.meta.glob(
    "../../../public/indicators/*",
    { query: "?raw", import: "default", eager: true },
);

interface IndexEntry {
    readonly filename: string;
    readonly sha256: string;
    readonly indicators: number;
    readonly collections: readonly string[];
}

interface SnapshotIndex {
    readonly commit: string;
    readonly upstream: string;
    readonly license: string;
    readonly total_indicators: number;
    readonly bundles: readonly IndexEntry[];
}

const rawIndex = Object.values(INDEX_FILES)[0];
// A deployment may deliberately ship no snapshot, so its absence skips rather
// than fails.
const index: SnapshotIndex | undefined =
    rawIndex === undefined ? undefined : (JSON.parse(rawIndex) as SnapshotIndex);

/** Snapshot-relative path (as recorded in the index) to file content. */
const contents = new Map<string, string>(
    Object.entries(BUNDLE_FILES).map(([path, content]) => [
        path.slice(path.indexOf("/indicators/") + "/indicators/".length),
        content,
    ]),
);

function loadAll(snapshot: SnapshotIndex): IndicatorLibrary {
    const library = new IndicatorLibrary();
    for (const entry of snapshot.bundles) {
        library.add(
            parseStix2Bundle(entry.filename, contents.get(entry.filename) ?? "", "bundled"),
        );
    }
    return library;
}

describe.skipIf(index === undefined)("pinned indicator snapshot", () => {
    const snapshot = index as SnapshotIndex;

    it("is attributed to a specific upstream commit under a known licence", () => {
        // Provenance is the whole point of pinning: "1617 indicators" is not
        // citable without stating exactly which 1617.
        expect(snapshot.commit).toMatch(/^[0-9a-f]{40}$/);
        expect(snapshot.upstream).toContain("mvt-indicators");
        expect(snapshot.license).toBe("MIT");

        // MIT requires the notice to ship with the data it covers.
        const license = Object.entries(ROOT_FILES).find(([path]) =>
            path.endsWith("/LICENSE"),
        )?.[1];
        expect(license).toBeDefined();
        expect(license).toMatch(/Permission is hereby granted/i);
    });

    it("matches the hashes recorded in its own index", () => {
        // The same check the loader performs in the browser. A snapshot that has
        // drifted from its index would silently change what the tool detects.
        for (const entry of snapshot.bundles) {
            const content = contents.get(entry.filename);
            expect(content, entry.filename).toBeDefined();

            const parsed = parseStix2Bundle(entry.filename, content ?? "", "bundled");
            expect(parsed.sha256, entry.filename).toBe(entry.sha256);
        }
    });

    it("lists every bundle present on disk", () => {
        // A bundle on disk but absent from the index would never be loaded, and
        // would look like an indicator that simply did not match.
        expect([...contents.keys()].sort()).toEqual(
            snapshot.bundles.map((entry) => entry.filename).sort(),
        );
    });

    it("interprets every pattern in every real bundle", () => {
        // The assertion that carries the weight: zero unsupported patterns across
        // the whole snapshot. A form this reader cannot read is lost detection
        // capability, so it must fail loudly here.
        const unsupported: string[] = [];
        let total = 0;

        for (const entry of snapshot.bundles) {
            const bundle = parseStix2Bundle(
                entry.filename,
                contents.get(entry.filename) ?? "",
                "bundled",
            );

            // Cross-checked against a count computed independently by the pinning
            // script, so this cannot pass by parsing nothing.
            expect(bundle.total, `${entry.filename} indicator count`).toBe(entry.indicators);
            unsupported.push(
                ...bundle.unsupportedPatterns.map((pattern) => `${entry.filename}: ${pattern}`),
            );
            total += bundle.total;
        }

        expect(unsupported).toEqual([]);
        expect(total).toBe(snapshot.total_indicators);
        expect(total).toBeGreaterThan(0);
    });

    it("loads the whole snapshot into one library", () => {
        const library = loadAll(snapshot);

        expect(library.bundles).toHaveLength(snapshot.bundles.length);
        expect(library.total).toBe(snapshot.total_indicators);
    });

    it("attributes indicators to named collections, not to a catch-all", () => {
        // A match reported without the report or family it came from is an
        // assertion an examiner cannot cite, so attribution has to survive real
        // bundle structure and not only the fixtures.
        const named = loadAll(snapshot).bundles.filter((bundle) =>
            bundle.collections.some((collection) => collection.name !== "Ungrouped indicators"),
        );

        expect(named.length).toBeGreaterThan(0);
    });

    it("matches values taken from the real bundles end to end", () => {
        // Spot-checks through the public matcher API using values drawn from the
        // snapshot itself, so the lookup path is exercised against real data.
        const library = loadAll(snapshot);
        const samples = { domain: [] as string[], sha256: [] as string[], appId: [] as string[] };

        for (const entry of snapshot.bundles) {
            const bundle = parseStix2Bundle(
                entry.filename,
                contents.get(entry.filename) ?? "",
                "bundled",
            );
            for (const indicator of bundle.indicators) {
                if (indicator.type === "domain" && samples.domain.length < 5) {
                    samples.domain.push(indicator.value);
                } else if (indicator.type === "file_sha256" && samples.sha256.length < 5) {
                    samples.sha256.push(indicator.value);
                } else if (indicator.type === "app_id" && samples.appId.length < 5) {
                    samples.appId.push(indicator.value);
                }
            }
        }

        expect(samples.domain.length).toBeGreaterThan(0);
        expect(samples.sha256.length).toBeGreaterThan(0);
        expect(samples.appId.length).toBeGreaterThan(0);

        for (const domain of samples.domain) {
            expect(library.checkDomain(domain), domain).toBeDefined();
            // Hostnames are case-insensitive, and real data varies in case.
            expect(library.checkDomain(domain.toUpperCase()), domain).toBeDefined();
        }
        for (const hash of samples.sha256) {
            expect(library.checkFileHash(hash), hash).toBeDefined();
            expect(library.checkFileHash(hash.toUpperCase()), hash).toBeDefined();
        }
        for (const appId of samples.appId) {
            expect(library.checkAppId(appId), appId).toBeDefined();
        }

        // Absent values must not match, or the checks above would pass vacuously.
        expect(library.checkDomain("example.invalid")).toBeUndefined();
        expect(library.checkAppId("com.example.definitely.not.present")).toBeUndefined();
        expect(library.checkFileHash("f".repeat(64))).toBeUndefined();
    });
});
