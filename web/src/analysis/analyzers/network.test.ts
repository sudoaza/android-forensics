import { describe, expect, it } from "vitest";

import { AlertStore } from "../alerts.js";
import type { AnalysisContext } from "../analyzer.js";
import { IndicatorLibrary } from "../indicators/matcher.js";
import { parseStix2Bundle } from "../indicators/stix2.js";
import type { ArtifactSource } from "../source.js";
import { extractEndpoints, networkAnalyzer } from "./network.js";

/**
 * The network analyzer against the real pinned indicator set.
 *
 * The synthetic tests prove the extraction works on the shapes I wrote. This
 * proves the whole path works against the 1178 real domain indicators and 73 real
 * IP indicators in the snapshot, which is the majority of every published bundle
 * and therefore the majority of this tool's malware-detection value.
 *
 * It also bounds the throughput. A real logcat reached 101 MB on a MIUI device, so
 * an extraction that is accidentally quadratic would make analysis unusable on
 * exactly the artifact that matters most.
 */

const BUNDLES: Record<string, string> = import.meta.glob(
    "../../../public/indicators/**/*.stix2",
    { query: "?raw", import: "default", eager: true },
);

function realLibrary(): IndicatorLibrary {
    const library = new IndicatorLibrary();
    for (const [path, content] of Object.entries(BUNDLES)) {
        const filename = path.slice(path.indexOf("/indicators/") + "/indicators/".length);
        library.add(parseStix2Bundle(filename, content, "bundled"));
    }
    return library;
}

const library = Object.keys(BUNDLES).length > 0 ? realLibrary() : undefined;

/** Sample real indicator values of a given type from the loaded snapshot. */
function sampleValues(type: string, limit: number): readonly string[] {
    const values: string[] = [];
    for (const bundle of library?.bundles ?? []) {
        for (const indicator of bundle.indicators) {
            if (indicator.type === type && values.length < limit) {
                values.push(indicator.value);
            }
        }
    }
    return values;
}

/** Minimal in-memory source, so the analyzer is driven through its real contract. */
function sourceOf(artifacts: Readonly<Record<string, string>>): ArtifactSource {
    const names = Object.keys(artifacts);
    return {
        acquisitionId: "AQ-TEST",
        origin: "zip",
        names,
        match(pattern: string) {
            const expression = new RegExp(
                `^${pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replaceAll("*", ".*")}$`,
            );
            return names.filter((name) => expression.test(name));
        },
        size: (name: string) => artifacts[name]?.length,
        async stream(name: string) {
            return new Blob([artifacts[name] ?? ""]).stream() as ReadableStream<Uint8Array>;
        },
        async bytes(name: string) {
            return new TextEncoder().encode(artifacts[name] ?? "");
        },
        async text(name: string) {
            return artifacts[name] ?? "";
        },
    };
}

async function run(artifacts: Readonly<Record<string, string>>): Promise<AlertStore> {
    const alerts = new AlertStore();
    const context: AnalysisContext = {
        source: sourceOf(artifacts),
        alerts,
        indicators: library,
        signal: new AbortController().signal,
        progress: () => undefined,
        examined: () => undefined,
        note: () => undefined,
    };

    await networkAnalyzer.run(context);
    return alerts;
}

describe.skipIf(library === undefined)("network analyzer against real indicators", () => {
    it("has real domain indicators to match, so these tests are not vacuous", () => {
        const domains = sampleValues("domain", 2000);
        // The snapshot is dominated by domains and addresses; if that stops being
        // true, this analyzer's justification changes and this should be revisited.
        expect(domains.length).toBeGreaterThan(500);
    });

    it("matches real indicator domains embedded in a logcat", async () => {
        const domains = sampleValues("domain", 25).filter((value) => value.includes("."));
        expect(domains.length).toBeGreaterThan(0);

        const log = domains
            .map((domain, index) => `09-01 12:00:0${index % 10} 1 1 I Net: GET https://${domain}/x`)
            .join("\n");

        const alerts = await run({ "AQ-TEST/logcat.txt": log });
        const matched = new Set(alerts.alerts.map((alert) => alert.evidence["endpoint"]));

        for (const domain of domains) {
            expect(matched.has(domain), domain).toBe(true);
        }
        // Every alert is critical and carries its indicator's provenance.
        for (const alert of alerts.alerts) {
            expect(alert.level).toBe("critical");
            expect(alert.matchedIndicator?.source).toMatch(/\.stix2$/);
            expect(alert.matchedIndicator?.collection).toBeTruthy();
        }
    });

    it("matches a subdomain of a real indicator domain", async () => {
        const domain = sampleValues("domain", 200).find(
            (value) => value.split(".").length === 2,
        );
        expect(domain).toBeDefined();

        const alerts = await run({
            "AQ-TEST/logcat.txt": `GET https://cdn-assets.${domain}/payload`,
        });

        expect(alerts.alerts.length).toBeGreaterThan(0);
        expect(alerts.alerts[0]?.message).toMatch(/subdomain/i);
    });

    it("produces no findings on ordinary Android log noise", async () => {
        // The false-positive check that matters: a realistic log of framework
        // chatter must be silent against 1617 real indicators. A scan that fires
        // here would bury real findings.
        const noise = [
            "09-01 12:00:00.000  1234  5678 I ActivityManager: Start proc com.android.chrome",
            "09-01 12:00:00.001  1234  5678 D WifiService: connected to network 5",
            "09-01 12:00:00.002  1234  5678 W System: at android.view.View.performClick(View.java:7448)",
            "09-01 12:00:00.003  1234  5678 I Finsky: [2] com.google.android.finsky.foo.bar(12)",
            "09-01 12:00:00.004  1234  5678 I Net: GET https://www.google.com/generate_204",
            "09-01 12:00:00.005  1234  5678 I Net: connecting to android.googleapis.com",
            "09-01 12:00:00.006  1234  5678 D Versions: build 1.2.3.4, sdk 34.0.0.1",
            "09-01 12:00:00.007  1234  5678 I DHCP: lease from 192.168.1.1 for 10.0.0.42",
            "09-01 12:00:00.008  1234  5678 I Time: sync with time.android.com ok",
        ].join("\n");

        const alerts = await run({ "AQ-TEST/logcat.txt": noise });

        expect(
            alerts.alerts.map((alert) => alert.evidence["endpoint"]),
            "ordinary Android log noise produced indicator matches",
        ).toEqual([]);
    });

    it("scans a logcat-sized artifact in reasonable time", () => {
        // ~12 MB of realistic log lines. The concern is algorithmic: on a 101 MB
        // logcat anything superlinear here makes analysis unusable.
        const line =
            "09-01 12:00:00.000  1234  5678 I ActivityManager: Start proc " +
            "com.example.app for service host.cdn.example.net/1.2.3.4\n";
        const large = line.repeat(120_000);

        const started = Date.now();
        const endpoints = extractEndpoints(large);
        const elapsed = Date.now() - started;

        // Distinct values are deduplicated, so a repetitive log yields few
        // endpoints regardless of its size.
        expect(endpoints.length).toBeLessThan(20);
        expect(elapsed, `extraction took ${elapsed}ms for ${large.length} bytes`).toBeLessThan(
            15_000,
        );
    });
});
