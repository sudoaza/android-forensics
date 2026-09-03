import type { Rule } from "../alerts.js";
import type { AnalysisContext, Analyzer } from "../analyzer.js";

/**
 * Network endpoints, scanned against domain and IP indicators.
 *
 * This analyzer exists because of an arithmetic fact about real indicator sets:
 * of the 1617 indicators in the pinned snapshot, 1178 are domains and 73 are IP
 * addresses. Without it, 77% of every published indicator bundle can never match
 * anything, and a report claiming no indicator matches would be close to
 * meaningless while looking authoritative.
 *
 * The approach is deliberately coarse. Rather than parse each `dumpsys` section
 * (whose formats differ per service, per OEM and per Android version, and would
 * be a large surface of parsers each able to silently stop matching), hostnames
 * and addresses are extracted by pattern from any text artifact and looked up.
 * Precision comes from the indicator set, not from the extraction: an arbitrary
 * hostname is not reported, only one that appears in a loaded bundle.
 *
 * The cost of that choice is context. A match says the endpoint appears in this
 * artifact, not which app contacted it, so every alert carries the artifact, the
 * line number and the surrounding line for the examiner to interpret. That is
 * honest about what a text scan can establish.
 */

/**
 * Artifacts scanned.
 *
 * Ordered roughly by signal density. Deliberately excludes `packages.txt` and the
 * APK directory: package names are matched by the packages analyzer, and scanning
 * binary content as text produces meaningless line context.
 */
const NETWORK_PATTERNS: readonly string[] = [
    "*/logcat.txt",
    "*/logcat_old.txt",
    "*/security/connectivity.txt",
    "*/security/netpolicy.txt",
    "*/security/wifi.txt",
    "*/security/vpn_management.txt",
    "*/security/proc_net_tcp.txt",
    "*/security/proc_net_tcp6.txt",
    "*/security/proc_net_udp.txt",
    "*/security/usagestats.txt",
    "*/security/notifications.txt",
    "*/security/jobscheduler.txt",
    "*/security/alarms.txt",
    "*/dumpsys.txt",
];

const RULES = {
    indicatorHost: {
        id: "network.matched_indicator",
        level: "critical",
        rationale:
            "A hostname or address appearing in this acquisition matches a published " +
            "indicator of compromise. The artifact and line are recorded, but a text " +
            "match does not establish which application contacted the endpoint, nor " +
            "that a connection succeeded.",
    },
} as const satisfies Record<string, Rule>;

export const NETWORK_RULES: readonly Rule[] = Object.values(RULES);

/**
 * Hostname candidates.
 *
 * Requires a dot-separated name ending in a 2+ character alphabetic TLD, which
 * excludes version strings (`1.2.3`), package-like tokens ending in a number, and
 * bare filenames. Leading `://` and `@` are handled by the caller trimming, since
 * the indicator lookup normalises a URL to its host anyway.
 */
const HOST_EXPRESSION =
    /\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63})\b/gi;

/** Dotted-quad addresses. Range-checked below, since the pattern alone is loose. */
const IPV4_EXPRESSION = /\b(\d{1,3}(?:\.\d{1,3}){3})\b/g;

/**
 * Hostname suffixes never worth looking up.
 *
 * Not a safety filter — a flagged domain under any of these would still be found,
 * because matching is done by the indicator set rather than by this list. It only
 * avoids hashing millions of Android framework tokens that look like hostnames
 * (`android.view.View`, `com.google.android.gms`) on a 100 MB logcat, which is
 * purely a throughput concern.
 */
const SKIPPED_PREFIXES: readonly string[] = [
    "android.",
    "androidx.",
    "com.android.",
    "com.google.android.",
    "java.",
    "javax.",
    "kotlin.",
    "dalvik.",
    "libcore.",
    "sun.",
    "org.chromium.",
];

function shouldSkipHost(host: string): boolean {
    return SKIPPED_PREFIXES.some((prefix) => host.startsWith(prefix));
}

function isPlausibleIpv4(value: string): boolean {
    const parts = value.split(".");
    if (parts.length !== 4) {
        return false;
    }
    for (const part of parts) {
        // Reject leading zeros, which are version-string artifacts far more often
        // than real addresses in this data.
        if (part.length > 1 && part.startsWith("0")) {
            return false;
        }
        const octet = Number(part);
        if (!Number.isInteger(octet) || octet < 0 || octet > 255) {
            return false;
        }
    }
    return true;
}

/** Extracted endpoint, with enough context for the finding to be interpretable. */
export interface EndpointOccurrence {
    readonly value: string;
    readonly line: number;
    /** The source line, trimmed and length-capped for the report. */
    readonly context: string;
}

const MAX_CONTEXT = 300;

/**
 * Extracts hostname and IPv4 candidates from text.
 *
 * Returns the first occurrence of each distinct value: a domain appearing 40,000
 * times in a logcat is one finding with one example, not 40,000 alerts.
 */
export function extractEndpoints(content: string): readonly EndpointOccurrence[] {
    const seen = new Map<string, EndpointOccurrence>();
    const lines = content.split("\n");

    for (let index = 0; index < lines.length; index += 1) {
        const line = lines[index] ?? "";
        // Long single lines occur in dumpsys; the cost is bounded per line rather
        // than skipping the line entirely, so nothing is silently unexamined.
        const context = line.trim().slice(0, MAX_CONTEXT);

        for (const match of line.matchAll(HOST_EXPRESSION)) {
            const host = (match[1] ?? "").toLowerCase();
            if (host === "" || shouldSkipHost(host) || seen.has(host)) {
                continue;
            }
            seen.set(host, { value: host, line: index + 1, context });
        }

        for (const match of line.matchAll(IPV4_EXPRESSION)) {
            const address = match[1] ?? "";
            if (!isPlausibleIpv4(address) || seen.has(address)) {
                continue;
            }
            seen.set(address, { value: address, line: index + 1, context });
        }
    }

    return [...seen.values()];
}

export const networkAnalyzer: Analyzer = {
    id: "network",
    label: "Network endpoints",
    inputs: NETWORK_PATTERNS,
    rules: NETWORK_RULES,

    async run(ctx: AnalysisContext): Promise<void> {
        // Without indicators there is nothing to compare against, and every
        // hostname on the device is uninteresting on its own. Returning early
        // keeps a large scan off the critical path; the report already states that
        // no indicators were loaded.
        if (ctx.indicators === undefined) {
            return;
        }

        const names = NETWORK_PATTERNS.flatMap((pattern) => [...ctx.source.match(pattern)]);
        const scanned = new Set<string>();

        for (const [position, name] of names.entries()) {
            ctx.signal.throwIfAborted();

            // A pattern may match the same artifact twice; scanning it twice would
            // double every finding from it.
            if (scanned.has(name)) {
                continue;
            }
            scanned.add(name);

            ctx.progress(`Scanning ${name}`, position, names.length);

            let endpoints: readonly EndpointOccurrence[];
            try {
                endpoints = extractEndpoints(await ctx.source.text(name));
            } catch (error) {
                ctx.note(name, error instanceof Error ? error.message : String(error));
                continue;
            }

            ctx.examined(name);

            for (const endpoint of endpoints) {
                const hit = ctx.indicators.checkDomain(endpoint.value);
                if (hit === undefined) {
                    continue;
                }

                ctx.alerts.indicatorMatch("network", hit, hit.message, {
                    artifact: name,
                    evidence: {
                        endpoint: endpoint.value,
                        line: endpoint.line,
                        context: endpoint.context,
                        // Stated on the finding itself, so the limit travels with
                        // the alert rather than living only in the report preamble.
                        caveat:
                            "Textual occurrence in a collected artifact. This does not " +
                            "establish which application contacted the endpoint, or that " +
                            "a connection was made.",
                    },
                });
            }
        }
    },
};
