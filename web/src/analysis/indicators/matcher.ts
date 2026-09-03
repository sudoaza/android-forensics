import type { IndicatorHit, IndicatorMatcher } from "../analyzer.js";
import type { Indicator, IndicatorType, LoadedBundle } from "./stix2.js";

/**
 * Indicator matching.
 *
 * Matching semantics are the substance here, not the lookup. Each is chosen to
 * match how the observed value is actually produced on Android, because a
 * mismatch in either direction is a real failure: too strict and a genuine
 * detection is missed, too loose and an examiner is sent after a false positive
 * in a criminal matter.
 *
 * Notable cases, all deliberate:
 *
 *   - **Process names are truncated to 15 characters** by the kernel's `comm`
 *     field, so a longer indicator is matched by prefix against a 15-character
 *     observation. Doing otherwise would silently miss every implant whose
 *     process name exceeds the limit.
 *   - **File paths match by prefix**, since an indicator names a directory whose
 *     contents are all implicated.
 *   - **Domains match the full host, and also a parent domain**, so a subdomain
 *     of a known-malicious domain is caught.
 *   - **Hashes and package names match exactly**, case-insensitively. A prefix
 *     match on a hash would be meaningless, and on a package name it would flag
 *     unrelated applications sharing a vendor prefix.
 */

export class IndicatorLibrary implements IndicatorMatcher {
    readonly #bundles: LoadedBundle[] = [];
    /** Exact-match lookups, keyed by lowercased value. */
    readonly #exact = new Map<IndicatorType, Map<string, Indicator>>();
    /** Types needing a scan rather than a lookup. */
    readonly #scanned = new Map<IndicatorType, Indicator[]>();

    get bundles(): readonly LoadedBundle[] {
        return this.#bundles;
    }

    get total(): number {
        return this.#bundles.reduce((sum, bundle) => sum + bundle.total, 0);
    }

    get isEmpty(): boolean {
        return this.total === 0;
    }

    /** Indicator counts by type, across every loaded bundle. */
    get countsByType(): Readonly<Record<string, number>> {
        const counts: Record<string, number> = {};
        for (const bundle of this.#bundles) {
            for (const indicator of bundle.indicators) {
                counts[indicator.type] = (counts[indicator.type] ?? 0) + 1;
            }
        }
        return counts;
    }

    add(bundle: LoadedBundle): void {
        // Re-loading the same bundle content is a no-op rather than a duplicate:
        // an examiner adding a directory that overlaps the shipped snapshot
        // should not double every count in the report.
        if (this.#bundles.some((existing) => existing.sha256 === bundle.sha256)) {
            return;
        }

        this.#bundles.push(bundle);

        for (const indicator of bundle.indicators) {
            // Paths and process names need BOTH structures: the exact table for
            // the common case, and the scan list for prefix and truncation
            // matching. Populating only the scan list would make every exact
            // lookup miss.
            const table = this.#exact.get(indicator.type) ?? new Map<string, Indicator>();
            // First wins, so the collection reported is the first bundle that
            // published the indicator rather than the last loaded.
            const key = indicatorKey(indicator.type, indicator.value);
            if (!table.has(key)) {
                table.set(key, indicator);
            }
            this.#exact.set(indicator.type, table);

            if (needsScan(indicator.type)) {
                const list = this.#scanned.get(indicator.type) ?? [];
                list.push(indicator);
                this.#scanned.set(indicator.type, list);
            }
        }
    }

    remove(sha256: string): void {
        const index = this.#bundles.findIndex((bundle) => bundle.sha256 === sha256);
        if (index < 0) {
            return;
        }
        this.#bundles.splice(index, 1);
        this.#rebuild();
    }

    clear(): void {
        this.#bundles.length = 0;
        this.#rebuild();
    }

    #rebuild(): void {
        const bundles = [...this.#bundles];
        this.#bundles.length = 0;
        this.#exact.clear();
        this.#scanned.clear();
        for (const bundle of bundles) {
            this.add(bundle);
        }
    }

    #lookup(type: IndicatorType, value: string): Indicator | undefined {
        return this.#exact.get(type)?.get(indicatorKey(type, value));
    }

    #hit(indicator: Indicator, message: string): IndicatorHit {
        return {
            type: indicator.type,
            value: indicator.value,
            collection: indicator.collection,
            source: indicator.source,
            message,
        };
    }

    checkAppId(appId: string): IndicatorHit | undefined {
        if (appId === "") {
            return undefined;
        }
        const indicator = this.#lookup("app_id", appId);
        return indicator === undefined
            ? undefined
            : this.#hit(
                  indicator,
                  `Package "${appId}" is a known indicator of compromise from "${indicator.collection}"`,
              );
    }

    /**
     * Matches a file hash, choosing the algorithm by digest length.
     *
     * 32 hex characters is MD5, 40 is SHA-1, anything else is treated as SHA-256.
     */
    checkFileHash(hash: string): IndicatorHit | undefined {
        if (hash === "") {
            return undefined;
        }
        const type: IndicatorType =
            hash.length === 32 ? "file_md5" : hash.length === 40 ? "file_sha1" : "file_sha256";

        const indicator = this.#lookup(type, hash);
        return indicator === undefined
            ? undefined
            : this.#hit(
                  indicator,
                  `File with hash ${hash} is a known indicator of compromise from "${indicator.collection}"`,
              );
    }

    checkAppCertificateHash(hash: string): IndicatorHit | undefined {
        if (hash === "") {
            return undefined;
        }
        const indicator = this.#lookup("app_cert_hash", hash);
        return indicator === undefined
            ? undefined
            : this.#hit(
                  indicator,
                  `Application signing certificate ${hash} is a known indicator of compromise from "${indicator.collection}"`,
              );
    }

    checkAndroidPropertyName(name: string): IndicatorHit | undefined {
        if (name === "") {
            return undefined;
        }
        const indicator = this.#lookup("android_property", name);
        return indicator === undefined
            ? undefined
            : this.#hit(
                  indicator,
                  `Android property "${name}" is a known indicator of compromise from "${indicator.collection}"`,
              );
    }

    checkFileName(name: string): IndicatorHit | undefined {
        if (name === "") {
            return undefined;
        }
        const indicator = this.#lookup("file_name", name);
        return indicator === undefined
            ? undefined
            : this.#hit(
                  indicator,
                  `File named "${name}" is a known indicator of compromise from "${indicator.collection}"`,
              );
    }

    /**
     * Matches a process name, allowing for kernel truncation.
     *
     * Linux stores a process name in a 16-byte `comm` field, so `ps` reports at
     * most 15 characters. An indicator longer than that can therefore never match
     * exactly, and is compared against its own first 15 characters.
     */
    checkProcess(name: string): IndicatorHit | undefined {
        if (name === "") {
            return undefined;
        }

        const exact = this.#lookup("process", name);
        if (exact !== undefined) {
            return this.#hit(
                exact,
                `Process "${name}" is a known indicator of compromise from "${exact.collection}"`,
            );
        }

        if (name.length < 15) {
            return undefined;
        }

        for (const indicator of this.#scanned.get("process") ?? []) {
            if (indicator.value.length <= 15) {
                continue;
            }
            if (indicator.value.slice(0, 15) === name.slice(0, 15)) {
                return this.#hit(
                    indicator,
                    `Process "${name}" matches indicator "${indicator.value}" from ` +
                        `"${indicator.collection}" (the name is truncated to 15 characters by the kernel)`,
                );
            }
        }

        return undefined;
    }

    /**
     * Matches a file path exactly, or as a descendant of an indicator path.
     *
     * An indicator naming a directory implicates its contents, so a trailing
     * slash is normalised away and descendants are matched on a segment boundary
     * — `/data/local/tmpfoo` must not match an indicator for `/data/local/tmp`.
     */
    checkFilePath(path: string): IndicatorHit | undefined {
        if (path === "") {
            return undefined;
        }

        const exact = this.#lookup("file_path", path);
        if (exact !== undefined) {
            return this.#hit(
                exact,
                `Path "${path}" is a known indicator of compromise from "${exact.collection}"`,
            );
        }

        for (const indicator of this.#scanned.get("file_path") ?? []) {
            const base = indicator.value.replace(/\/+$/, "");
            if (base === "" || !path.startsWith(`${base}/`)) {
                continue;
            }
            return this.#hit(
                indicator,
                `Path "${path}" is inside "${indicator.value}", a known indicator of ` +
                    `compromise from "${indicator.collection}"`,
            );
        }

        return undefined;
    }

    /**
     * Matches a hostname, or a subdomain of an indicator domain.
     *
     * A bare host is expected; a URL is reduced to its host first so callers can
     * pass either. Note that no network request is made — a shortened URL is not
     * expanded, and the report states this.
     */
    checkDomain(value: string): IndicatorHit | undefined {
        const host = toHost(value);
        if (host === undefined) {
            return undefined;
        }

        const exact = this.#lookup("domain", host);
        if (exact !== undefined) {
            return this.#hit(
                exact,
                `Host "${host}" is a known indicator of compromise from "${exact.collection}"`,
            );
        }

        // Walk up the labels so a subdomain of a flagged domain is caught, while
        // still requiring a boundary match: "notevil.com" must not match an
        // indicator for "evil.com".
        const labels = host.split(".");
        for (let index = 1; index < labels.length - 1; index += 1) {
            const parent = labels.slice(index).join(".");
            const indicator = this.#lookup("domain", parent);
            if (indicator !== undefined) {
                return this.#hit(
                    indicator,
                    `Host "${host}" is a subdomain of "${parent}", a known indicator of ` +
                        `compromise from "${indicator.collection}"`,
                );
            }
        }

        const url = this.#lookup("url", value);
        return url === undefined
            ? undefined
            : this.#hit(
                  url,
                  `URL "${value}" is a known indicator of compromise from "${url.collection}"`,
              );
    }
}

/** Types matched by scanning rather than by exact lookup. */
function needsScan(type: IndicatorType): boolean {
    return type === "file_path" || type === "process";
}

/**
 * Lookup key for an indicator value.
 *
 * Case is folded only where the underlying namespace is case-insensitive.
 * Filesystem paths and process names on Android are case-sensitive, so folding
 * them would let `/data/EVIL` match an indicator for `/data/evil` and create a
 * false positive. Hashes, package names, hostnames and property names are folded,
 * since case carries no meaning there and real data varies.
 */
function indicatorKey(type: IndicatorType, value: string): string {
    return needsScan(type) || type === "file_name" ? value : value.toLowerCase();
}

/**
 * Reduces a value to a hostname.
 *
 * Accepts a bare host or a URL. An IP address passes through unchanged, since
 * those are held alongside domains.
 */
function toHost(value: string): string | undefined {
    const trimmed = value.trim().toLowerCase();
    if (trimmed === "") {
        return undefined;
    }

    if (trimmed.includes("://")) {
        try {
            return new URL(trimmed).hostname;
        } catch {
            return undefined;
        }
    }

    // A bare `host/path` or `host:port` form.
    return trimmed.split("/")[0]?.split(":")[0] ?? undefined;
}
