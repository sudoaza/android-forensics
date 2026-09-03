import type { AnalysisContext, Analyzer } from "../analyzer.js";
import {
    CODE_INJECTION_PACKAGES,
    PACKAGE_RULES,
    PACKAGE_RULE_LIST,
    ROOT_CONCEALMENT_PACKAGES,
    ROOT_MANAGEMENT_PACKAGES,
    SECURITY_PACKAGES,
    SYSTEM_UPDATE_PACKAGES,
    classifyInstaller,
} from "../rules/packages.js";

/**
 * Package inventory analysis, from `packages.json`.
 *
 * This is the highest-yield surface in the archive: it carries both the install
 * provenance of every application and the SHA-256 of every APK, so it supports
 * hash-based identification of known malware even when the APKs themselves were
 * not collected — which is the case under the Quick profile.
 *
 * The parser is tolerant of shape. Our collector writes a specific record, but
 * an AndroidQF acquisition writes a similar one with different optional fields,
 * and analysis must work on both without a second implementation.
 */

const PACKAGES_PATTERN = "*/packages.json";

interface PackageFile {
    readonly path: string;
    readonly sha256: string | undefined;
    readonly certificateHashes: readonly string[];
}

interface PackageEntry {
    readonly name: string;
    readonly system: boolean;
    readonly installer: string | null;
    readonly disabled: boolean;
    readonly files: readonly PackageFile[];
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
    return typeof value === "object" && value !== null && !Array.isArray(value)
        ? (value as Record<string, unknown>)
        : undefined;
}

function asString(value: unknown): string | undefined {
    return typeof value === "string" && value !== "" ? value : undefined;
}

/**
 * Collects certificate hashes from a file record.
 *
 * AndroidQF nests them under `certificate` with capitalised algorithm keys
 * (`Md5`, `Sha1`, `Sha256`). Keys are matched case-insensitively so a lowercase
 * variant is not silently ignored — an unread certificate hash means an
 * `app:cert.*` indicator can never fire, which would be a silent detection gap
 * rather than a visible error.
 */
function certificateHashes(file: Record<string, unknown>): readonly string[] {
    const certificate = asRecord(file["certificate"]);
    if (certificate === undefined) {
        return [];
    }
    const hashes: string[] = [];
    for (const [key, value] of Object.entries(certificate)) {
        const normalised = key.toLowerCase();
        if (normalised === "md5" || normalised === "sha1" || normalised === "sha256") {
            const hash = asString(value);
            if (hash !== undefined) {
                hashes.push(hash);
            }
        }
    }
    return hashes;
}

export function parsePackagesJson(content: string): readonly PackageEntry[] {
    const parsed: unknown = JSON.parse(content);
    if (!Array.isArray(parsed)) {
        throw new Error("packages.json does not contain a JSON array.");
    }

    const entries: PackageEntry[] = [];
    for (const raw of parsed) {
        const record = asRecord(raw);
        const name = asString(record?.["name"]);
        if (record === undefined || name === undefined) {
            continue;
        }

        const files: PackageFile[] = [];
        const rawFiles = record["files"];
        if (Array.isArray(rawFiles)) {
            for (const rawFile of rawFiles) {
                const file = asRecord(rawFile);
                if (file === undefined) {
                    continue;
                }
                const path = asString(file["path"]) ?? "";
                const sha256 = asString(file["sha256"]);
                files.push({
                    path,
                    sha256,
                    certificateHashes: certificateHashes(file),
                });
            }
        }

        // `installer` is a string, `null`, or the literal "null" depending on the
        // collector; classification normalises all three.
        const installerRaw = record["installer"];
        const installer = typeof installerRaw === "string" ? installerRaw : null;

        entries.push({
            name,
            system: record["system"] === true,
            installer,
            disabled: record["disabled"] === true,
            files,
        });
    }

    return entries;
}

export const packagesAnalyzer: Analyzer = {
    id: "packages",
    label: "Installed packages",
    inputs: [PACKAGES_PATTERN],
    rules: PACKAGE_RULE_LIST,

    async run(ctx: AnalysisContext): Promise<void> {
        const name = ctx.source.match(PACKAGES_PATTERN)[0];
        if (name === undefined) {
            return;
        }

        let packages: readonly PackageEntry[];
        try {
            packages = parsePackagesJson(await ctx.source.text(name));
        } catch (error) {
            ctx.note(name, error instanceof Error ? error.message : String(error));
            return;
        }
        ctx.examined(name);

        const rootSet = new Set(ROOT_MANAGEMENT_PACKAGES);
        const injectionSet = new Set(CODE_INJECTION_PACKAGES);
        const concealmentSet = new Set(ROOT_CONCEALMENT_PACKAGES);
        const securitySet = new Set(SECURITY_PACKAGES);
        const updateSet = new Set(SYSTEM_UPDATE_PACKAGES);

        for (const [index, entry] of packages.entries()) {
            ctx.signal.throwIfAborted();
            if (index % 50 === 0) {
                ctx.progress(entry.name, index, packages.length);
            }

            const evidence = {
                package: entry.name,
                system: entry.system,
                installer: entry.installer,
                disabled: entry.disabled,
            };

            if (rootSet.has(entry.name)) {
                ctx.alerts.fire(
                    "packages",
                    PACKAGE_RULES.rootManagement,
                    `Root management application installed: ${entry.name}`,
                    { artifact: name, evidence },
                );
            } else if (injectionSet.has(entry.name)) {
                ctx.alerts.fire(
                    "packages",
                    PACKAGE_RULES.codeInjection,
                    `Code injection framework installed: ${entry.name}`,
                    { artifact: name, evidence },
                );
            } else if (concealmentSet.has(entry.name)) {
                ctx.alerts.fire(
                    "packages",
                    PACKAGE_RULES.rootConcealment,
                    `Root concealment application installed: ${entry.name}`,
                    { artifact: name, evidence },
                );
            }

            // Install provenance applies only to non-system packages: a system
            // package legitimately has no installer, and reporting every one of
            // them would bury the findings that matter under hundreds of rows.
            if (!entry.system) {
                const installerClass = classifyInstaller(entry.installer);
                if (installerClass === "none") {
                    ctx.alerts.fire(
                        "packages",
                        PACKAGE_RULES.sideloaded,
                        `Package installed outside any store, with no recorded installer: ${entry.name}`,
                        { artifact: name, evidence },
                    );
                } else if (installerClass === "package-installer") {
                    ctx.alerts.fire(
                        "packages",
                        PACKAGE_RULES.packageInstaller,
                        `Package installed from a local APK file via ${entry.installer}: ${entry.name}`,
                        { artifact: name, evidence },
                    );
                } else if (installerClass === "third-party-store") {
                    ctx.alerts.fire(
                        "packages",
                        PACKAGE_RULES.thirdPartyStore,
                        `Package installed from an alternative store (${entry.installer}): ${entry.name}`,
                        { artifact: name, evidence },
                    );
                }
            }

            if (entry.disabled && securitySet.has(entry.name)) {
                ctx.alerts.fire(
                    "packages",
                    PACKAGE_RULES.securityDisabled,
                    `Security component disabled: ${entry.name}`,
                    { artifact: name, evidence },
                );
            }
            if (entry.disabled && updateSet.has(entry.name)) {
                ctx.alerts.fire(
                    "packages",
                    PACKAGE_RULES.updateDisabled,
                    `System update component disabled: ${entry.name}`,
                    { artifact: name, evidence },
                );
            }

            if (ctx.indicators === undefined) {
                continue;
            }

            const appIdHit = ctx.indicators.checkAppId(entry.name);
            if (appIdHit !== undefined) {
                ctx.alerts.indicatorMatch("packages", appIdHit, appIdHit.message, {
                    artifact: name,
                    evidence,
                });
            }

            for (const file of entry.files) {
                if (file.sha256 !== undefined) {
                    const hashHit = ctx.indicators.checkFileHash(file.sha256);
                    if (hashHit !== undefined) {
                        ctx.alerts.indicatorMatch("packages", hashHit, hashHit.message, {
                            artifact: name,
                            evidence: { ...evidence, path: file.path, sha256: file.sha256 },
                        });
                    }
                }

                for (const certificateHash of file.certificateHashes) {
                    const certHit = ctx.indicators.checkAppCertificateHash(certificateHash);
                    if (certHit !== undefined) {
                        ctx.alerts.indicatorMatch("packages", certHit, certHit.message, {
                            artifact: name,
                            evidence: {
                                ...evidence,
                                path: file.path,
                                certificate_hash: certificateHash,
                            },
                        });
                        break;
                    }
                }
            }
        }
    },
};
