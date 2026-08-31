import type { AcquisitionContext, AcquisitionModule, ModuleResult } from "../acquisition/artifact.js";
import { ResultBuilder } from "../acquisition/artifact.js";
import type { ArtifactRecord } from "../evidence/store.js";
import {
    apkArtifactName,
    isSystemPath,
    parsePackageList,
    parsePackagePaths,
    type PackageListEntry,
} from "./package-list.js";

/**
 * Package inventory and APK acquisition.
 *
 * `packages.json` mirrors the shape MVT reads from an AndroidQF acquisition:
 * per-package metadata with a `files` array carrying each APK's path and
 * SHA-256, so hash-based triage works without the APKs themselves.
 *
 * APKs are pulled with `apkPolicy`:
 *   "none"       inventory only
 *   "third-party" everything not on a read-only system partition (Standard)
 *   "all"        including system APKs (Full; adds gigabytes)
 */

export type ApkPolicy = "none" | "third-party" | "all";

interface PackageFileRecord {
    path: string;
    sha256?: string;
    size?: number;
    /** Archive path, absent when the APK was not pulled. */
    local_path?: string;
    error?: string;
}

interface PackageRecord {
    name: string;
    uid: number | null;
    system: boolean;
    installer: string | null;
    disabled: boolean;
    /**
     * Whether `pm path` was run for this package. When false, `files` holds only
     * the base APK reported by `pm list packages -f` and split APKs were not
     * enumerated.
     */
    splits_enumerated: boolean;
    files: PackageFileRecord[];
}

async function collectPackageList(
    ctx: AcquisitionContext,
    result: ResultBuilder,
): Promise<PackageListEntry[]> {
    // `-U` (uid) and `-i` (installer) are not supported on older builds, so the
    // richest invocation is tried first and the output is saved verbatim
    // alongside the parsed JSON.
    const candidates: readonly (readonly string[])[] = [
        ["pm", "list", "packages", "-U", "-f", "-i"],
        ["pm", "list", "packages", "-f", "-i"],
        ["pm", "list", "packages", "-f"],
        ["pm", "list", "packages"],
    ];

    for (const command of candidates) {
        try {
            const record = await ctx.runToArtifact(command, "packages.txt");
            const raw = await (await ctx.store.openFile(record.name)).text();
            const parsed = parsePackageList(raw);

            if (parsed.length > 0) {
                result.artifact("packages.txt");
                result.note("list_command", command.join(" "));
                return parsed;
            }
        } catch (error) {
            result.error(command.join(" "), error);
        }
    }

    return [];
}

async function collectDisabledPackages(
    ctx: AcquisitionContext,
    result: ResultBuilder,
): Promise<Set<string>> {
    try {
        const output = await ctx.run(["pm", "list", "packages", "-d"]);
        return new Set(
            output.stdout
                .split("\n")
                .map((line) => line.trim().replace(/^package:/, ""))
                .filter((line) => line.length > 0),
        );
    } catch (error) {
        result.error("pm list packages -d", error);
        return new Set();
    }
}

/**
 * Resolves every APK belonging to a package, including splits.
 *
 * `pm list packages -f` reports only one path, so `pm path` is required to find
 * split APKs. Split configs are where a malicious payload can hide while
 * `base.apk` looks unremarkable.
 */
async function resolvePackageFiles(
    ctx: AcquisitionContext,
    entry: PackageListEntry,
    result: ResultBuilder,
): Promise<string[]> {
    try {
        const output = await ctx.run(["pm", "path", entry.name]);
        const paths = parsePackagePaths(output.stdout);
        if (paths.length > 0) {
            return paths;
        }
    } catch (error) {
        result.error(`pm path ${entry.name}`, error);
    }

    return entry.apkPath === undefined ? [] : [entry.apkPath];
}

export function packagesModule(apkPolicy: ApkPolicy): AcquisitionModule {
    return {
        id: "packages",
        label: apkPolicy === "none" ? "Package inventory" : "Packages and APKs",
        supports: (device) => device.capabilities.pm,

        async run(ctx: AcquisitionContext): Promise<ModuleResult> {
            const result = new ResultBuilder();

            const entries = await collectPackageList(ctx, result);
            if (entries.length === 0) {
                result.error("pm list packages", "No packages could be enumerated", false);
                return result.build();
            }

            const disabled = await collectDisabledPackages(ctx, result);
            const records: PackageRecord[] = [];

            // A per-package `pm path` costs a full shell round trip (~1s on real
            // hardware, so ~7min for 443 packages). It is only needed to discover
            // split APKs for packages that will actually be pulled; `pm list
            // packages -f` already reported the base path for the inventory.
            const needsResolution = (entry: PackageListEntry): boolean => {
                if (apkPolicy === "none") {
                    return false;
                }
                if (apkPolicy === "all") {
                    return true;
                }
                return entry.apkPath === undefined || !isSystemPath(entry.apkPath);
            };

            const resolved: { entry: PackageListEntry; paths: string[]; splitsResolved: boolean }[] =
                [];
            const toResolve = entries.filter(needsResolution);
            let resolvedCount = 0;

            for (const entry of entries) {
                ctx.signal.throwIfAborted();

                if (!needsResolution(entry)) {
                    resolved.push({
                        entry,
                        paths: entry.apkPath === undefined ? [] : [entry.apkPath],
                        splitsResolved: false,
                    });
                    continue;
                }

                resolvedCount += 1;
                ctx.progress(`Resolving ${entry.name}`, resolvedCount, toResolve.length);
                resolved.push({
                    entry,
                    paths: await resolvePackageFiles(ctx, entry, result),
                    splitsResolved: true,
                });
            }

            const shouldPull = (entry: PackageListEntry, apkPath: string): boolean => {
                if (apkPolicy === "none") {
                    return false;
                }
                if (apkPolicy === "all") {
                    return true;
                }
                return !isSystemPath(apkPath ?? entry.apkPath);
            };

            const pullTargets = resolved.flatMap(({ entry, paths }) =>
                paths.filter((path) => shouldPull(entry, path)).map((path) => ({ entry, path })),
            );
            const totalPulls = pullTargets.length;
            let completedPulls = 0;

            for (const { entry, paths, splitsResolved } of resolved) {
                ctx.signal.throwIfAborted();

                const system = isSystemPath(entry.apkPath ?? paths[0]);
                const files: PackageFileRecord[] = [];

                for (const path of paths) {
                    ctx.signal.throwIfAborted();

                    if (!shouldPull(entry, path)) {
                        files.push({ path });
                        continue;
                    }

                    completedPulls += 1;
                    ctx.progress(`${entry.name} (${path.split("/").pop()})`, completedPulls, totalPulls);

                    const artifactName = apkArtifactName(entry.name, path);
                    let record: ArtifactRecord | undefined;
                    try {
                        record = await ctx.pullToArtifact(path, artifactName);
                        result.artifact(artifactName);
                    } catch (error) {
                        const message = error instanceof Error ? error.message : String(error);
                        // A single unreadable APK is normal; keep the metadata.
                        result.error(path, error);
                        files.push({ path, error: message });
                        continue;
                    }

                    files.push({
                        path,
                        sha256: record.sha256,
                        size: record.size,
                        local_path: artifactName,
                    });
                }

                records.push({
                    name: entry.name,
                    uid: entry.uid ?? null,
                    system,
                    installer: entry.installer ?? null,
                    disabled: disabled.has(entry.name),
                    // Records that `files` may omit split APKs, so an analyst does
                    // not read a single-entry list as proof the package has no
                    // splits.
                    splits_enumerated: splitsResolved,
                    files,
                });
            }

            try {
                await ctx.writeText(
                    "packages.json",
                    `${JSON.stringify(records, undefined, 2)}\n`,
                );
                result.artifact("packages.json");
            } catch (error) {
                result.error("packages.json", error);
            }

            result.note("packages", records.length);
            result.note("third_party_packages", records.filter((entry) => !entry.system).length);
            result.note("apks_pulled", completedPulls);

            return result.build();
        },
    };
}

/**
 * Richer package metadata, kept separate because on some builds these commands
 * are slow enough to be worth failing independently.
 */
export const packageDetailModule: AcquisitionModule = {
    id: "package-detail",
    label: "Package details",
    supports: (device) => device.capabilities.cmd,

    async run(ctx: AcquisitionContext): Promise<ModuleResult> {
        const result = new ResultBuilder();

        const probes: readonly { command: readonly string[]; artifact: string }[] = [
            {
                command: ["cmd", "package", "list", "packages", "-U", "-f", "-i", "-u"],
                artifact: "packages_including_uninstalled.txt",
            },
            {
                command: ["dumpsys", "package", "packages"],
                artifact: "dumpsys_packages.txt",
            },
        ];

        for (const [index, probe] of probes.entries()) {
            ctx.signal.throwIfAborted();
            ctx.progress(probe.artifact, index + 1, probes.length);
            try {
                await ctx.streamToArtifact(probe.command, probe.artifact);
                result.artifact(probe.artifact);
            } catch (error) {
                result.error(probe.command.join(" "), error);
            }
        }

        return result.build();
    },
};
