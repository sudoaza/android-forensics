import type { Rule } from "../alerts.js";
import type { AnalysisContext, Analyzer } from "../analyzer.js";

/**
 * Root indicators and mount state.
 *
 * `root_binaries.json` is this collector's own artifact and records observations
 * rather than a verdict, including which probes were inconclusive. That
 * distinction is carried through into the report: a path the shell was refused
 * permission to check is not evidence of absence, and reporting it as clean
 * would be the single most misleading thing this analyzer could do.
 *
 * The mount check is independent of the binary search and harder to defeat: a
 * writable system or vendor partition is a state, not a file that can be hidden
 * from `which`.
 */

const ROOT_BINARIES_PATTERN = "*/root_binaries.json";
const MOUNTS_PATTERNS = ["*/security/proc_mounts.txt", "*/security/mounts.txt", "*/mounts.json"];

const RULES = {
    binaryPresent: {
        id: "root.binary_present",
        level: "high",
        rationale:
            "A binary associated with rooting was found on the device. Presence is not " +
            "proof that root was used, but it requires explanation.",
    },
    pathPresent: {
        id: "root.path_present",
        level: "high",
        rationale:
            "A filesystem path associated with a rooting framework exists. These paths " +
            "are created by installation rather than by normal use.",
    },
    shellIsRoot: {
        id: "root.adb_shell_is_root",
        level: "high",
        rationale:
            "The adb shell ran as root. On a production build this is not possible " +
            "without the device having been modified.",
    },
    indeterminate: {
        id: "root.probe_indeterminate",
        level: "informational",
        rationale:
            "Some root checks could not be completed because the shell was refused " +
            "permission. Those paths are unknown, not absent, and the negative result " +
            "elsewhere in this section is correspondingly weaker.",
    },
    systemWritable: {
        id: "mount.system_writable",
        level: "high",
        rationale:
            "A partition that is read-only on an unmodified device is mounted " +
            "writable, so its contents may have been altered after the build was " +
            "signed.",
    },
} as const satisfies Record<string, Rule>;

export const ROOT_RULES: readonly Rule[] = Object.values(RULES);

/** Partitions that must be read-only on an unmodified device. */
const READ_ONLY_PARTITIONS = ["/system", "/vendor", "/product", "/system_ext", "/odm"];

export interface MountEntry {
    readonly device: string;
    readonly mountPoint: string;
    readonly filesystem: string;
    readonly options: readonly string[];
}

/** Parses `/proc/mounts` or `mount` output. */
export function parseMounts(content: string): readonly MountEntry[] {
    const entries: MountEntry[] = [];

    for (const line of content.split("\n")) {
        const trimmed = line.trim();
        if (trimmed === "") {
            continue;
        }

        // /proc/mounts: `device mountpoint fstype options dump pass`
        const fields = trimmed.split(/\s+/);
        if (fields.length >= 4 && fields[1]?.startsWith("/") === true) {
            entries.push({
                device: fields[0] ?? "",
                mountPoint: fields[1] ?? "",
                filesystem: fields[2] ?? "",
                options: (fields[3] ?? "").split(","),
            });
            continue;
        }

        // `mount` output: `device on /mountpoint type fstype (options)`
        const busybox = /^(\S+) on (\S+) type (\S+) \((.*)\)$/.exec(trimmed);
        if (busybox !== null) {
            entries.push({
                device: busybox[1] ?? "",
                mountPoint: busybox[2] ?? "",
                filesystem: busybox[3] ?? "",
                options: (busybox[4] ?? "").split(","),
            });
        }
    }

    return entries;
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
    return typeof value === "object" && value !== null && !Array.isArray(value)
        ? (value as Record<string, unknown>)
        : undefined;
}

export const rootAnalyzer: Analyzer = {
    id: "root",
    label: "Root indicators and mount state",
    inputs: [ROOT_BINARIES_PATTERN, ...MOUNTS_PATTERNS],
    rules: ROOT_RULES,

    async run(ctx: AnalysisContext): Promise<void> {
        await analyseRootBinaries(ctx);
        await analyseMounts(ctx);
    },
};

/**
 * Reads `root_binaries.json` in either shape.
 *
 * AndroidQF writes a flat array of path strings. This collector writes an object
 * with `binaries`, `paths` and `summary`. Both are accepted so an archive from
 * either tool is analysable, and so our own richer fields (notably
 * `indeterminate`) are used when available.
 */
async function analyseRootBinaries(ctx: AnalysisContext): Promise<void> {
    const name = ctx.source.match(ROOT_BINARIES_PATTERN)[0];
    if (name === undefined) {
        return;
    }

    let parsed: unknown;
    try {
        parsed = JSON.parse(await ctx.source.text(name));
    } catch (error) {
        ctx.note(name, error instanceof Error ? error.message : String(error));
        return;
    }

    // AndroidQF form: a flat array of paths that were found to exist.
    if (Array.isArray(parsed)) {
        ctx.examined(name);
        for (const value of parsed) {
            if (typeof value !== "string" || value === "") {
                continue;
            }
            ctx.alerts.fire("root", RULES.pathPresent, `Root binary present at ${value}`, {
                artifact: name,
                evidence: { path: value },
            });
        }
        return;
    }

    const report = asRecord(parsed);
    if (report === undefined) {
        ctx.note(name, "root_binaries.json is neither an array nor an object.");
        return;
    }
    ctx.examined(name);

    const binaries = report["binaries"];
    if (Array.isArray(binaries)) {
        for (const raw of binaries) {
            const binary = asRecord(raw);
            const binaryName = binary?.["name"];
            const paths = binary?.["paths"];
            if (typeof binaryName !== "string" || !Array.isArray(paths) || paths.length === 0) {
                continue;
            }
            ctx.alerts.fire(
                "root",
                RULES.binaryPresent,
                `Root binary "${binaryName}" found at ${paths.join(", ")}`,
                { artifact: name, evidence: { binary: binaryName, paths } },
            );
        }
    }

    const paths = report["paths"];
    let indeterminate = 0;
    if (Array.isArray(paths)) {
        for (const raw of paths) {
            const entry = asRecord(raw);
            const path = entry?.["path"];
            if (typeof path !== "string") {
                continue;
            }
            if (entry?.["indeterminate"] === true) {
                indeterminate += 1;
                continue;
            }
            if (entry?.["present"] === true) {
                ctx.alerts.fire("root", RULES.pathPresent, `Root-related path present: ${path}`, {
                    artifact: name,
                    evidence: { path, detail: entry?.["detail"] ?? null },
                });
            }
        }
    }

    if (indeterminate > 0) {
        ctx.alerts.fire(
            "root",
            RULES.indeterminate,
            `${indeterminate} root path check${indeterminate === 1 ? "" : "s"} could not be ` +
                "completed because the shell was refused permission; those paths are unknown " +
                "rather than absent",
            { artifact: name, evidence: { indeterminate_count: indeterminate } },
        );
    }

    const managementPackages = report["root_management_packages"];
    if (Array.isArray(managementPackages) && managementPackages.length > 0) {
        // Reported by the packages analyzer from packages.json as well; recorded
        // here only as evidence on the existing finding rather than duplicated.
        ctx.progress(`${managementPackages.length} root management packages recorded`);
    }

    const summary = asRecord(report["summary"]);
    if (summary?.["shell_is_root"] === true) {
        ctx.alerts.fire("root", RULES.shellIsRoot, "The adb shell is running as root", {
            artifact: name,
            evidence: { shell_is_root: true },
        });
    }
}

async function analyseMounts(ctx: AnalysisContext): Promise<void> {
    const name = MOUNTS_PATTERNS.flatMap((pattern) => [...ctx.source.match(pattern)])[0];
    if (name === undefined) {
        return;
    }

    let content: string;
    try {
        content = await ctx.source.text(name);
    } catch (error) {
        ctx.note(name, error instanceof Error ? error.message : String(error));
        return;
    }

    // `mounts.json` holds a JSON array of the same lines, so it is unwrapped
    // before parsing rather than handled separately.
    if (name.endsWith(".json")) {
        try {
            const parsed: unknown = JSON.parse(content);
            if (Array.isArray(parsed)) {
                content = parsed.filter((line): line is string => typeof line === "string").join("\n");
            }
        } catch (error) {
            ctx.note(name, error instanceof Error ? error.message : String(error));
            return;
        }
    }

    const entries = parseMounts(content);
    if (entries.length === 0) {
        ctx.note(name, "No mount entries could be parsed.");
        return;
    }
    ctx.examined(name);

    for (const entry of entries) {
        if (!READ_ONLY_PARTITIONS.includes(entry.mountPoint)) {
            continue;
        }
        if (!entry.options.includes("rw")) {
            continue;
        }
        ctx.alerts.fire(
            "root",
            RULES.systemWritable,
            `${entry.mountPoint} is mounted read-write`,
            {
                artifact: name,
                evidence: {
                    mount_point: entry.mountPoint,
                    device: entry.device,
                    filesystem: entry.filesystem,
                    options: entry.options,
                },
            },
        );
    }
}
