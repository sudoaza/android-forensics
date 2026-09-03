import type { AcquisitionContext, AcquisitionModule, ModuleResult } from "./artifact.js";
import { ResultBuilder } from "./artifact.js";
import type { DeviceContext } from "./device-context.js";

/**
 * Declarative helpers for the common shapes of forensic probe.
 *
 * Adding a probe should be one line here, not a new class. Only genuinely
 * stateful modules (packages, bugreport) are written by hand.
 */

export interface CommandArtifactSpec {
    readonly id: string;
    readonly label: string;
    /** Argv, never a shell string. */
    readonly command: readonly string[];
    readonly artifact: string;
    /** Stream instead of buffering, for unbounded output. */
    readonly stream?: boolean;
    /** Caps a streamed artifact, marking it truncated rather than failing. */
    readonly maxBytes?: number;
    readonly supports?: (device: DeviceContext) => boolean;
}

export function commandArtifact(spec: CommandArtifactSpec): AcquisitionModule {
    return {
        id: spec.id,
        label: spec.label,
        ...(spec.supports === undefined ? {} : { supports: spec.supports }),
        async run(ctx: AcquisitionContext): Promise<ModuleResult> {
            const result = new ResultBuilder();
            try {
                if (spec.stream === true) {
                    await ctx.streamToArtifact(
                        spec.command,
                        spec.artifact,
                        spec.maxBytes === undefined ? undefined : { maxBytes: spec.maxBytes },
                    );
                } else {
                    await ctx.runToArtifact(spec.command, spec.artifact);
                }
                result.artifact(spec.artifact);
            } catch (error) {
                result.error(spec.command.join(" "), error);
            }
            return result.build();
        },
    };
}

export interface CommandGroupSpec {
    readonly id: string;
    readonly label: string;
    readonly supports?: (device: DeviceContext) => boolean;
    readonly items: readonly {
        readonly command: readonly string[];
        readonly artifact: string;
        readonly stream?: boolean;
        /** Caps a streamed artifact, marking it truncated rather than failing. */
        readonly maxBytes?: number;
        /**
         * Marks a probe whose failure is a normal device condition rather than a
         * collection fault, so it is not counted as unexpected. Used for
         * genuinely optional sources, e.g. the pre-reboot log buffer that only
         * exists when the kernel retained one.
         */
        readonly optional?: boolean;
    }[];
}

/**
 * Several related commands under one module id, e.g. the `security/` dumpsys
 * set. Each item fails independently: one unsupported service must not cost
 * the rest of the group.
 */
export function commandGroup(spec: CommandGroupSpec): AcquisitionModule {
    return {
        id: spec.id,
        label: spec.label,
        ...(spec.supports === undefined ? {} : { supports: spec.supports }),
        async run(ctx: AcquisitionContext): Promise<ModuleResult> {
            const result = new ResultBuilder();
            let completed = 0;

            for (const item of spec.items) {
                ctx.signal.throwIfAborted();
                ctx.progress(item.artifact, completed, spec.items.length);

                try {
                    if (item.stream === true) {
                        await ctx.streamToArtifact(
                            item.command,
                            item.artifact,
                            item.maxBytes === undefined ? undefined : { maxBytes: item.maxBytes },
                        );
                    } else {
                        await ctx.runToArtifact(item.command, item.artifact);
                    }
                    result.artifact(item.artifact);
                } catch (error) {
                    result.error(
                        item.command.join(" "),
                        error,
                        item.optional === true ? true : undefined,
                    );
                }
                completed += 1;
            }

            return result.build();
        },
    };
}

export interface FallbackCommandSpec {
    readonly id: string;
    readonly label: string;
    readonly artifact: string;
    /** Tried in order until one succeeds with usable output. */
    readonly candidates: readonly (readonly string[])[];
    readonly supports?: (device: DeviceContext) => boolean;
}

/**
 * Tries progressively simpler commands until one works, recording which one
 * did. Necessary because `ps` flags, and other coreutils behaviour, vary across
 * OEM builds and Android versions; the actual command used is evidence.
 */
export function fallbackCommandArtifact(spec: FallbackCommandSpec): AcquisitionModule {
    return {
        id: spec.id,
        label: spec.label,
        ...(spec.supports === undefined ? {} : { supports: spec.supports }),
        async run(ctx: AcquisitionContext): Promise<ModuleResult> {
            const result = new ResultBuilder();

            for (const candidate of spec.candidates) {
                ctx.signal.throwIfAborted();
                try {
                    const record = await ctx.runToArtifact(candidate, spec.artifact);
                    result.artifact(spec.artifact);
                    result.note("command", candidate.join(" "));
                    result.note("bytes", record.size);
                    return result.build();
                } catch (error) {
                    result.error(candidate.join(" "), error);
                }
            }

            return result.build();
        },
    };
}

export interface PullPathsSpec {
    readonly id: string;
    readonly label: string;
    /** Device paths to attempt; absence and refusal are both normal. */
    readonly paths: readonly { readonly remote: string; readonly artifact: string }[];
    readonly supports?: (device: DeviceContext) => boolean;
}

export function pullPaths(spec: PullPathsSpec): AcquisitionModule {
    return {
        id: spec.id,
        label: spec.label,
        ...(spec.supports === undefined ? {} : { supports: spec.supports }),
        async run(ctx: AcquisitionContext): Promise<ModuleResult> {
            const result = new ResultBuilder();
            let completed = 0;

            for (const path of spec.paths) {
                ctx.signal.throwIfAborted();
                ctx.progress(path.remote, completed, spec.paths.length);

                try {
                    await ctx.pullToArtifact(path.remote, path.artifact);
                    result.artifact(path.artifact);
                } catch (error) {
                    result.error(path.remote, error);
                }
                completed += 1;
            }

            return result.build();
        },
    };
}

/**
 * Recursively copies a device directory.
 *
 * Depth and file count are bounded because directories like
 * `/data/local/tmp` can contain arbitrary attacker-controlled content, and an
 * unbounded walk would let one path consume the whole acquisition.
 */
export interface PullDirectorySpec {
    readonly id: string;
    readonly label: string;
    readonly directories: readonly { readonly remote: string; readonly prefix: string }[];
    readonly maxDepth?: number;
    readonly maxFiles?: number;
    readonly maxFileBytes?: number;
    readonly supports?: (device: DeviceContext) => boolean;
}

export function pullDirectories(spec: PullDirectorySpec): AcquisitionModule {
    const maxDepth = spec.maxDepth ?? 3;
    const maxFiles = spec.maxFiles ?? 500;
    const maxFileBytes = spec.maxFileBytes ?? 256 * 1024 * 1024;

    return {
        id: spec.id,
        label: spec.label,
        ...(spec.supports === undefined ? {} : { supports: spec.supports }),
        async run(ctx: AcquisitionContext): Promise<ModuleResult> {
            const result = new ResultBuilder();
            let fileCount = 0;

            const walk = async (remote: string, prefix: string, depth: number): Promise<void> => {
                if (depth > maxDepth) {
                    result.error(remote, `Depth limit ${maxDepth} reached`, true);
                    return;
                }

                let entries;
                try {
                    entries = await ctx.client.listDirectory(remote);
                } catch (error) {
                    result.error(remote, error);
                    return;
                }

                for (const entry of entries) {
                    ctx.signal.throwIfAborted();

                    if (fileCount >= maxFiles) {
                        result.error(remote, `File limit ${maxFiles} reached`, true);
                        return;
                    }

                    const childRemote = `${remote.replace(/\/$/, "")}/${entry.name}`;
                    const childArtifact = `${prefix.replace(/\/$/, "")}/${entry.name}`;

                    if (entry.type === "directory") {
                        await walk(childRemote, childArtifact, depth + 1);
                        continue;
                    }

                    // Symlinks are not followed: they can point outside the
                    // subtree, and their target is not the evidence here.
                    if (entry.type !== "file") {
                        result.error(childRemote, `Skipped ${entry.type}`, true);
                        continue;
                    }

                    if (entry.size > maxFileBytes) {
                        result.error(
                            childRemote,
                            `Skipped: ${entry.size} bytes exceeds limit ${maxFileBytes}`,
                            true,
                        );
                        continue;
                    }

                    fileCount += 1;
                    ctx.progress(childRemote, fileCount, maxFiles);

                    try {
                        await ctx.pullToArtifact(childRemote, childArtifact);
                        result.artifact(childArtifact);
                    } catch (error) {
                        result.error(childRemote, error);
                    }
                }
            };

            for (const directory of spec.directories) {
                ctx.signal.throwIfAborted();
                await walk(directory.remote, directory.prefix, 1);
            }

            result.note("files", fileCount);
            return result.build();
        },
    };
}
