import type { AcquisitionContext, AcquisitionModule, ModuleResult } from "../acquisition/artifact.js";
import { ResultBuilder } from "../acquisition/artifact.js";

/**
 * Root and tampering indicators.
 *
 * Presence of a binary is not proof of compromise, and absence is not proof of
 * integrity: a competent root hider defeats a `which` probe. The module
 * therefore records observations rather than a verdict, and pairs the binary
 * search with verified-boot state, which is far harder to forge.
 */

const ROOT_BINARIES = [
    "su",
    "magisk",
    "magiskinit",
    "magiskpolicy",
    "magiskboot",
    "resetprop",
    "supolicy",
    "busybox",
    "daemonsu",
    "ksud",
    "zygisk",
] as const;

/**
 * Paths checked directly, because `which` only searches `$PATH` and rooting
 * frameworks frequently install outside it.
 */
const ROOT_PATHS = [
    "/sbin/su",
    "/system/bin/su",
    "/system/xbin/su",
    "/system/sbin/su",
    "/vendor/bin/su",
    "/data/local/tmp/su",
    "/data/local/bin/su",
    "/data/adb/magisk",
    "/data/adb/ksu",
    "/data/adb/modules",
    "/sbin/.magisk",
    "/cache/magisk.log",
    "/system/app/Superuser.apk",
    "/system/app/SuperSU",
    "/system/etc/init.d",
] as const;

const PACKAGES_OF_INTEREST = [
    "com.topjohnwu.magisk",
    "com.noshufou.android.su",
    "eu.chainfire.supersu",
    "me.weishu.kernelsu",
    "com.koushikdutta.superuser",
    "de.robv.android.xposed.installer",
    "org.lsposed.manager",
] as const;

interface BinaryFinding {
    readonly name: string;
    readonly paths: readonly string[];
}

interface PathFinding {
    readonly path: string;
    /** True only when the path was confirmed to exist. */
    readonly present: boolean;
    /**
     * True when the shell refused the check, so presence is unknown rather than
     * negative. Recorded separately because "cannot tell" must not be read as
     * "absent" during analysis.
     */
    readonly indeterminate: boolean;
    readonly detail: string;
}

export const rootIndicatorsModule: AcquisitionModule = {
    id: "root-indicators",
    label: "Root and tampering indicators",

    async run(ctx: AcquisitionContext): Promise<ModuleResult> {
        const result = new ResultBuilder();

        const binaries: BinaryFinding[] = [];
        const paths: PathFinding[] = [];
        const installedPackages: string[] = [];

        let step = 0;
        const totalSteps = ROOT_BINARIES.length + ROOT_PATHS.length + 1;

        for (const name of ROOT_BINARIES) {
            ctx.signal.throwIfAborted();
            ctx.progress(`which ${name}`, (step += 1), totalSteps);

            try {
                // `which` exits non-zero when the binary is absent, which is the
                // expected answer on a clean device, not a collection failure.
                const found = await ctx.run(["which", "-a", name], { tolerateFailure: true });
                const lines = found.stdout
                    .split("\n")
                    .map((line) => line.trim())
                    .filter((line) => line.startsWith("/"));

                if (lines.length > 0) {
                    binaries.push({ name, paths: lines });
                }
            } catch (error) {
                result.error(`which -a ${name}`, error);
            }
        }

        for (const path of ROOT_PATHS) {
            ctx.signal.throwIfAborted();
            ctx.progress(`stat ${path}`, (step += 1), totalSteps);

            try {
                // `ls -ld` rather than sync stat: the shell reports a readable
                // reason for refusal, which is itself worth recording. A missing
                // path exits non-zero and is the expected negative result.
                const listing = await ctx.run(["ls", "-ld", path], { tolerateFailure: true });
                const output = `${listing.stdout}${listing.stderr}`.trim();
                const missing = /no such file|not found/i.test(output);
                const denied = /permission denied|operation not permitted/i.test(output);
                const present = listing.exitCode === 0 && !missing && output.length > 0;
                paths.push({
                    path,
                    present,
                    indeterminate: !present && !missing && denied,
                    detail: output.slice(0, 300),
                });
            } catch (error) {
                result.error(path, error);
            }
        }

        ctx.progress("root management packages", (step += 1), totalSteps);
        if (ctx.device.capabilities.pm) {
            try {
                const listed = await ctx.run(["pm", "list", "packages"]);
                const present = new Set(
                    listed.stdout
                        .split("\n")
                        .map((line) => line.trim().replace(/^package:/, ""))
                        .filter((line) => line.length > 0),
                );
                for (const name of PACKAGES_OF_INTEREST) {
                    if (present.has(name)) {
                        installedPackages.push(name);
                    }
                }
            } catch (error) {
                result.error("pm list packages", error);
            }
        }

        const report = {
            collected_at: new Date().toISOString(),
            binaries,
            paths,
            root_management_packages: installedPackages,
            verified_boot: {
                state: ctx.device.verifiedBootState ?? null,
                bootloader_locked: ctx.device.bootloaderLocked ?? null,
                vbmeta_device_state: ctx.device.properties.get("ro.boot.vbmeta.device_state") ?? null,
                verity_mode: ctx.device.properties.get("ro.boot.veritymode") ?? null,
            },
            selinux: ctx.device.selinux ?? null,
            adb_shell_user: ctx.device.shellUser ?? null,
            debuggable_build: ctx.device.properties.get("ro.debuggable") ?? null,
            build_tags: ctx.device.properties.get("ro.build.tags") ?? null,
            build_type: ctx.device.properties.get("ro.build.type") ?? null,
            // Deliberately observations, not a score. Interpretation is the
            // analyst's, and a hidden root will show none of these.
            summary: {
                root_binaries_found: binaries.length,
                suspicious_paths_present: paths.filter((entry) => entry.present).length,
                // Surfaced so an analyst can see how much of the filesystem probe
                // was inconclusive rather than negative.
                paths_indeterminate: paths.filter((entry) => entry.indeterminate).length,
                test_keys: (ctx.device.properties.get("ro.build.tags") ?? "").includes("test-keys"),
                shell_is_root: ctx.device.isRootShell,
            },
        };

        try {
            await ctx.writeText("root_binaries.json", `${JSON.stringify(report, undefined, 2)}\n`);
            result.artifact("root_binaries.json");
        } catch (error) {
            result.error("root_binaries.json", error);
        }

        result.note("root_binaries_found", binaries.length);
        result.note("shell_is_root", ctx.device.isRootShell);

        return result.build();
    },
};
