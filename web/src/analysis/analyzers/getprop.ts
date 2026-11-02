import { parseGetProp } from "../../acquisition/device-context.js";
import type { Rule } from "../alerts.js";
import type { AnalysisContext, Analyzer } from "../analyzer.js";

/**
 * Build and boot-state analysis, from `getprop.txt`.
 *
 * These properties qualify every other finding in the report. An unlocked
 * bootloader or a permissive SELinux does not merely add a weakness — it changes
 * what the rest of the acquisition can be trusted to prove, because the system
 * that produced those artifacts was itself modifiable. They are therefore
 * reported first and at higher severity than most configuration findings.
 *
 * The security-patch age check is a judgement about exposure, not about
 * compromise: a device months behind on patches is vulnerable to publicly known
 * exploit chains, which is context for how an implant could have arrived.
 */

const GETPROP_PATTERN = "*/getprop.txt";
/**
 * SELinux mode comes from `getenforce`, not from a property, so the artifact is
 * read here rather than in a separate analyzer: it belongs with verified boot
 * and dm-verity as a statement about how much the platform was still enforcing.
 */
const SELINUX_PATTERN = "*/security/selinux.txt";

/** Age at which the patch level is reported. Six months, in days. */
const PATCH_AGE_DAYS = 183;

const RULES = {
    verifiedBoot: {
        id: "boot.verified_boot_not_green",
        level: "high",
        rationale:
            "Verified boot reports that the boot chain was not intact. Any artifact " +
            "collected from this device was produced by software whose integrity the " +
            "platform itself does not vouch for.",
    },
    bootloaderUnlocked: {
        id: "boot.bootloader_unlocked",
        level: "high",
        rationale:
            "An unlocked bootloader permits flashing arbitrary system images, so " +
            "persistence below the OS is possible and root can be obtained without " +
            "any trace in the packages.",
    },
    verityDisabled: {
        id: "boot.dm_verity_disabled",
        level: "high",
        rationale:
            "With dm-verity off, the system partition can be modified without " +
            "detection, which defeats the integrity assumption behind file-hash " +
            "comparison.",
    },
    debuggable: {
        id: "build.debuggable",
        level: "high",
        rationale:
            "A debuggable build grants any application access to other apps' data " +
            "via the debugger, which is not a configuration weakness but a different " +
            "security model entirely.",
    },
    testKeys: {
        id: "build.test_keys",
        level: "medium",
        rationale:
            "The build is signed with publicly available test keys rather than the " +
            "vendor's release keys, so its provenance cannot be established.",
    },
    userdebug: {
        id: "build.userdebug",
        level: "medium",
        rationale:
            "A userdebug or eng build carries relaxed security defaults and an " +
            "unrestricted root shell compared with a production user build.",
    },
    selinuxPermissive: {
        id: "boot.selinux_permissive",
        level: "high",
        rationale:
            "SELinux in permissive mode logs policy violations instead of blocking " +
            "them, removing the confinement that limits a compromised process.",
    },
    patchAge: {
        id: "build.security_patch_stale",
        level: "medium",
        rationale:
            "The device is missing more than six months of security patches, so " +
            "publicly documented exploit chains are likely to apply to it.",
    },
    patchUnknown: {
        id: "build.security_patch_unknown",
        level: "low",
        rationale:
            "The security patch level could not be read, so the device's exposure to " +
            "known vulnerabilities cannot be assessed.",
    },
} as const satisfies Record<string, Rule>;

export const GETPROP_RULES: readonly Rule[] = Object.values(RULES);

/**
 * Whether the patch level is older than the threshold.
 *
 * `now` is injectable so the test suite does not depend on the wall clock; a
 * date-sensitive rule that only fails in six months' time is worse than no test.
 */
export function isPatchStale(patchLevel: string, now: Date): boolean {
    const parsed = Date.parse(`${patchLevel}T00:00:00Z`);
    if (Number.isNaN(parsed)) {
        return false;
    }
    const ageDays = (now.getTime() - parsed) / 86_400_000;
    return ageDays > PATCH_AGE_DAYS;
}

/** Reports SELinux running in permissive mode. */
async function checkSelinux(ctx: AnalysisContext): Promise<void> {
    const name = ctx.source.match(SELINUX_PATTERN)[0];
    if (name === undefined) {
        return;
    }

    let mode: string;
    try {
        mode = (await ctx.source.text(name)).trim();
    } catch (error) {
        ctx.note(name, error instanceof Error ? error.message : String(error));
        return;
    }

    if (mode.toLowerCase() === "permissive") {
        ctx.alerts.fire("getprop", RULES.selinuxPermissive, "SELinux is in permissive mode", {
            artifact: name,
            evidence: { getenforce: mode },
        });
    }
    ctx.examined(name);
}

export function getpropAnalyzer(now: () => Date = () => new Date()): Analyzer {
    return {
        id: "getprop",
        label: "Build and verified-boot state",
        inputs: [GETPROP_PATTERN, SELINUX_PATTERN],
        rules: GETPROP_RULES,

        async run(ctx: AnalysisContext): Promise<void> {
            await checkSelinux(ctx);

            const name = ctx.source.match(GETPROP_PATTERN)[0];
            if (name === undefined) {
                return;
            }

            let properties: ReadonlyMap<string, string>;
            try {
                properties = parseGetProp(await ctx.source.text(name));
            } catch (error) {
                ctx.note(name, error instanceof Error ? error.message : String(error));
                return;
            }

            if (properties.size === 0) {
                ctx.note(name, "No properties could be parsed from getprop.txt.");
                return;
            }
            ctx.examined(name);

            const fire = (rule: Rule, message: string, evidence: Record<string, unknown>): void => {
                ctx.alerts.fire("getprop", rule, message, { artifact: name, evidence });
            };

            const verifiedBoot = properties.get("ro.boot.verifiedbootstate");
            if (verifiedBoot !== undefined && verifiedBoot.toLowerCase() !== "green") {
                fire(
                    RULES.verifiedBoot,
                    `Verified boot state is "${verifiedBoot}" rather than "green"`,
                    { "ro.boot.verifiedbootstate": verifiedBoot },
                );
            }

            const locked = properties.get("ro.boot.flash.locked");
            const vbmeta = properties.get("ro.boot.vbmeta.device_state");
            if (locked === "0" || vbmeta?.toLowerCase() === "unlocked") {
                fire(RULES.bootloaderUnlocked, "The bootloader is unlocked", {
                    "ro.boot.flash.locked": locked ?? null,
                    "ro.boot.vbmeta.device_state": vbmeta ?? null,
                });
            }

            const verity = properties.get("ro.boot.veritymode");
            if (verity !== undefined && verity.toLowerCase() === "disabled") {
                fire(RULES.verityDisabled, "dm-verity is disabled", {
                    "ro.boot.veritymode": verity,
                });
            }

            if (properties.get("ro.debuggable") === "1") {
                fire(RULES.debuggable, "The build is debuggable (ro.debuggable=1)", {
                    "ro.debuggable": "1",
                });
            }

            const tags = properties.get("ro.build.tags");
            if (tags !== undefined && tags.includes("test-keys")) {
                fire(RULES.testKeys, `The build is signed with test keys (${tags})`, {
                    "ro.build.tags": tags,
                });
            }

            const buildType = properties.get("ro.build.type");
            if (buildType !== undefined && buildType !== "user") {
                fire(RULES.userdebug, `The build type is "${buildType}" rather than "user"`, {
                    "ro.build.type": buildType,
                });
            }

            const patch = properties.get("ro.build.version.security_patch");
            if (patch === undefined || patch === "") {
                fire(RULES.patchUnknown, "The security patch level is not reported", {});
            } else if (isPatchStale(patch, now())) {
                fire(
                    RULES.patchAge,
                    `The security patch level is ${patch}, more than six months old`,
                    { "ro.build.version.security_patch": patch },
                );
            }

            // Property-name indicators: some implants are identified by a
            // property they set, which survives even when their package is gone.
            if (ctx.indicators !== undefined) {
                for (const key of properties.keys()) {
                    const hit = ctx.indicators.checkAndroidPropertyName(key);
                    if (hit !== undefined) {
                        ctx.alerts.indicatorMatch("getprop", hit, hit.message, {
                            artifact: name,
                            evidence: { property: key, value: properties.get(key) ?? null },
                        });
                    }
                }
            }
        },
    };
}
