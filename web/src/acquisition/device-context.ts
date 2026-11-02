import type { AdbClient } from "../adb/client.js";

/**
 * Device facts gathered during preflight, before any profile is chosen.
 *
 * Collected once and reused for capability checks, so modules never re-probe
 * the device to decide whether they apply.
 */

export interface DeviceContext {
    readonly serial: string;
    readonly usbName: string;

    readonly manufacturer: string | undefined;
    readonly brand: string | undefined;
    readonly model: string | undefined;
    readonly device: string | undefined;
    readonly androidRelease: string | undefined;
    readonly sdk: number | undefined;
    readonly securityPatch: string | undefined;
    readonly buildFingerprint: string | undefined;
    readonly abi: string | undefined;

    readonly verifiedBootState: string | undefined;
    readonly bootloaderLocked: boolean | undefined;
    readonly selinux: string | undefined;

    /** Effective shell user, e.g. "shell" or "root". */
    readonly shellUser: string | undefined;
    readonly isRootShell: boolean;

    /** Negotiated ADB protocol features. */
    readonly adbFeatures: readonly string[];
    readonly hasShellV2: boolean;

    /** All `getprop` key/values, reused by later modules. */
    readonly properties: ReadonlyMap<string, string>;

    /** Whether `cmd`, `bugreportz` etc. are usable on this device. */
    readonly capabilities: DeviceCapabilities;
}

export interface DeviceCapabilities {
    readonly bugreportz: boolean;
    readonly bugreportzProgress: boolean;
    readonly cmd: boolean;
    readonly pm: boolean;
    readonly dumpsys: boolean;
    readonly settings: boolean;
    /** Android 16+ Intrusion Logging, surfaced but not collected in 0.1. */
    readonly intrusionLogging: "supported" | "unavailable" | "unknown";
}

/**
 * Parses `getprop` output.
 *
 * Format is `[key]: [value]` per line, and values may contain `]` or newlines,
 * so the split is anchored on the `]: [` separator and the trailing `]`.
 */
export function parseGetProp(output: string): Map<string, string> {
    const properties = new Map<string, string>();
    const pattern = /^\[([^\]]+)\]: \[([\s\S]*?)\]$/gm;

    for (const match of output.matchAll(pattern)) {
        const [, key, value] = match;
        if (key !== undefined && value !== undefined) {
            properties.set(key, value);
        }
    }

    return properties;
}

function toBoolean(value: string | undefined): boolean | undefined {
    if (value === undefined) {
        return undefined;
    }
    if (value === "1" || value === "true") {
        return true;
    }
    if (value === "0" || value === "false") {
        return false;
    }
    return undefined;
}

/** Whether a probe command is actually usable, judged by output not exit code. */
async function probe(client: AdbClient, command: readonly string[]): Promise<boolean> {
    try {
        const result = await client.exec(command);
        const combined = `${result.stdout}${result.stderr}`;
        if (result.exitCode !== undefined && result.exitCode !== 0) {
            // Many `--help`-style probes exit non-zero while still proving the
            // binary exists; only a "not found" is disqualifying.
            return !/not found|inaccessible/i.test(combined);
        }
        return !/not found|inaccessible/i.test(combined);
    } catch {
        return false;
    }
}

export async function buildDeviceContext(client: AdbClient): Promise<DeviceContext> {
    const identity = client.identity;

    const getprop = await client.exec(["getprop"]);
    const properties = parseGetProp(getprop.stdout);

    const idResult = await client.exec(["id"]);
    const shellUserMatch = /uid=\d+\((?<name>[^)]+)\)/.exec(idResult.stdout);
    const shellUser = shellUserMatch?.groups?.["name"];

    const selinuxResult = await client.exec(["getenforce"]).catch(() => undefined);
    const selinux = selinuxResult?.stdout.trim() ?? undefined;

    const sdkRaw = properties.get("ro.build.version.sdk");
    const sdk = sdkRaw === undefined ? undefined : Number.parseInt(sdkRaw, 10);

    const [hasBugreportz, hasCmd, hasPm, hasDumpsys, hasSettings] = await Promise.all([
        probe(client, ["bugreportz", "-v"]),
        probe(client, ["cmd", "-l"]),
        probe(client, ["pm", "--help"]),
        probe(client, ["dumpsys", "-l"]),
        probe(client, ["settings", "--help"]),
    ]);

    // `bugreportz -p` (progress reporting) landed in Android 7 / API 24.
    const bugreportzProgress = hasBugreportz && (sdk ?? 0) >= 24;

    const abi = properties.get("ro.product.cpu.abi");
    const bootloaderLocked = toBoolean(properties.get("ro.boot.flash.locked"));

    return {
        serial: identity.serial,
        usbName: identity.name,
        manufacturer: properties.get("ro.product.manufacturer"),
        brand: properties.get("ro.product.brand"),
        model: properties.get("ro.product.model") ?? identity.model,
        device: properties.get("ro.product.device") ?? identity.device,
        androidRelease: properties.get("ro.build.version.release"),
        sdk: Number.isFinite(sdk) ? sdk : undefined,
        securityPatch: properties.get("ro.build.version.security_patch"),
        buildFingerprint: properties.get("ro.build.fingerprint"),
        abi,
        verifiedBootState: properties.get("ro.boot.verifiedbootstate"),
        bootloaderLocked,
        selinux,
        shellUser,
        isRootShell: shellUser === "root",
        adbFeatures: identity.features,
        hasShellV2: identity.features.includes("shell_v2"),
        properties,
        capabilities: {
            bugreportz: hasBugreportz,
            bugreportzProgress,
            cmd: hasCmd,
            pm: hasPm,
            dumpsys: hasDumpsys,
            settings: hasSettings,
            // Intrusion Logging is Android 16+ (API 36). Detection needs a
            // device-side probe that 0.1 does not perform, so anything new
            // enough is reported as "unknown" rather than guessed.
            intrusionLogging: sdk === undefined ? "unknown" : sdk >= 36 ? "unknown" : "unavailable",
        },
    };
}
