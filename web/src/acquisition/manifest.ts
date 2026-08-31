import type { ArtifactRecord } from "../evidence/store.js";
import type { ClockCorrelation } from "./clock.js";
import type { ModuleError, ModuleStatus } from "./artifact.js";
import type { DeviceContext } from "./device-context.js";
import type { ProfileId } from "./profiles.js";

export const COLLECTOR_NAME = "webadb-forensics";
export const COLLECTOR_VERSION = "0.1.0";
export const MANIFEST_FORMAT_VERSION = 1;

export interface ModuleReport {
    readonly id: string;
    readonly label: string;
    readonly status: ModuleStatus;
    readonly startedAt: string;
    readonly completedAt: string;
    readonly durationMs: number;
    readonly artifacts: readonly string[];
    readonly errors: readonly ModuleError[];
    readonly notes?: Readonly<Record<string, unknown>>;
}

export interface AcquisitionSummary {
    readonly acquisitionId: string;
    readonly caseId: string | undefined;
    readonly examiner: string | undefined;
    readonly station: string;
    readonly profile: ProfileId;
    readonly startedAt: string;
    readonly completedAt: string;
    readonly device: DeviceContext;
    readonly hostPublicKey: string;
    readonly credentialProtection: string;
    readonly clockStart: ClockCorrelation;
    readonly clockEnd: ClockCorrelation | undefined;
    readonly modules: readonly ModuleReport[];
    readonly artifacts: readonly ArtifactRecord[];
    readonly cancelled: boolean;
    readonly abortReason: string | undefined;
}

/**
 * Builds `acquisition.json`.
 *
 * Two compatibility requirements drive the shape:
 *
 *   1. MVT's AndroidQF parser reads `adb_host_public_key` from this file,
 *      falling back to an `adb_host_key.pub` file. Both are produced.
 *
 *   2. AndroidQF-style top-level keys (`uuid`, `serial_number`, `build`,
 *      `collector`) are emitted so MVT recognizes the acquisition, while
 *      collector-specific detail lives under namespaced keys. The `format` key
 *      makes clear this is not AndroidQF output, since claiming otherwise would
 *      misrepresent provenance.
 */
export function buildManifest(summary: AcquisitionSummary): string {
    const device = summary.device;

    const manifest = {
        format: COLLECTOR_NAME,
        format_version: MANIFEST_FORMAT_VERSION,

        uuid: summary.acquisitionId,
        started: summary.startedAt,
        completed: summary.completedAt,

        // AndroidQF-compatible fields, read by MVT.
        serial_number: device.serial,
        adb_host_public_key: summary.hostPublicKey,
        build: device.buildFingerprint ?? null,

        collector: {
            name: COLLECTOR_NAME,
            version: COLLECTOR_VERSION,
            // Recorded because acquisition semantics are tied to the build that ran.
            user_agent: typeof navigator === "undefined" ? null : navigator.userAgent,
        },

        case: {
            case_id: summary.caseId ?? null,
            examiner: summary.examiner ?? null,
            station: summary.station,
        },

        transport: {
            type: "webusb",
            adb_features: device.adbFeatures,
            shell_protocol: device.hasShellV2 ? "shell_v2" : "none",
            credential_protection: summary.credentialProtection,
        },

        device: {
            serial: device.serial,
            usb_name: device.usbName,
            manufacturer: device.manufacturer ?? null,
            brand: device.brand ?? null,
            model: device.model ?? null,
            device: device.device ?? null,
            android_release: device.androidRelease ?? null,
            sdk: device.sdk ?? null,
            security_patch: device.securityPatch ?? null,
            build_fingerprint: device.buildFingerprint ?? null,
            cpu: device.abi ?? null,
            verified_boot_state: device.verifiedBootState ?? null,
            bootloader_locked: device.bootloaderLocked ?? null,
            selinux: device.selinux ?? null,
            shell_user: device.shellUser ?? null,
            capabilities: device.capabilities,
        },

        profile: summary.profile,

        /**
         * Host/device clock offset, measured at start and end. Required to
         * align logcat and dumpsys timestamps with external telemetry.
         */
        clock: {
            start: summary.clockStart,
            end: summary.clockEnd ?? null,
        },

        // Flat id -> status map, matching the shape in the design.
        modules: Object.fromEntries(
            summary.modules.map((module) => [module.id, module.status]),
        ),

        module_details: summary.modules,

        artifacts: {
            count: summary.artifacts.length,
            total_bytes: summary.artifacts.reduce((sum, artifact) => sum + artifact.size, 0),
            all_verified: summary.artifacts.every((artifact) => artifact.verified),
            /**
             * A manifest cannot describe itself. These entries are written after
             * this file and so are absent from the counts above, while being
             * present in `hashes.csv`. Stated explicitly so the difference is
             * accounted for rather than looking like missing evidence.
             */
            excluded_from_counts: ["acquisition.json", "manifest.sha256.json", "hashes.csv"],
        },

        errors: {
            total: summary.modules.reduce((sum, module) => sum + module.errors.length, 0),
            expected: summary.modules.reduce(
                (sum, module) => sum + module.errors.filter((error) => error.expected).length,
                0,
            ),
        },

        completion: {
            cancelled: summary.cancelled,
            abort_reason: summary.abortReason ?? null,
        },
    };

    return `${JSON.stringify(manifest, undefined, 2)}\n`;
}

/**
 * Richer per-artifact hash record, alongside `hashes.csv`.
 *
 * `hashes.csv` is kept byte-compatible with AndroidQF's format for tooling,
 * so size and timestamp detail goes here instead of being added as extra
 * columns there.
 */
export function buildHashManifest(artifacts: readonly ArtifactRecord[]): string {
    const entries = Object.fromEntries(
        artifacts.map((artifact) => [
            artifact.name,
            {
                sha256: artifact.sha256,
                size: artifact.size,
                acquired_at: artifact.acquiredAt,
                verified: artifact.verified,
            },
        ]),
    );
    return `${JSON.stringify(entries, undefined, 2)}\n`;
}
