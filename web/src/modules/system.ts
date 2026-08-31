import type { AcquisitionModule } from "../acquisition/artifact.js";
import {
    commandArtifact,
    commandGroup,
    fallbackCommandArtifact,
} from "../acquisition/declarative.js";

/**
 * System state, settings, processes, services and logs.
 *
 * Artifact names match AndroidQF where MVT's parsers key on them
 * (`getprop.txt`, `settings_*.txt`, `logcat.txt`, `dumpsys.txt`), so MVT can
 * consume the archive unchanged.
 */

export const getpropModule: AcquisitionModule = commandArtifact({
    id: "getprop",
    label: "System properties",
    command: ["getprop"],
    artifact: "getprop.txt",
});

export const settingsModule: AcquisitionModule = commandGroup({
    id: "settings",
    label: "Settings",
    supports: (device) => device.capabilities.settings,
    items: [
        { command: ["settings", "list", "system"], artifact: "settings_system.txt" },
        { command: ["settings", "list", "secure"], artifact: "settings_secure.txt" },
        { command: ["settings", "list", "global"], artifact: "settings_global.txt" },
    ],
});

/**
 * `ps` flag support varies widely across OEM builds, so the richest form is
 * tried first and the command that actually ran is recorded.
 */
export const processesModule: AcquisitionModule = fallbackCommandArtifact({
    id: "processes",
    label: "Processes",
    artifact: "processes.txt",
    candidates: [
        ["ps", "-A", "-o", "USER,PID,PPID,VSZ,RSS,WCHAN,ADDR,S,NAME"],
        ["ps", "-A", "-o", "USER,PID,PPID,VSZ,RSS,S,NAME"],
        ["ps", "-A"],
        ["ps"],
    ],
});

export const servicesModule: AcquisitionModule = commandGroup({
    id: "services",
    label: "Services",
    items: [
        { command: ["service", "list"], artifact: "services.txt" },
        {
            command: ["dumpsys", "activity", "services"],
            artifact: "services_activity.txt",
            stream: true,
        },
    ],
});

/**
 * Logcat, from both the live ring buffers and the pre-reboot buffers.
 *
 * `-d` dumps the current buffers; `-L` reads the last boot's, which is where
 * evidence of a crash or a reboot-triggered payload survives. `-g` records
 * buffer sizes so a truncated log is not mistaken for a quiet device.
 *
 * Streamed: on a real MIUI device `-b all '*:V'` produced a 101 MB dump, so
 * buffering is not an option. `-L` is optional because a device that retained no
 * prior-boot buffer reports "Logcat read failure", which is a device condition
 * rather than a collection fault.
 *
 * The buffer-size probe runs first, so `logcat_buffers.txt` is present to
 * corroborate the size of the dump even if the dump itself is interrupted.
 */
export const logcatModule: AcquisitionModule = commandGroup({
    id: "logcat",
    label: "Logcat",
    items: [
        { command: ["logcat", "-g", "-b", "all"], artifact: "logcat_buffers.txt" },
        { command: ["logcat", "-d", "-b", "all", "*:V"], artifact: "logcat.txt", stream: true },
        {
            command: ["logcat", "-L", "-b", "all", "*:V"],
            artifact: "logcat_old.txt",
            stream: true,
            optional: true,
        },
    ],
});

/** Full dumpsys. Large, so streamed; Standard profile and above only. */
export const dumpsysModule: AcquisitionModule = commandArtifact({
    id: "dumpsys",
    label: "Full dumpsys",
    command: ["dumpsys"],
    artifact: "dumpsys.txt",
    stream: true,
    supports: (device) => device.capabilities.dumpsys,
});

export const dumpsysServicesModule: AcquisitionModule = commandArtifact({
    id: "dumpsys-list",
    label: "Dumpsys service list",
    command: ["dumpsys", "-l"],
    artifact: "dumpsys_services.txt",
    supports: (device) => device.capabilities.dumpsys,
});
