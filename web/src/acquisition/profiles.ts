import type { AcquisitionModule } from "./artifact.js";
import { bugreportModule } from "../modules/bugreport.js";
import {
    kernelLogModule,
    logDirectoriesModule,
    systemLogsModule,
    tmpDirectoriesModule,
} from "../modules/logs.js";
import { packageDetailModule, packagesModule } from "../modules/packages.js";
import { rootIndicatorsModule } from "../modules/root.js";
import {
    bootStateModule,
    networkStateModule,
    schedulingModule,
    securityStateModule,
} from "../modules/security.js";
import {
    dumpsysModule,
    dumpsysServicesModule,
    getpropModule,
    logcatModule,
    processesModule,
    servicesModule,
    settingsModule,
} from "../modules/system.js";

export type ProfileId = "quick" | "standard" | "full";

export interface Profile {
    readonly id: ProfileId;
    readonly label: string;
    readonly description: string;
    readonly modules: readonly AcquisitionModule[];
}

/**
 * Modules run in a fixed order: cheap state first, expensive transfers last.
 *
 * This is deliberate. If the cable is pulled or the battery dies mid-run, the
 * artifacts most likely to establish the device's state have already been
 * captured, and only bulk transfers are lost.
 *
 * No runtime estimates are shown anywhere: APK volume and bugreport generation
 * time vary by more than an order of magnitude across devices.
 */

const QUICK_MODULES: readonly AcquisitionModule[] = [
    getpropModule,
    settingsModule,
    processesModule,
    servicesModule,
    bootStateModule,
    rootIndicatorsModule,
    securityStateModule,
    networkStateModule,
    schedulingModule,
    dumpsysServicesModule,
    // Inventory without APK transfer keeps Quick small.
    packagesModule("none"),
    logcatModule,
];

const STANDARD_MODULES: readonly AcquisitionModule[] = [
    getpropModule,
    settingsModule,
    processesModule,
    servicesModule,
    bootStateModule,
    rootIndicatorsModule,
    securityStateModule,
    networkStateModule,
    schedulingModule,
    dumpsysServicesModule,
    packagesModule("third-party"),
    packageDetailModule,
    logcatModule,
    kernelLogModule,
    dumpsysModule,
    systemLogsModule,
    logDirectoriesModule,
    tmpDirectoriesModule,
    bugreportModule,
];

const FULL_MODULES: readonly AcquisitionModule[] = [
    getpropModule,
    settingsModule,
    processesModule,
    servicesModule,
    bootStateModule,
    rootIndicatorsModule,
    securityStateModule,
    networkStateModule,
    schedulingModule,
    dumpsysServicesModule,
    packagesModule("all"),
    packageDetailModule,
    logcatModule,
    kernelLogModule,
    dumpsysModule,
    systemLogsModule,
    logDirectoriesModule,
    tmpDirectoriesModule,
    bugreportModule,
];

export const PROFILES: Readonly<Record<ProfileId, Profile>> = {
    quick: {
        id: "quick",
        label: "Quick triage",
        description:
            "Device state, security posture, package inventory and logcat. No APK or " +
            "bugreport transfer, so evidence volume stays small.",
        modules: QUICK_MODULES,
    },
    standard: {
        id: "standard",
        label: "Standard",
        description:
            "Quick, plus third-party APKs, full dumpsys, readable diagnostic logs, " +
            "temp directories and bugreport.zip.",
        modules: STANDARD_MODULES,
    },
    full: {
        id: "full",
        label: "Full",
        description:
            "Standard, plus system APKs. Substantially larger and slower; use when the " +
            "system partition itself is in question.",
        modules: FULL_MODULES,
    },
};

export function profileFor(id: ProfileId): Profile {
    return PROFILES[id];
}
