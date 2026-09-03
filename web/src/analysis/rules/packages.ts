import type { Rule } from "../alerts.js";

/**
 * Package-level rule data.
 *
 * Two kinds of judgement live here, and they are deliberately kept apart:
 *
 *   - **How a package arrived.** The installer identifies the install path. A
 *     package with no installer on a non-system partition was placed there by
 *     adb or by a process acting outside the normal package manager flow, which
 *     is how nearly every Android implant is deployed.
 *
 *   - **What the device's defences are doing.** A disabled security or OTA
 *     package is an active step to keep the device vulnerable and unpatched, and
 *     is much harder to explain innocently than a sideloaded app.
 *
 * The root-management list is intentionally short and named. A long list of
 * every historical rooting app would produce noise and imply a completeness the
 * list cannot have, since a renamed package defeats it entirely. It identifies
 * what it can and the report says the check is name-based.
 */

export const ROOT_MANAGEMENT_PACKAGES: readonly string[] = [
    "com.topjohnwu.magisk",
    "io.github.huskydg.magisk",
    "me.weishu.kernelsu",
    "com.rifsxd.ksunext",
    "me.bmax.apatch",
    "eu.chainfire.supersu",
    "eu.chainfire.supersu.pro",
    "com.koushikdutta.superuser",
    "com.noshufou.android.su",
    "com.noshufou.android.su.elite",
    "com.thirdparty.superuser",
    "com.kingouser.com",
    "com.yellowes.su",
    "me.phh.superuser",
    "com.topjohnwu.magisk.delta",
];

/** Frameworks that inject code into other processes; root-adjacent but distinct. */
export const CODE_INJECTION_PACKAGES: readonly string[] = [
    "de.robv.android.xposed.installer",
    "org.lsposed.manager",
    "org.lsposed.daemon",
    "io.github.lsposed.manager",
    "com.saurik.substrate",
];

/** Apps whose purpose is to conceal root from other applications. */
export const ROOT_CONCEALMENT_PACKAGES: readonly string[] = [
    "com.devadvance.rootcloak",
    "com.devadvance.rootcloakplus",
    "com.amphoras.hidemyroot",
    "com.amphoras.hidemyrootadfree",
    "com.formyhm.hideroot",
    "com.formyhm.hiderootPremium",
    "com.zachspong.temprootremovejb",
];

/** OEM components whose absence or disablement degrades platform security. */
export const SECURITY_PACKAGES: readonly string[] = [
    "com.policydm",
    "com.samsung.android.securitylogagent",
    "com.samsung.android.app.omcagent",
    "com.sec.android.soagent",
    "com.google.android.gms",
];

/** Components responsible for delivering system updates. */
export const SYSTEM_UPDATE_PACKAGES: readonly string[] = [
    "com.android.updater",
    "com.google.android.gms",
    "com.huawei.android.hwouc",
    "com.lge.lgdmsclient",
    "com.motorola.ccc.ota",
    "com.oneplus.opbackup",
    "com.oppo.ota",
    "com.transsion.systemupdate",
    "com.wssyncmldm",
    "com.xiaomi.market",
];

export type InstallerClass = "store" | "third-party-store" | "package-installer" | "none" | "other";

const STORE_INSTALLERS = new Set([
    "com.android.vending",
    "com.amazon.venezia",
    "com.sec.android.app.samsungapps",
    "com.huawei.appmarket",
    "com.xiaomi.mipicks",
    "com.heytap.market",
    "com.bbk.appstore",
]);

const THIRD_PARTY_STORE_INSTALLERS = new Set([
    "org.fdroid.fdroid",
    "com.aurora.store",
    "com.apkpure.aegon",
    "com.github.yeriomin.yalpstore",
]);

/**
 * The system package installer.
 *
 * This is what appears as the installer when a user installs an APK obtained
 * outside a store — from a browser download, a messaging app, or a file manager.
 * It records that the file was already on the device and the user confirmed the
 * install, which is the classic social-engineering delivery path.
 */
const PACKAGE_INSTALLERS = new Set([
    "com.android.packageinstaller",
    "com.google.android.packageinstaller",
    "com.google.android.permissioncontroller",
    "com.miui.packageinstaller",
    "com.samsung.android.packageinstaller",
]);

export function classifyInstaller(installer: string | null | undefined): InstallerClass {
    if (installer === null || installer === undefined || installer === "" || installer === "null") {
        return "none";
    }
    if (STORE_INSTALLERS.has(installer)) {
        return "store";
    }
    if (THIRD_PARTY_STORE_INSTALLERS.has(installer)) {
        return "third-party-store";
    }
    if (PACKAGE_INSTALLERS.has(installer)) {
        return "package-installer";
    }
    return "other";
}

export const PACKAGE_RULES = {
    rootManagement: {
        id: "package.root_management",
        level: "high",
        rationale:
            "A root management application is installed, so privileged access can be " +
            "granted to other applications on demand. This is a name-based check and " +
            "a renamed package will not be identified.",
    },
    codeInjection: {
        id: "package.code_injection_framework",
        level: "high",
        rationale:
            "A code injection framework is installed. These modify other applications " +
            "in memory, which can defeat both app-level protections and this " +
            "acquisition's own observations.",
    },
    rootConcealment: {
        id: "package.root_concealment",
        level: "high",
        rationale:
            "An application whose purpose is to hide root from other applications is " +
            "installed, so negative root findings elsewhere in this report carry less " +
            "weight.",
    },
    sideloaded: {
        id: "package.sideloaded_no_installer",
        level: "medium",
        rationale:
            "A non-system package with no recorded installer was placed on the device " +
            "outside the normal store flow — typically over adb. This is the usual " +
            "deployment path for targeted Android implants.",
    },
    packageInstaller: {
        id: "package.installed_from_file",
        level: "medium",
        rationale:
            "The package was installed from a local APK file via the system installer, " +
            "meaning it came from a download, a message, or a file manager rather than " +
            "a store.",
    },
    thirdPartyStore: {
        id: "package.third_party_store",
        level: "informational",
        rationale:
            "The package came from an alternative store. Ordinary for some users, and " +
            "recorded for context rather than as a weakness.",
    },
    securityDisabled: {
        id: "package.security_component_disabled",
        level: "high",
        rationale:
            "A component that contributes to platform security has been disabled. " +
            "Disabling it requires elevated privilege and has no benign explanation in " +
            "normal use.",
    },
    updateDisabled: {
        id: "package.update_component_disabled",
        level: "high",
        rationale:
            "A system update component has been disabled, which keeps the device on a " +
            "known-vulnerable build indefinitely.",
    },
} as const satisfies Record<string, Rule>;

export const PACKAGE_RULE_LIST: readonly Rule[] = Object.values(PACKAGE_RULES);
