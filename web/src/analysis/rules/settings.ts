import type { AlertLevel, Rule } from "../alerts.js";

/**
 * Android settings whose value weakens the platform's own defences.
 *
 * These are configuration findings, not malware findings: each is a state a user
 * or an application has put the device into, and each one removes a control that
 * would otherwise impede installing or hiding an implant. None is proof of
 * compromise on its own, and several have legitimate explanations — a developer's
 * device, or a user who dismissed a prompt. The rationale is carried into the
 * report so that judgement stays with the examiner.
 *
 * Namespaces correspond to the artifacts they are read from:
 * `settings_global.txt`, `settings_secure.txt`, `settings_system.txt`. A key is
 * checked in whichever namespace it appears, because OEMs move several of these
 * between `global` and `secure`; the namespace observed is recorded on the alert.
 */

export interface SettingRule extends Rule {
    readonly key: string;
    /** The value indicating the protection is intact. */
    readonly expected: string;
    /** Shown to the examiner as the finding. */
    readonly finding: string;
}

export const SETTING_RULES: readonly SettingRule[] = [
    {
        id: "setting.package_verifier_enable",
        key: "package_verifier_enable",
        expected: "1",
        level: "medium",
        finding: "Play Protect application verification is disabled",
        rationale:
            "With verification off, an installed package is never checked against " +
            "Google's malware corpus, removing the platform's main barrier to " +
            "commodity malware.",
    },
    {
        id: "setting.package_verifier_state",
        key: "package_verifier_state",
        expected: "1",
        level: "medium",
        finding: "APK package verification is disabled",
        rationale: "Packages are installed without the verifier being consulted.",
    },
    {
        id: "setting.package_verifier_user_consent",
        key: "package_verifier_user_consent",
        expected: "1",
        level: "medium",
        finding: "Consent for package verification has been withdrawn",
        rationale:
            "A negative value records that the user, or something acting as the " +
            "user, declined verification rather than merely leaving it unset.",
    },
    {
        id: "setting.verifier_verify_adb_installs",
        key: "verifier_verify_adb_installs",
        expected: "1",
        level: "medium",
        finding: "Verification of sideloaded (adb) installs is disabled",
        rationale:
            "This setting governs exactly the install path an attacker with " +
            "physical or debugging access uses, so disabling it is materially " +
            "different from disabling verification for store installs.",
    },
    {
        id: "setting.upload_apk_enable",
        key: "upload_apk_enable",
        expected: "1",
        level: "medium",
        finding: "Submission of suspicious APKs for analysis is disabled",
        rationale:
            "Prevents unknown packages on this device from ever being examined by " +
            "the platform's backend, which suppresses later detection.",
    },
    {
        id: "setting.adb_install_need_confirm",
        key: "adb_install_need_confirm",
        expected: "1",
        level: "medium",
        finding: "Confirmation of adb application installs is disabled",
        rationale:
            "Installs over adb proceed without a prompt on the device, so a " +
            "package can be added during brief physical access without any visible " +
            "interaction.",
    },
    {
        id: "setting.accessibility_enabled",
        key: "accessibility_enabled",
        expected: "0",
        level: "medium",
        finding: "One or more accessibility services are enabled",
        rationale:
            "Accessibility is the most abused surface on Android: it grants " +
            "screen reading and synthetic input, which is sufficient to capture " +
            "credentials and drive the UI. Legitimate assistive use is common, so " +
            "this is a prompt to review which service holds it, not a finding of " +
            "abuse.",
    },
    {
        id: "setting.send_security_reports",
        key: "send_security_reports",
        expected: "1",
        level: "low",
        finding: "Sharing of security reports is disabled",
        rationale: "Reduces the telemetry that would otherwise record an intrusion.",
    },
    {
        id: "setting.send_action_app_error",
        key: "send_action_app_error",
        expected: "1",
        level: "low",
        finding: "Application error reporting is disabled",
        rationale:
            "Implants frequently crash; suppressing error reports removes a record " +
            "of that instability.",
    },
    {
        id: "setting.samsung_errorlog_agree",
        key: "samsung_errorlog_agree",
        expected: "1",
        level: "low",
        finding: "Sharing of crash logs with the manufacturer is disabled (Samsung)",
        rationale: "As above, for the OEM's own diagnostic channel.",
    },
    {
        id: "setting.install_non_market_apps",
        key: "install_non_market_apps",
        expected: "0",
        level: "medium",
        finding: "Installation from unknown sources is enabled device-wide",
        rationale:
            "The legacy global permission to install outside the store. Superseded " +
            "by per-app grants on modern Android, so its presence on a recent " +
            "build is itself notable.",
    },
    {
        id: "setting.development_settings_enabled",
        key: "development_settings_enabled",
        expected: "0",
        level: "low",
        finding: "Developer options are enabled",
        rationale:
            "A precondition for adb access and for several settings above. Ordinary " +
            "on an examined or developer-owned device, and recorded for context " +
            "rather than as a weakness in itself.",
    },
    {
        id: "setting.adb_enabled",
        key: "adb_enabled",
        expected: "0",
        level: "informational",
        finding: "USB debugging is enabled",
        rationale:
            "Necessarily true during this acquisition, so it is reported for " +
            "completeness. It is only meaningful if the examiner did not enable it.",
    },
];

/** Rules exposed for the report's rule-set provenance. */
export const SETTING_RULE_LIST: readonly Rule[] = SETTING_RULES;

export interface SettingsFinding {
    readonly rule: SettingRule;
    readonly namespace: string;
    readonly value: string;
}

/**
 * Evaluates parsed settings against the rule table.
 *
 * Only keys actually present are considered. An absent key is not a finding: on
 * many builds the default is safe and the row simply does not exist, so treating
 * absence as a violation would produce a false positive on every device that
 * never changed the setting.
 */
export function evaluateSettings(
    namespaces: ReadonlyMap<string, ReadonlyMap<string, string>>,
): readonly SettingsFinding[] {
    const findings: SettingsFinding[] = [];

    for (const [namespace, settings] of namespaces) {
        for (const rule of SETTING_RULES) {
            const raw = settings.get(rule.key);
            if (raw === undefined) {
                continue;
            }
            const value = normalise(raw);
            // An explicit `null` means the platform default applies, which is
            // indistinguishable from the key being absent. Firing on it would
            // report a weakness on any device that merely has the row present.
            if (value === undefined) {
                continue;
            }
            if (value !== rule.expected) {
                findings.push({ rule, namespace, value: raw });
            }
        }
    }

    return findings;
}

/**
 * Normalises a setting value for comparison, or `undefined` when it is unset.
 *
 * Values are strings on the wire and OEMs write booleans inconsistently, so
 * `true`/`false` are folded onto `1`/`0`.
 */
function normalise(value: string): string | undefined {
    const trimmed = value.trim().toLowerCase();
    if (trimmed === "" || trimmed === "null") {
        return undefined;
    }
    if (trimmed === "true") {
        return "1";
    }
    if (trimmed === "false") {
        return "0";
    }
    return trimmed;
}

export function levelOf(rule: SettingRule): AlertLevel {
    return rule.level;
}
