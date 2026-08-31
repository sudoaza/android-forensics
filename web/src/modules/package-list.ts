/**
 * Parser for `pm list packages -U -f -i` output.
 *
 * The format is genuinely awkward. A line looks like:
 *
 *   package:/data/app/~~a==/com.example-b==/base.apk=com.example uid:10352
 *   package:/system/priv-app/Foo/Foo.apk=com.foo installer=com.android.vending uid:10123
 *
 * The APK path and the package name are joined by `=`, but paths themselves can
 * contain `=` (the base64-ish directory names Android generates). So the
 * separator must be found from the RIGHT, and only after the trailing
 * `installer=` and `uid:` fields have been removed. Splitting on the first `=`,
 * which is the obvious implementation, silently truncates paths on any modern
 * Android build.
 *
 * Field order is not guaranteed across versions either, so trailing fields are
 * matched by name instead of position.
 */

export interface PackageListEntry {
    readonly name: string;
    readonly apkPath: string | undefined;
    readonly uid: number | undefined;
    readonly installer: string | undefined;
}

const UID_PATTERN = /\s+uid:(\d+)\s*$/;
const INSTALLER_PATTERN = /\s+installer=(\S*)\s*$/;

export function parsePackageList(output: string): PackageListEntry[] {
    const entries: PackageListEntry[] = [];

    for (const rawLine of output.split("\n")) {
        const line = rawLine.trim();
        if (!line.startsWith("package:")) {
            continue;
        }

        let remainder = line.slice("package:".length);

        // Strip trailing fields, in the order they appear, right to left.
        let uid: number | undefined;
        const uidMatch = UID_PATTERN.exec(remainder);
        if (uidMatch?.[1] !== undefined) {
            uid = Number.parseInt(uidMatch[1], 10);
            remainder = remainder.slice(0, uidMatch.index);
        }

        let installer: string | undefined;
        const installerMatch = INSTALLER_PATTERN.exec(remainder);
        if (installerMatch?.[1] !== undefined) {
            // `-i` prints "installer=null" when the package has no recorded installer.
            installer =
                installerMatch[1] === "null" || installerMatch[1] === ""
                    ? undefined
                    : installerMatch[1];
            remainder = remainder.slice(0, installerMatch.index);
        }

        remainder = remainder.trim();

        // What remains is either "path=name" (with -f) or just "name".
        let name: string;
        let apkPath: string | undefined;

        if (remainder.startsWith("/")) {
            // Rightmost `=` separates path from package name, because the path
            // may itself contain `=` but a package name never does.
            const separator = remainder.lastIndexOf("=");
            if (separator === -1) {
                apkPath = remainder;
                name = "";
            } else {
                apkPath = remainder.slice(0, separator);
                name = remainder.slice(separator + 1);
            }
        } else {
            name = remainder;
        }

        name = name.trim();
        if (name.length === 0) {
            continue;
        }

        entries.push({
            name,
            apkPath: apkPath === undefined || apkPath.length === 0 ? undefined : apkPath,
            uid: uid !== undefined && Number.isFinite(uid) ? uid : undefined,
            installer,
        });
    }

    return entries;
}

/** Parses `pm path <package>`, which prints one `package:<path>` line per split. */
export function parsePackagePaths(output: string): string[] {
    return output
        .split("\n")
        .map((line) => line.trim())
        .filter((line) => line.startsWith("package:"))
        .map((line) => line.slice("package:".length).trim())
        .filter((line) => line.length > 0);
}

/**
 * A package is treated as system when its APK lives on a read-only system
 * partition. Checked by path because `pm list packages -s` requires a second
 * device round trip and disagrees with the path for updated system apps.
 */
const SYSTEM_PATH_PREFIXES = [
    "/system/",
    "/system_ext/",
    "/vendor/",
    "/product/",
    "/apex/",
    "/odm/",
    "/oem/",
] as const;

export function isSystemPath(apkPath: string | undefined): boolean {
    if (apkPath === undefined) {
        return false;
    }
    return SYSTEM_PATH_PREFIXES.some((prefix) => apkPath.startsWith(prefix));
}

/**
 * Builds a filesystem-safe archive name for a pulled APK.
 *
 * Split APKs share a package name, so the split's own filename is appended;
 * without it, splits overwrite each other and `hashes.csv` ends up describing
 * only the last one.
 */
export function apkArtifactName(packageName: string, apkPath: string): string {
    const basename = apkPath.split("/").pop() ?? "base.apk";
    const safePackage = packageName.replaceAll(/[^A-Za-z0-9._-]/g, "_");

    if (basename === "base.apk") {
        return `apks/${safePackage}.apk`;
    }

    const safeSplit = basename.replace(/\.apk$/, "").replaceAll(/[^A-Za-z0-9._-]/g, "_");
    return `apks/${safePackage}_${safeSplit}.apk`;
}
