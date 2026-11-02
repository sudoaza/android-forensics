import { describe, expect, it } from "vitest";

import {
    apkArtifactName,
    isSystemPath,
    parsePackageList,
    parsePackagePaths,
} from "./package-list.js";

describe("parsePackageList", () => {
    it("keeps APK paths that contain '=' intact", () => {
        // Modern Android generates base64-ish directory names containing '=',
        // so splitting on the FIRST '=' truncates the path. This is the
        // regression this parser exists to prevent.
        const output =
            "package:/data/app/~~kPq3vA==/com.example.app-Xy9Zb2c3d4==/base.apk=com.example.app uid:10352";

        const [entry] = parsePackageList(output);

        expect(entry?.apkPath).toBe(
            "/data/app/~~kPq3vA==/com.example.app-Xy9Zb2c3d4==/base.apk",
        );
        expect(entry?.name).toBe("com.example.app");
        expect(entry?.uid).toBe(10352);
    });

    it("parses installer and uid together", () => {
        const output =
            "package:/data/app/com.foo-1/base.apk=com.foo installer=com.android.vending uid:10123";

        const [entry] = parsePackageList(output);

        expect(entry).toEqual({
            name: "com.foo",
            apkPath: "/data/app/com.foo-1/base.apk",
            uid: 10123,
            installer: "com.android.vending",
        });
    });

    it("treats a null installer as absent", () => {
        const output = "package:/system/app/Foo/Foo.apk=com.foo installer=null uid:10001";

        const [entry] = parsePackageList(output);

        expect(entry?.installer).toBeUndefined();
    });

    it("handles output without -f (no path)", () => {
        const output = "package:com.foo\npackage:com.bar";

        const entries = parsePackageList(output);

        expect(entries).toHaveLength(2);
        expect(entries[0]).toEqual({
            name: "com.foo",
            apkPath: undefined,
            uid: undefined,
            installer: undefined,
        });
    });

    it("ignores non-package lines and blank input", () => {
        const output = "\nWARNING: linker: something\npackage:com.foo uid:10002\n\n";

        const entries = parsePackageList(output);

        expect(entries).toHaveLength(1);
        expect(entries[0]?.name).toBe("com.foo");
    });

    it("parses a mixed realistic listing", () => {
        const output = [
            "package:/system/priv-app/Settings/Settings.apk=com.android.settings uid:1000",
            "package:/data/app/~~aB==/com.spy.app-cD==/base.apk=com.spy.app installer=null uid:10412",
            "package:/data/app/~~aB==/com.spy.app-cD==/split_config.arm64_v8a.apk=com.spy.app uid:10412",
        ].join("\n");

        const entries = parsePackageList(output);

        expect(entries.map((entry) => entry.name)).toEqual([
            "com.android.settings",
            "com.spy.app",
            "com.spy.app",
        ]);
        expect(entries[2]?.apkPath).toContain("split_config.arm64_v8a.apk");
    });
});

describe("parsePackagePaths", () => {
    it("returns base and split APKs", () => {
        const output = [
            "package:/data/app/~~x==/com.foo-y==/base.apk",
            "package:/data/app/~~x==/com.foo-y==/split_config.arm64_v8a.apk",
            "package:/data/app/~~x==/com.foo-y==/split_config.xxhdpi.apk",
        ].join("\n");

        expect(parsePackagePaths(output)).toHaveLength(3);
    });

    it("ignores unrelated output", () => {
        expect(parsePackagePaths("Failure [not installed]")).toEqual([]);
    });
});

describe("apkArtifactName", () => {
    it("names base APKs after the package", () => {
        expect(apkArtifactName("com.foo", "/data/app/~~x==/com.foo-y==/base.apk")).toBe(
            "apks/com.foo.apk",
        );
    });

    it("gives splits distinct names so they cannot overwrite each other", () => {
        const base = apkArtifactName("com.foo", "/data/app/x/base.apk");
        const split = apkArtifactName("com.foo", "/data/app/x/split_config.arm64_v8a.apk");

        expect(split).toBe("apks/com.foo_split_config.arm64_v8a.apk");
        expect(split).not.toBe(base);
    });

    it("sanitizes names that are unsafe as paths", () => {
        expect(apkArtifactName("com/foo bar", "/data/app/x/base.apk")).toBe(
            "apks/com_foo_bar.apk",
        );
    });
});

describe("isSystemPath", () => {
    it("recognizes read-only system partitions", () => {
        expect(isSystemPath("/system/app/Foo/Foo.apk")).toBe(true);
        expect(isSystemPath("/apex/com.android.foo/javalib.apk")).toBe(true);
        expect(isSystemPath("/product/app/Bar/Bar.apk")).toBe(true);
    });

    it("treats /data as third-party", () => {
        expect(isSystemPath("/data/app/~~x==/com.foo-y==/base.apk")).toBe(false);
        expect(isSystemPath(undefined)).toBe(false);
    });
});
