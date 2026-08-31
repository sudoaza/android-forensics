import { describe, expect, it } from "vitest";

import { ResultBuilder } from "../acquisition/artifact.js";
import { rootIndicatorsModule } from "./root.js";
import type { AcquisitionContext } from "../acquisition/artifact.js";
import type { CommandResult } from "../adb/client.js";

/**
 * Regression tests derived from a real acquisition (Redmi Note 9 Pro, Android
 * 12), where this module reported 26 "errors" on a device that was simply not
 * rooted. Absence of a root binary is the expected negative result, so it must
 * be recorded as a finding rather than a collection failure.
 */

interface FakeCommand {
    readonly stdout?: string;
    readonly stderr?: string;
    readonly exitCode?: number;
}

/**
 * Builds a context whose `run` honours the `tolerateFailure` contract the engine
 * implements: throw on non-zero exit unless the caller opted out.
 */
function fakeContext(responses: Record<string, FakeCommand>): {
    ctx: AcquisitionContext;
    written: Map<string, string>;
} {
    const written = new Map<string, string>();

    const ctx = {
        device: {
            capabilities: { pm: true },
            properties: new Map<string, string>([["ro.build.tags", "release-keys"]]),
            verifiedBootState: "green",
            bootloaderLocked: true,
            selinux: "Enforcing",
            shellUser: "shell",
            isRootShell: false,
        },
        signal: new AbortController().signal,
        progress: () => undefined,

        async run(
            command: readonly string[],
            options?: { tolerateFailure?: boolean },
        ): Promise<CommandResult> {
            const key = command.join(" ");
            const response = responses[key] ?? { exitCode: 1, stderr: "" };
            const result = {
                command: [...command],
                stdout: response.stdout ?? "",
                stderr: response.stderr ?? "",
                exitCode: response.exitCode ?? 0,
                protocol: "shell_v2",
            } as unknown as CommandResult;

            if (result.exitCode !== 0 && options?.tolerateFailure !== true) {
                throw new Error(`Command failed (exit ${String(result.exitCode)}): ${key}`);
            }
            return result;
        },

        async writeText(name: string, text: string) {
            written.set(name, text);
            return { name, sha256: "0".repeat(64), size: text.length, acquiredAt: "", verified: true };
        },
    } as unknown as AcquisitionContext;

    return { ctx, written };
}

describe("rootIndicatorsModule", () => {
    it("reports a clean device as complete, with absence recorded as a finding", async () => {
        // Every probe fails the way a stock device fails: `which` exits 1 with no
        // output, and `ls` exits 1 with a reason.
        const { ctx, written } = fakeContext({
            "pm list packages": { stdout: "package:com.android.settings\n" },
        });

        const result = await rootIndicatorsModule.run(ctx);

        expect(result.errors).toEqual([]);
        expect(result.status).toBe("complete");

        const report = JSON.parse(written.get("root_binaries.json") ?? "{}");
        expect(report.binaries).toEqual([]);
        expect(report.summary.root_binaries_found).toBe(0);
        expect(report.summary.suspicious_paths_present).toBe(0);
        expect(report.root_management_packages).toEqual([]);
    });

    it("records a present binary and a root manager package", async () => {
        const { ctx, written } = fakeContext({
            "which -a su": { stdout: "/system/xbin/su\n", exitCode: 0 },
            "ls -ld /system/xbin/su": { stdout: "-rwsr-xr-x 1 root root 1234 su\n", exitCode: 0 },
            "pm list packages": { stdout: "package:com.topjohnwu.magisk\n", exitCode: 0 },
        });

        const result = await rootIndicatorsModule.run(ctx);
        const report = JSON.parse(written.get("root_binaries.json") ?? "{}");

        expect(report.binaries).toEqual([{ name: "su", paths: ["/system/xbin/su"] }]);
        expect(report.root_management_packages).toEqual(["com.topjohnwu.magisk"]);

        const suPath = report.paths.find((entry: { path: string }) => entry.path === "/system/xbin/su");
        expect(suPath.present).toBe(true);
        expect(result.status).toBe("complete");
    });

    it("distinguishes a denied path from a missing one", async () => {
        // The real device refused /data/adb/magisk. Presence is then unknown, and
        // must not be recorded as absent.
        const { ctx, written } = fakeContext({
            "ls -ld /data/adb/magisk": {
                stderr: "ls: /data/adb/magisk: Permission denied\n",
                exitCode: 1,
            },
            "pm list packages": { stdout: "", exitCode: 0 },
        });

        await rootIndicatorsModule.run(ctx);
        const report = JSON.parse(written.get("root_binaries.json") ?? "{}");

        const denied = report.paths.find((e: { path: string }) => e.path === "/data/adb/magisk");
        expect(denied.present).toBe(false);
        expect(denied.indeterminate).toBe(true);

        const missing = report.paths.find((e: { path: string }) => e.path === "/sbin/su");
        expect(missing.present).toBe(false);
        expect(missing.indeterminate).toBe(false);

        expect(report.summary.paths_indeterminate).toBe(1);
    });

    it("still reports a genuine transport failure as an error", async () => {
        const { ctx } = fakeContext({});
        const failing = {
            ...ctx,
            run: async () => {
                throw new Error("Transport closed");
            },
        } as unknown as AcquisitionContext;

        const result = await rootIndicatorsModule.run(failing);
        expect(result.errors.length).toBeGreaterThan(0);
        expect(result.errors.every((entry) => entry.expected)).toBe(false);
    });
});

describe("ResultBuilder", () => {
    it("honours an explicit expected flag for optional probes", () => {
        const builder = new ResultBuilder();
        builder.artifact("logcat.txt");
        // "Logcat read failure" matches no refusal pattern, so without the
        // explicit flag an absent prior-boot buffer counts as unexpected.
        builder.error("logcat -L", new Error("Logcat read failure: No such file"), true);

        const result = builder.build();
        expect(result.status).toBe("partial");
        expect(result.errors[0]?.expected).toBe(true);
    });
});
