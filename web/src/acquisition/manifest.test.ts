import { describe, expect, it } from "vitest";

import { parseGetProp } from "./device-context.js";
import { CommandLog } from "./command-log.js";
import { buildHashesCsv, HASHES_FILENAME, planArchive } from "../evidence/package-zip.js";
import type { ArtifactRecord } from "../evidence/store.js";

function record(name: string, sha256: string, size = 10): ArtifactRecord {
    return {
        name,
        sha256,
        size,
        acquiredAt: "2026-08-31T01:22:31.000Z",
        verified: true,
    };
}

describe("parseGetProp", () => {
    it("parses standard key/value lines", () => {
        const output = ["[ro.product.model]: [Pixel 9 Pro]", "[ro.build.version.sdk]: [36]"].join(
            "\n",
        );

        const properties = parseGetProp(output);

        expect(properties.get("ro.product.model")).toBe("Pixel 9 Pro");
        expect(properties.get("ro.build.version.sdk")).toBe("36");
    });

    it("preserves values containing brackets and colons", () => {
        const output = "[ro.build.fingerprint]: [google/caiman/caiman:16/BP41.250:user/release-keys]";

        expect(parseGetProp(output).get("ro.build.fingerprint")).toBe(
            "google/caiman/caiman:16/BP41.250:user/release-keys",
        );
    });

    it("handles empty values", () => {
        expect(parseGetProp("[persist.sys.timezone]: []").get("persist.sys.timezone")).toBe("");
    });

    it("ignores malformed lines", () => {
        const properties = parseGetProp("garbage\n[ro.x]: [1]\nmore garbage");

        expect(properties.size).toBe(1);
        expect(properties.get("ro.x")).toBe("1");
    });
});

describe("buildHashesCsv", () => {
    it("emits the AndroidQF header and quoted paths", () => {
        const csv = buildHashesCsv([
            record("getprop.txt", "c68"),
            record("security/appops.txt", "72d"),
        ]);

        expect(csv).toBe('SHA256,FILE\nc68,"getprop.txt"\n72d,"security/appops.txt"\n');
    });

    it("never hashes itself", () => {
        const csv = buildHashesCsv([
            record("getprop.txt", "c68"),
            record(HASHES_FILENAME, "deadbeef"),
        ]);

        expect(csv).not.toContain("deadbeef");
        expect(csv).not.toContain(HASHES_FILENAME);
    });

    it("escapes embedded quotes per RFC 4180", () => {
        const csv = buildHashesCsv([record('weird"name.txt', "aaa")]);

        expect(csv).toContain('aaa,"weird""name.txt"');
    });
});

describe("planArchive", () => {
    it("places hashes.csv last and excludes it from the entry list", () => {
        const plan = planArchive("AQ-1", [
            record("getprop.txt", "a"),
            record("acquisition.json", "b"),
            record(HASHES_FILENAME, "c"),
        ]);

        expect(plan.entries.map((entry) => entry.name)).toEqual([
            "getprop.txt",
            "acquisition.json",
        ]);
        expect(plan.hashesCsv).toContain('a,"getprop.txt"');
        expect(plan.hashesCsv).toContain('b,"acquisition.json"');
        expect(plan.filename).toBe("AQ-1.zip");
    });

    it("sums only archived entries", () => {
        const plan = planArchive("AQ-2", [
            record("a.txt", "a", 100),
            record("b.txt", "b", 250),
        ]);

        expect(plan.totalBytes).toBe(350);
    });
});

describe("CommandLog", () => {
    it("records failures as visibly as successes", () => {
        const log = new CommandLog();

        log.append({
            module: "system-logs",
            command: ["cat", "/proc/kmsg"],
            startedAt: "2026-08-31T01:22:35.223Z",
            completedAt: "2026-08-31T01:22:35.418Z",
            durationMs: 195,
            deviceTime: undefined,
            exitCode: 1,
            protocol: "shell-v2",
            bytes: 0,
            artifact: undefined,
            sha256: undefined,
            stderr: "cat: /proc/kmsg: Permission denied",
            error: "Command reported failure",
        });

        const rendered = log.render();

        expect(rendered).toContain("START [system-logs] cat /proc/kmsg");
        expect(rendered).toContain("EXIT 1");
        expect(rendered).toContain("STDERR cat: /proc/kmsg: Permission denied");
        expect(rendered).toContain("ERROR Command reported failure");
    });

    it("marks a missing exit code rather than implying success", () => {
        const log = new CommandLog();

        log.append({
            module: "getprop",
            command: ["getprop"],
            startedAt: "2026-08-31T01:22:35.223Z",
            completedAt: "2026-08-31T01:22:35.418Z",
            durationMs: 195,
            deviceTime: undefined,
            exitCode: undefined,
            protocol: "none",
            bytes: 1024,
            artifact: "getprop.txt",
            sha256: "abc123",
            stderr: "",
            error: undefined,
        });

        const rendered = log.render();

        expect(rendered).toContain("EXIT unknown (none-protocol)");
        expect(rendered).toContain("SHA256 abc123");
    });

    it("numbers entries sequentially", () => {
        const log = new CommandLog();
        const base = {
            module: "m",
            command: ["true"],
            startedAt: "2026-08-31T01:00:00.000Z",
            completedAt: "2026-08-31T01:00:00.100Z",
            durationMs: 100,
            deviceTime: undefined,
            exitCode: 0,
            protocol: "shell-v2" as const,
            bytes: 0,
            artifact: undefined,
            sha256: undefined,
            stderr: "",
            error: undefined,
        };

        log.append(base);
        log.append(base);

        expect(log.entries.map((entry) => entry.sequence)).toEqual([1, 2]);
    });
});
