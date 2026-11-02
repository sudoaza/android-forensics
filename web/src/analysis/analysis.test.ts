import { makeZip } from "client-zip";
import { describe, expect, it } from "vitest";

import { hashText } from "../evidence/hasher.js";
import { defaultAnalyzers } from "./analyzers/index.js";
import { extractEndpoints } from "./analyzers/network.js";
import { parseProcesses } from "./analyzers/processes.js";
import { AnalysisEngine } from "./engine.js";
import { describeIndicatorSources } from "./indicators/library.js";
import { IndicatorLibrary } from "./indicators/matcher.js";
import { parseStix2Bundle } from "./indicators/stix2.js";
import { buildAlertsCsv, buildAnalysisReport, buildTimelineCsv } from "./report.js";
import { ZipSource, parseHashesCsv } from "./source.js";

/**
 * End-to-end analysis over a synthetic archive.
 *
 * The archive is built to contain specific known-bad values, and the assertions
 * name the rules expected to fire. This is the regression test that matters: a
 * rule silently ceasing to fire is the failure mode that would let this tool
 * report a compromised device as clean, and it is invisible to a typecheck.
 *
 * The fixtures are written here rather than taken from MVT's test data, so they
 * exercise our own artifact shapes and wording.
 */

const ACQUISITION = "AQ-20260901-120000-abcd";

interface Fixture {
    readonly name: string;
    readonly content: string;
}

/** A device with several deliberate problems. */
const COMPROMISED: readonly Fixture[] = [
    {
        name: "getprop.txt",
        content: [
            "[ro.build.version.release]: [13]",
            "[ro.build.version.sdk]: [33]",
            "[ro.build.version.security_patch]: [2024-01-05]",
            "[ro.build.tags]: [test-keys]",
            "[ro.build.type]: [userdebug]",
            "[ro.debuggable]: [1]",
            "[ro.boot.verifiedbootstate]: [orange]",
            "[ro.boot.flash.locked]: [0]",
            "[ro.boot.veritymode]: [disabled]",
            "[ro.product.model]: [Test Device]",
            "[persist.sys.malware.flag]: [1]",
        ].join("\n"),
    },
    { name: "security/selinux.txt", content: "Permissive\n" },
    {
        name: "security/proc_mounts.txt",
        content: [
            "/dev/block/dm-0 / ext4 ro,seclabel,relatime 0 0",
            "/dev/block/dm-1 /system ext4 rw,seclabel,relatime 0 0",
            "/dev/block/dm-2 /vendor ext4 ro,seclabel,relatime 0 0",
            "tmpfs /dev/shm tmpfs rw,seclabel,relatime 0 0",
        ].join("\n"),
    },
    {
        name: "settings_global.txt",
        content: [
            "package_verifier_enable=0",
            "verifier_verify_adb_installs=0",
            "adb_enabled=1",
            "development_settings_enabled=1",
            "some_unrelated_setting=42",
        ].join("\n"),
    },
    {
        name: "settings_secure.txt",
        content: ["accessibility_enabled=1", "install_non_market_apps=1"].join("\n"),
    },
    {
        name: "root_binaries.json",
        content: JSON.stringify({
            binaries: [{ name: "su", paths: ["/system/xbin/su"] }],
            paths: [
                { path: "/data/adb/magisk", present: true, indeterminate: false, detail: "drwx" },
                { path: "/sbin/.magisk", present: false, indeterminate: true, detail: "denied" },
                { path: "/cache/magisk.log", present: false, indeterminate: false, detail: "" },
            ],
            root_management_packages: ["com.topjohnwu.magisk"],
            summary: { shell_is_root: true },
        }),
    },
    {
        name: "packages.json",
        content: JSON.stringify([
            {
                name: "com.topjohnwu.magisk",
                system: false,
                installer: null,
                disabled: false,
                files: [{ path: "/data/app/magisk.apk", sha256: "a".repeat(64) }],
            },
            {
                name: "com.example.spyware",
                system: false,
                installer: null,
                disabled: false,
                files: [{ path: "/data/app/spy.apk", sha256: "b".repeat(64) }],
            },
            {
                name: "com.example.sideloaded",
                system: false,
                installer: "com.android.packageinstaller",
                disabled: false,
                files: [{ path: "/data/app/side.apk", sha256: "c".repeat(64) }],
            },
            {
                name: "com.samsung.android.securitylogagent",
                system: true,
                installer: null,
                disabled: true,
                files: [],
            },
            {
                name: "com.android.chrome",
                system: false,
                installer: "com.android.vending",
                disabled: false,
                files: [{ path: "/data/app/chrome.apk", sha256: "d".repeat(64) }],
            },
        ]),
    },
];

/** A device with none of the above problems. */
const CLEAN: readonly Fixture[] = [
    {
        name: "getprop.txt",
        content: [
            "[ro.build.version.release]: [15]",
            `[ro.build.version.security_patch]: [${recentPatchDate()}]`,
            "[ro.build.tags]: [release-keys]",
            "[ro.build.type]: [user]",
            "[ro.debuggable]: [0]",
            "[ro.boot.verifiedbootstate]: [green]",
            "[ro.boot.flash.locked]: [1]",
            "[ro.boot.veritymode]: [enforcing]",
        ].join("\n"),
    },
    { name: "security/selinux.txt", content: "Enforcing\n" },
    {
        name: "security/proc_mounts.txt",
        content: "/dev/block/dm-1 /system ext4 ro,seclabel,relatime 0 0",
    },
    {
        name: "settings_global.txt",
        content: ["package_verifier_enable=1", "verifier_verify_adb_installs=1"].join("\n"),
    },
    { name: "settings_secure.txt", content: "accessibility_enabled=0" },
    {
        name: "root_binaries.json",
        content: JSON.stringify({
            binaries: [],
            paths: [{ path: "/system/xbin/su", present: false, indeterminate: false, detail: "" }],
            root_management_packages: [],
            summary: { shell_is_root: false },
        }),
    },
    {
        name: "packages.json",
        content: JSON.stringify([
            {
                name: "com.android.chrome",
                system: false,
                installer: "com.android.vending",
                disabled: false,
                files: [{ path: "/data/app/chrome.apk", sha256: "d".repeat(64) }],
            },
        ]),
    },
];

function recentPatchDate(): string {
    const date = new Date();
    date.setUTCDate(date.getUTCDate() - 20);
    return date.toISOString().slice(0, 10);
}

/**
 * Builds an archive nested under an acquisition directory, with a `hashes.csv`
 * covering every entry — the layout the exporter produces.
 */
async function buildArchive(fixtures: readonly Fixture[]): Promise<Blob> {
    const hashLines = ["SHA256,FILE"];
    for (const fixture of fixtures) {
        hashLines.push(`${hashText(fixture.content)},"${fixture.name}"`);
    }
    const hashesCsv = `${hashLines.join("\n")}\n`;

    const entries = [
        ...fixtures.map((fixture) => ({
            name: `${ACQUISITION}/${fixture.name}`,
            input: fixture.content,
            lastModified: new Date("2026-09-01T12:00:00Z"),
        })),
        {
            name: `${ACQUISITION}/hashes.csv`,
            input: hashesCsv,
            lastModified: new Date("2026-09-01T12:00:00Z"),
        },
    ];

    return new Response(makeZip(entries) as ReadableStream<Uint8Array>).blob();
}

async function analyse(fixtures: readonly Fixture[]) {
    const source = await ZipSource.open(await buildArchive(fixtures), `${ACQUISITION}.zip`);
    const analyzers = defaultAnalyzers();
    const engine = new AnalysisEngine({ source, analyzers });
    const outcome = await engine.run();
    return { source, analyzers, outcome };
}

/** Rule ids that fired, for concise assertions. */
function firedRules(alerts: readonly { ruleId: string | undefined }[]): Set<string> {
    return new Set(
        alerts
            .map((alert) => alert.ruleId)
            .filter((ruleId): ruleId is string => ruleId !== undefined),
    );
}

describe("analysis of a compromised device", () => {
    it("identifies boot and build integrity problems", async () => {
        const { outcome } = await analyse(COMPROMISED);
        const fired = firedRules(outcome.alerts.alerts);

        expect(fired).toContain("boot.verified_boot_not_green");
        expect(fired).toContain("boot.bootloader_unlocked");
        expect(fired).toContain("boot.dm_verity_disabled");
        expect(fired).toContain("boot.selinux_permissive");
        expect(fired).toContain("build.debuggable");
        expect(fired).toContain("build.test_keys");
        expect(fired).toContain("build.userdebug");
        expect(fired).toContain("build.security_patch_stale");
    });

    it("identifies disabled platform protections", async () => {
        const { outcome } = await analyse(COMPROMISED);
        const fired = firedRules(outcome.alerts.alerts);

        expect(fired).toContain("setting.package_verifier_enable");
        expect(fired).toContain("setting.verifier_verify_adb_installs");
        expect(fired).toContain("setting.accessibility_enabled");
        expect(fired).toContain("setting.install_non_market_apps");
    });

    it("identifies root indicators and separates inconclusive probes", async () => {
        const { outcome } = await analyse(COMPROMISED);
        const fired = firedRules(outcome.alerts.alerts);

        expect(fired).toContain("root.binary_present");
        expect(fired).toContain("root.path_present");
        expect(fired).toContain("root.adb_shell_is_root");
        expect(fired).toContain("mount.system_writable");

        // The refused check must be reported as unknown, never folded into the
        // negative results.
        expect(fired).toContain("root.probe_indeterminate");
        const indeterminate = outcome.alerts.alerts.find(
            (alert) => alert.ruleId === "root.probe_indeterminate",
        );
        expect(indeterminate?.evidence["indeterminate_count"]).toBe(1);
        expect(indeterminate?.level).toBe("informational");
    });

    it("does not report a path that was confirmed absent", async () => {
        const { outcome } = await analyse(COMPROMISED);
        const paths = outcome.alerts.alerts
            .filter((alert) => alert.ruleId === "root.path_present")
            .map((alert) => alert.evidence["path"]);

        expect(paths).toContain("/data/adb/magisk");
        expect(paths).not.toContain("/cache/magisk.log");
        // Denied, therefore unknown: it must not appear as a positive finding.
        expect(paths).not.toContain("/sbin/.magisk");
    });

    it("classifies install provenance and disabled security components", async () => {
        const { outcome } = await analyse(COMPROMISED);
        const fired = firedRules(outcome.alerts.alerts);

        expect(fired).toContain("package.root_management");
        expect(fired).toContain("package.sideloaded_no_installer");
        expect(fired).toContain("package.installed_from_file");
        expect(fired).toContain("package.security_component_disabled");
    });

    it("does not flag a store-installed package", async () => {
        const { outcome } = await analyse(COMPROMISED);
        const chromeAlerts = outcome.alerts.alerts.filter(
            (alert) => alert.evidence["package"] === "com.android.chrome",
        );
        expect(chromeAlerts).toEqual([]);
    });

    it("reports the sideloaded package by name", async () => {
        const { outcome } = await analyse(COMPROMISED);
        const sideloaded = outcome.alerts.alerts
            .filter((alert) => alert.ruleId === "package.sideloaded_no_installer")
            .map((alert) => alert.evidence["package"]);

        expect(sideloaded).toContain("com.example.spyware");
    });
});

describe("analysis of a clean device", () => {
    it("produces no findings above informational", async () => {
        const { outcome } = await analyse(CLEAN);
        const significant = outcome.alerts.alerts.filter(
            (alert) => alert.level !== "informational",
        );
        expect(significant.map((alert) => alert.ruleId)).toEqual([]);
    });

    it("still records which analyzers ran, so silence is attributable", async () => {
        const { outcome } = await analyse(CLEAN);
        const statuses = new Map(outcome.reports.map((report) => [report.id, report.status]));

        expect(statuses.get("getprop")).toBe("complete");
        expect(statuses.get("settings")).toBe("complete");
        expect(statuses.get("packages")).toBe("complete");
        expect(statuses.get("root")).toBe("complete");
    });
});

describe("analyzer isolation and applicability", () => {
    it("reports not-applicable rather than clean when an artifact is absent", async () => {
        // A Quick-profile archive has no dumpsys; "we did not look" must never be
        // recorded the same way as "we looked and found nothing".
        const { outcome } = await analyse([
            { name: "getprop.txt", content: "[ro.build.type]: [user]" },
        ]);
        const statuses = new Map(outcome.reports.map((report) => [report.id, report.status]));

        expect(statuses.get("packages")).toBe("not-applicable");
        expect(statuses.get("settings")).toBe("not-applicable");
        expect(statuses.get("getprop")).toBe("complete");
    });

    it("records a parse failure without losing other analyzers' findings", async () => {
        const { outcome } = await analyse([
            { name: "packages.json", content: "{ not valid json" },
            { name: "settings_global.txt", content: "package_verifier_enable=0" },
        ]);

        const packages = outcome.reports.find((report) => report.id === "packages");
        expect(packages?.status).toBe("failed");
        expect(packages?.problems.length).toBeGreaterThan(0);

        // The settings finding must survive the packages failure.
        expect(firedRules(outcome.alerts.alerts)).toContain("setting.package_verifier_enable");
    });

    it("distinguishes an unparseable artifact from a clean one", async () => {
        // Both produce zero alerts. If the engine derived status from alert count
        // alone, a broken parser would be reported exactly like a clean device —
        // the most dangerous failure mode this tool has.
        const unparseable = await analyse([
            { name: "packages.json", content: "{ not valid json" },
        ]);
        const clean = await analyse([
            {
                name: "packages.json",
                content: JSON.stringify([
                    {
                        name: "com.android.chrome",
                        system: false,
                        installer: "com.android.vending",
                        disabled: false,
                        files: [],
                    },
                ]),
            },
        ]);

        const brokenReport = unparseable.outcome.reports.find(
            (report) => report.id === "packages",
        );
        const cleanReport = clean.outcome.reports.find((report) => report.id === "packages");

        expect(brokenReport?.alertCount).toBe(0);
        expect(cleanReport?.alertCount).toBe(0);

        expect(brokenReport?.status).toBe("failed");
        expect(brokenReport?.examined).toEqual([]);

        expect(cleanReport?.status).toBe("complete");
        expect(cleanReport?.examined).toHaveLength(1);
    });

    it("reports partial when one of several inputs is unusable", async () => {
        const { outcome } = await analyse([
            { name: "settings_global.txt", content: "package_verifier_enable=0" },
            { name: "settings_secure.txt", content: "" },
        ]);

        const settings = outcome.reports.find((report) => report.id === "settings");
        expect(settings?.status).toBe("partial");
        expect(settings?.examined).toHaveLength(1);
        expect(settings?.problems).toHaveLength(1);
    });
});

describe("archive integrity verification", () => {
    it("verifies an intact archive against its own hashes.csv", async () => {
        const source = await ZipSource.open(await buildArchive(CLEAN));
        const verification = await source.verify();

        expect(verification.status).toBe("verified");
        expect(verification.checked).toBe(CLEAN.length);
        expect(verification.mismatches).toEqual([]);
    });

    it("detects an artifact whose content no longer matches the manifest", async () => {
        // hashes.csv is built from the clean fixtures, then one artifact is
        // substituted: exactly the case where findings would otherwise be derived
        // from content the device never produced.
        const hashLines = ["SHA256,FILE"];
        for (const fixture of CLEAN) {
            hashLines.push(`${hashText(fixture.content)},"${fixture.name}"`);
        }

        const tampered = CLEAN.map((fixture) =>
            fixture.name === "settings_global.txt"
                ? { ...fixture, content: "package_verifier_enable=0" }
                : fixture,
        );

        const blob = await new Response(
            makeZip([
                ...tampered.map((fixture) => ({
                    name: `${ACQUISITION}/${fixture.name}`,
                    input: fixture.content,
                    lastModified: new Date("2026-09-01T12:00:00Z"),
                })),
                {
                    name: `${ACQUISITION}/hashes.csv`,
                    input: `${hashLines.join("\n")}\n`,
                    lastModified: new Date("2026-09-01T12:00:00Z"),
                },
            ]) as ReadableStream<Uint8Array>,
        ).blob();

        const verification = await (await ZipSource.open(blob)).verify();

        expect(verification.status).toBe("failed");
        expect(verification.mismatches.map((mismatch) => mismatch.name)).toEqual([
            "settings_global.txt",
        ]);
    });

    it("distinguishes an unverifiable archive from a failed one", async () => {
        const blob = await new Response(
            makeZip([
                {
                    name: `${ACQUISITION}/getprop.txt`,
                    input: "[ro.build.type]: [user]",
                    lastModified: new Date(),
                },
            ]) as ReadableStream<Uint8Array>,
        ).blob();

        const verification = await (await ZipSource.open(blob)).verify();
        expect(verification.status).toBe("unverifiable");
        expect(verification.reason).toMatch(/no hashes\.csv/i);
    });

    it("parses quoted paths in hashes.csv", () => {
        const parsed = parseHashesCsv(
            ['SHA256,FILE', `${"a".repeat(64)},"security/appops.txt"`].join("\n"),
        );
        expect(parsed.get("security/appops.txt")).toBe("a".repeat(64));
    });
});

describe("ps parsing", () => {
    it("locates columns from the header, whatever the layout", () => {
        const processes = parseProcesses(
            [
                "USER           PID  PPID     VSZ    RSS WCHAN            ADDR S NAME",
                "root             1     0   10804   2668 0                   0 S init",
                "u0_a99        3312   823 5471232 118884 0                   0 S com.android.chrome",
            ].join("\n"),
        );

        expect(processes).toHaveLength(2);
        expect(processes[0]).toEqual({ user: "root", pid: 1, ppid: 0, name: "init" });
        expect(processes[1]?.name).toBe("com.android.chrome");
        expect(processes[1]?.ppid).toBe(823);
    });

    it("takes the executable, not the last argument, under a command-line column", () => {
        // The regression this guards: with `ARGS` last, taking the final field
        // yields "--zygote" and no indicator could ever match.
        const processes = parseProcesses(
            [
                "USER    PID  PPID ARGS",
                "root    823     1 /system/bin/app_process -Xzygote /system/bin --zygote",
            ].join("\n"),
        );

        expect(processes[0]?.name).toBe("/system/bin/app_process");
    });

    it("strips the brackets around kernel threads", () => {
        const processes = parseProcesses(
            ["USER PID PPID NAME", "root 12 2 [kworker/0:1]"].join("\n"),
        );

        expect(processes[0]?.name).toBe("kworker/0:1");
    });

    it("skips headings and blank lines without inventing entries", () => {
        const processes = parseProcesses(
            ["USER PID PPID NAME", "", "root 1 0 init", "   ", "not-a-process-line"].join("\n"),
        );

        expect(processes).toHaveLength(1);
    });

    it("returns nothing for empty output rather than throwing", () => {
        expect(parseProcesses("")).toEqual([]);
        expect(parseProcesses("\n\n")).toEqual([]);
    });
});

describe("indicator matching through the engine", () => {
    /** A bundle flagging values planted in the COMPROMISED fixtures. */
    function indicatorBundle(): string {
        return JSON.stringify({
            type: "bundle",
            id: "bundle--test",
            objects: [
                { type: "malware", id: "malware--1", name: "ExampleSpy", is_family: false },
                {
                    type: "indicator",
                    id: "indicator--1",
                    pattern: "[app:id='com.example.spyware']",
                    pattern_type: "stix",
                },
                {
                    type: "indicator",
                    id: "indicator--2",
                    pattern: `[file:hashes.'SHA-256'='${"b".repeat(64)}']`,
                    pattern_type: "stix",
                },
                {
                    type: "indicator",
                    id: "indicator--3",
                    pattern: "[android-property:name='persist.sys.malware.flag']",
                    pattern_type: "stix",
                },
                {
                    type: "indicator",
                    id: "indicator--4",
                    pattern: "[process:name='com.example.spyware.daemon']",
                    pattern_type: "stix",
                },
                {
                    type: "indicator",
                    id: "indicator--5",
                    pattern: "[domain-name:value='evil.example.com']",
                    pattern_type: "stix",
                },
                ...[1, 2, 3, 4, 5].map((index) => ({
                    type: "relationship",
                    id: `relationship--${index}`,
                    relationship_type: "indicates",
                    source_ref: `indicator--${index}`,
                    target_ref: "malware--1",
                })),
            ],
        });
    }

    async function analyseWithIndicators(fixtures: readonly Fixture[]) {
        const library = new IndicatorLibrary();
        library.add(parseStix2Bundle("test.stix2", indicatorBundle(), "supplied"));

        const source = await ZipSource.open(await buildArchive(fixtures), `${ACQUISITION}.zip`);
        const analyzers = defaultAnalyzers();
        const engine = new AnalysisEngine({ source, analyzers, indicators: library });
        return { library, source, analyzers, outcome: await engine.run() };
    }

    it("reports a flagged package as a critical indicator match", async () => {
        const { outcome } = await analyseWithIndicators(COMPROMISED);
        const matches = outcome.alerts.alerts.filter(
            (alert) => alert.matchedIndicator !== undefined,
        );

        const appId = matches.find((alert) => alert.matchedIndicator?.type === "app_id");
        expect(appId?.level).toBe("critical");
        expect(appId?.matchedIndicator?.collection).toBe("ExampleSpy");
        expect(appId?.matchedIndicator?.source).toBe("test.stix2");
    });

    it("matches an APK by hash even though the APK was not collected", async () => {
        // The whole point of recording per-file SHA-256 during a Quick
        // acquisition: hash triage without transferring gigabytes of APKs.
        const { outcome } = await analyseWithIndicators(COMPROMISED);
        const hashMatch = outcome.alerts.alerts.find(
            (alert) => alert.matchedIndicator?.type === "file_sha256",
        );

        expect(hashMatch?.level).toBe("critical");
        expect(hashMatch?.evidence["sha256"]).toBe("b".repeat(64));
    });

    it("matches a property name left behind by an implant", async () => {
        const { outcome } = await analyseWithIndicators(COMPROMISED);
        const propertyMatch = outcome.alerts.alerts.find(
            (alert) => alert.matchedIndicator?.type === "android_property",
        );

        expect(propertyMatch?.evidence["property"]).toBe("persist.sys.malware.flag");
    });

    it("matches a process whose name the kernel truncated", async () => {
        const { outcome } = await analyseWithIndicators([
            ...COMPROMISED,
            {
                name: "processes.txt",
                content: [
                    "USER           PID  PPID     VSZ    RSS S NAME",
                    "root             1     0   10000   2000 S init",
                    // 15 characters, as the kernel reports it.
                    "u0_a123       4242   823  200000  50000 S com.example.spy",
                ].join("\n"),
            },
        ]);

        const processMatch = outcome.alerts.alerts.find(
            (alert) => alert.analyzer === "processes" && alert.matchedIndicator !== undefined,
        );

        expect(processMatch?.level).toBe("critical");
        expect(processMatch?.message).toMatch(/truncated/);
        expect(processMatch?.evidence["pid"]).toBe(4242);
    });

    it("finds nothing on a clean device even with indicators loaded", async () => {
        const { outcome } = await analyseWithIndicators(CLEAN);
        expect(
            outcome.alerts.alerts.filter((alert) => alert.matchedIndicator !== undefined),
        ).toEqual([]);
    });

    it("matches a flagged domain found in a collected log", async () => {
        // Domains are the bulk of every real indicator set, so this path carries
        // most of the malware-detection value.
        const { outcome } = await analyseWithIndicators([
            ...COMPROMISED,
            {
                name: "logcat.txt",
                content: [
                    "09-01 12:00:00.000 1 1 I Net: GET https://cdn.evil.example.com/beacon",
                    "09-01 12:00:01.000 1 1 I Net: GET https://safe.example.org/ok",
                ].join("\n"),
            },
        ]);

        const match = outcome.alerts.alerts.find((alert) => alert.analyzer === "network");
        expect(match?.level).toBe("critical");
        // Matched via the subdomain walk against the "evil.example.com" indicator.
        expect(match?.evidence["endpoint"]).toBe("cdn.evil.example.com");
        expect(match?.evidence["line"]).toBe(1);
        // The limit of a text match travels with the finding itself.
        expect(String(match?.evidence["caveat"])).toMatch(/does not establish/i);
    });

    it("does not report unflagged hosts from the same log", async () => {
        const { outcome } = await analyseWithIndicators([
            ...CLEAN,
            {
                name: "logcat.txt",
                content: "09-01 12:00:00.000 1 1 I Net: GET https://safe.example.org/ok",
            },
        ]);

        expect(outcome.alerts.alerts.filter((alert) => alert.analyzer === "network")).toEqual([]);
    });

    it("scans network artifacts but records nothing when no indicators are loaded", async () => {
        // Without indicators every hostname is uninteresting, so the analyzer must
        // not manufacture findings from ordinary traffic.
        const source = await ZipSource.open(
            await buildArchive([
                ...CLEAN,
                { name: "logcat.txt", content: "GET https://cdn.evil.example.com/beacon" },
            ]),
            `${ACQUISITION}.zip`,
        );
        const outcome = await new AnalysisEngine({
            source,
            analyzers: defaultAnalyzers(),
        }).run();

        expect(outcome.alerts.alerts.filter((alert) => alert.analyzer === "network")).toEqual([]);
    });

    it("records which bundles were in force, with their hashes", async () => {
        const { library, source, analyzers, outcome } = await analyseWithIndicators(CLEAN);
        const report: unknown = JSON.parse(
            buildAnalysisReport({
                acquisitionId: source.acquisitionId,
                sourceOrigin: source.origin,
                startedAt: outcome.startedAt,
                completedAt: outcome.completedAt,
                cancelled: outcome.cancelled,
                analyzers,
                reports: outcome.reports,
                alerts: outcome.alerts,
                indicatorSources: describeIndicatorSources(library),
                verification: undefined,
            }),
        );

        const indicatorSet = (
            report as {
                indicator_set: {
                    sources: { filename: string; sha256: string; origin: string }[];
                    total_indicators: number;
                    note: string | null;
                };
            }
        ).indicator_set;

        expect(indicatorSet.sources).toHaveLength(1);
        expect(indicatorSet.sources[0]?.filename).toBe("test.stix2");
        expect(indicatorSet.sources[0]?.sha256).toMatch(/^[0-9a-f]{64}$/);
        expect(indicatorSet.sources[0]?.origin).toBe("supplied");
        expect(indicatorSet.total_indicators).toBe(5);
        // With indicators loaded, the "no conclusion possible" caveat is dropped.
        expect(indicatorSet.note).toBeNull();
    });
});

describe("network endpoint extraction", () => {
    it("finds hostnames and addresses with their line and context", () => {
        const endpoints = extractEndpoints(
            [
                "09-01 12:00:00.000  1234  5678 I Test: connecting to evil.example.com now",
                "09-01 12:00:01.000  1234  5678 I Test: resolved to 203.0.113.42",
            ].join("\n"),
        );

        const host = endpoints.find((endpoint) => endpoint.value === "evil.example.com");
        expect(host?.line).toBe(1);
        expect(host?.context).toContain("connecting to");

        expect(endpoints.some((endpoint) => endpoint.value === "203.0.113.42")).toBe(true);
    });

    it("reports a repeated endpoint once, with its first occurrence", () => {
        // A domain appearing tens of thousands of times in a logcat must be one
        // finding, not tens of thousands of alerts.
        const endpoints = extractEndpoints(
            ["first line", "hit evil.example.com", "hit evil.example.com again"].join("\n"),
        );

        const matches = endpoints.filter((e) => e.value === "evil.example.com");
        expect(matches).toHaveLength(1);
        expect(matches[0]?.line).toBe(2);
    });

    it("lowercases hostnames so case cannot hide a match", () => {
        const endpoints = extractEndpoints("Contacting EVIL.Example.COM");
        expect(endpoints.some((endpoint) => endpoint.value === "evil.example.com")).toBe(true);
    });

    it("does not mistake version strings for addresses", () => {
        // The most common false-positive source in real logs.
        const endpoints = extractEndpoints("version 1.2.3.4 build 01.02.03.04 sdk 10.0.0.256");
        const values = endpoints.map((endpoint) => endpoint.value);

        expect(values).not.toContain("01.02.03.04");
        expect(values).not.toContain("10.0.0.256");
    });

    it("skips Android framework class names that look like hostnames", () => {
        const endpoints = extractEndpoints(
            "at android.view.View.performClick(View.java:1) com.google.android.gms.foo",
        );

        expect(endpoints.map((endpoint) => endpoint.value)).not.toContain("android.view.view");
    });

    it("caps the context recorded for very long lines", () => {
        const endpoints = extractEndpoints(`evil.example.com ${"x".repeat(5000)}`);
        expect(endpoints[0]?.context.length).toBeLessThanOrEqual(300);
    });
});

describe("report output", () => {
    it("lists every rule in force, including those that did not fire", async () => {
        const { source, analyzers, outcome } = await analyse(CLEAN);
        const report: unknown = JSON.parse(
            buildAnalysisReport({
                acquisitionId: source.acquisitionId,
                sourceOrigin: source.origin,
                startedAt: outcome.startedAt,
                completedAt: outcome.completedAt,
                cancelled: outcome.cancelled,
                analyzers,
                reports: outcome.reports,
                alerts: outcome.alerts,
                indicatorSources: [],
                verification: undefined,
            }),
        );

        const ruleSet = (report as { rule_set: { id: string; fired: boolean }[] }).rule_set;
        expect(ruleSet.length).toBeGreaterThan(20);
        expect(ruleSet.some((rule) => rule.id === "package.root_management")).toBe(true);
        expect(ruleSet.every((rule) => rule.fired === false || rule.fired === true)).toBe(true);
    });

    it("states plainly that no conclusion follows when no indicators were loaded", async () => {
        const { source, analyzers, outcome } = await analyse(CLEAN);
        const report: unknown = JSON.parse(
            buildAnalysisReport({
                acquisitionId: source.acquisitionId,
                sourceOrigin: source.origin,
                startedAt: outcome.startedAt,
                completedAt: outcome.completedAt,
                cancelled: outcome.cancelled,
                analyzers,
                reports: outcome.reports,
                alerts: outcome.alerts,
                indicatorSources: [],
                verification: undefined,
            }),
        );

        const note = (report as { indicator_set: { note: string | null } }).indicator_set.note;
        expect(note).toMatch(/No indicator bundles were loaded/);
    });

    it("marks the report as derived rather than collected", async () => {
        const { source, analyzers, outcome } = await analyse(CLEAN);
        const report: unknown = JSON.parse(
            buildAnalysisReport({
                acquisitionId: source.acquisitionId,
                sourceOrigin: source.origin,
                startedAt: outcome.startedAt,
                completedAt: outcome.completedAt,
                cancelled: outcome.cancelled,
                analyzers,
                reports: outcome.reports,
                alerts: outcome.alerts,
                indicatorSources: [],
                verification: undefined,
            }),
        );

        expect((report as { derived: boolean }).derived).toBe(true);
    });

    it("escapes CSV fields containing quotes and commas", async () => {
        const { outcome } = await analyse(COMPROMISED);
        const csv = buildAlertsCsv(outcome.alerts);

        expect(csv.split("\n")[0]).toBe(
            '"Level","Analyzer","Rule","Message","Artifact","Indicator","Evidence"',
        );
        // Evidence is serialised JSON, so it contains quotes that must be doubled.
        expect(csv).toContain('""package""');
    });

    it("excludes state observations from the timeline", async () => {
        // A disabled verifier is a condition, not an event; stamping it with the
        // analysis time would imply the device recorded it then.
        const { outcome } = await analyse(COMPROMISED);
        const timeline = buildTimelineCsv(outcome.alerts);

        expect(timeline.trim().split("\n")).toHaveLength(1);
    });
});
