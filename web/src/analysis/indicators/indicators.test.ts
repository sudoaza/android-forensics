import { describe, expect, it } from "vitest";

import { IndicatorLibrary } from "./matcher.js";
import { parsePattern, parseStix2Bundle } from "./stix2.js";

/**
 * Indicator loading and matching.
 *
 * The matching semantics are the substance of these tests. Every case here is
 * one where being slightly wrong produces either a missed detection or a false
 * accusation, and neither is acceptable in a forensic tool: an examiner acts on
 * these findings.
 */

function bundle(objects: readonly Record<string, unknown>[]): string {
    return JSON.stringify({ type: "bundle", id: "bundle--test", objects });
}

function indicator(pattern: string, id = `indicator--${pattern}`): Record<string, unknown> {
    return { type: "indicator", spec_version: "2.1", id, pattern, pattern_type: "stix" };
}

describe("STIX2 pattern parsing", () => {
    it("reads the object types MVT's published bundles use", () => {
        expect(parsePattern("[domain-name:value='evil.example']")).toEqual({
            type: "domain",
            value: "evil.example",
        });
        expect(parsePattern("[app:id='com.example.spy']")).toEqual({
            type: "app_id",
            value: "com.example.spy",
        });
        expect(parsePattern("[process:name='malware_daemon']")).toEqual({
            type: "process",
            value: "malware_daemon",
        });
        expect(parsePattern("[file:path='/data/local/tmp/payload']")).toEqual({
            type: "file_path",
            value: "/data/local/tmp/payload",
        });
        expect(parsePattern("[android-property:name='persist.sys.spy']")).toEqual({
            type: "android_property",
            value: "persist.sys.spy",
        });
    });

    it("accepts both the spec-compliant and lowercase hash spellings", () => {
        // The spec requires quoting for algorithm names with a hyphen; bundles in
        // the wild use both. Dropping either would silently discard indicators.
        const quoted = parsePattern("[file:hashes.'SHA-256'='abc123']");
        const lower = parsePattern("[file:hashes.sha256='abc123']");

        expect(quoted).toEqual({ type: "file_sha256", value: "abc123" });
        expect(lower).toEqual(quoted);
    });

    it("normalises certificate hash spellings the same way", () => {
        expect(parsePattern("[app:cert.'SHA-1'='deadbeef']")).toEqual({
            type: "app_cert_hash",
            value: "deadbeef",
        });
    });

    it("treats IP addresses as hosts", () => {
        expect(parsePattern("[ipv4-addr:value='198.51.100.7']")).toEqual({
            type: "domain",
            value: "198.51.100.7",
        });
    });

    it("lowercases domains but preserves case in paths and package names", () => {
        // Paths and package names are case-sensitive on Android; folding them
        // would create false matches.
        expect(parsePattern("[domain-name:value='EVIL.Example']")?.value).toBe("evil.example");
        expect(parsePattern("[file:path='/Data/Local/Tmp']")?.value).toBe("/Data/Local/Tmp");
    });

    it("declines compound patterns rather than partially reading them", () => {
        // Reading one half of an AND would match on the wrong condition, which is
        // worse than not matching at all.
        expect(
            parsePattern("[domain-name:value='a.example' AND domain-name:value='b.example']"),
        ).toBeUndefined();
    });

    it("declines object types it does not understand", () => {
        expect(parsePattern("[windows-registry-key:key='HKLM\\\\Foo']")).toBeUndefined();
    });
});

describe("STIX2 bundle loading", () => {
    it("attributes indicators to the malware they relate to", () => {
        const loaded = parseStix2Bundle(
            "test.stix2",
            bundle([
                { type: "malware", id: "malware--1", name: "ExampleSpy", is_family: false },
                indicator("[app:id='com.example.spy']", "indicator--1"),
                {
                    type: "relationship",
                    id: "relationship--1",
                    relationship_type: "indicates",
                    source_ref: "indicator--1",
                    target_ref: "malware--1",
                },
            ]),
            "supplied",
        );

        expect(loaded.total).toBe(1);
        expect(loaded.indicators[0]?.collection).toBe("ExampleSpy");
        expect(loaded.collections[0]?.name).toBe("ExampleSpy");
        expect(loaded.collections[0]?.counts["app_id"]).toBe(1);
    });

    it("attributes indicators referenced by a report", () => {
        const loaded = parseStix2Bundle(
            "report.stix2",
            bundle([
                {
                    type: "report",
                    id: "report--1",
                    name: "Campaign Writeup",
                    object_refs: ["indicator--1"],
                },
                indicator("[domain-name:value='evil.example']", "indicator--1"),
            ]),
            "supplied",
        );

        expect(loaded.indicators[0]?.collection).toBe("Campaign Writeup");
    });

    it("groups unattributed indicators rather than discarding them", () => {
        const loaded = parseStix2Bundle(
            "loose.stix2",
            bundle([indicator("[domain-name:value='evil.example']")]),
            "supplied",
        );

        expect(loaded.total).toBe(1);
        expect(loaded.indicators[0]?.collection).toBe("Ungrouped indicators");
    });

    it("counts patterns it could not read, so a silent gap is visible", () => {
        const loaded = parseStix2Bundle(
            "mixed.stix2",
            bundle([
                indicator("[app:id='com.example.spy']", "indicator--ok"),
                indicator("[windows-registry-key:key='HKLM']", "indicator--bad"),
            ]),
            "supplied",
        );

        expect(loaded.total).toBe(1);
        expect(loaded.unsupportedPatterns).toHaveLength(1);
    });

    it("records a content hash for provenance", () => {
        const content = bundle([indicator("[app:id='com.example.spy']")]);
        const first = parseStix2Bundle("a.stix2", content, "bundled");
        const second = parseStix2Bundle("b.stix2", content, "supplied");

        expect(first.sha256).toMatch(/^[0-9a-f]{64}$/);
        expect(second.sha256).toBe(first.sha256);
        expect(first.origin).toBe("bundled");
        expect(second.origin).toBe("supplied");
    });

    it("rejects a file that is not a STIX2 bundle", () => {
        expect(() => parseStix2Bundle("x.stix2", "{}", "supplied")).toThrow(/not a STIX2 bundle/);
        expect(() => parseStix2Bundle("x.stix2", "nonsense", "supplied")).toThrow(/not valid JSON/);
    });
});

describe("indicator matching", () => {
    function libraryWith(patterns: readonly string[]): IndicatorLibrary {
        const library = new IndicatorLibrary();
        library.add(
            parseStix2Bundle(
                "test.stix2",
                bundle([
                    { type: "malware", id: "malware--1", name: "ExampleSpy", is_family: false },
                    ...patterns.map((pattern, index) =>
                        indicator(pattern, `indicator--${index}`),
                    ),
                    ...patterns.map((_pattern, index) => ({
                        type: "relationship",
                        id: `relationship--${index}`,
                        relationship_type: "indicates",
                        source_ref: `indicator--${index}`,
                        target_ref: "malware--1",
                    })),
                ]),
                "supplied",
            ),
        );
        return library;
    }

    it("matches package names exactly, case-insensitively", () => {
        const library = libraryWith(["[app:id='com.example.spy']"]);

        expect(library.checkAppId("com.example.spy")?.collection).toBe("ExampleSpy");
        expect(library.checkAppId("COM.EXAMPLE.SPY")).toBeDefined();
        // A vendor prefix must not drag in unrelated applications.
        expect(library.checkAppId("com.example.spyware")).toBeUndefined();
        expect(library.checkAppId("com.example")).toBeUndefined();
    });

    it("selects the hash algorithm by digest length", () => {
        const library = libraryWith([
            `[file:hashes.md5='${"a".repeat(32)}']`,
            `[file:hashes.sha1='${"b".repeat(40)}']`,
            `[file:hashes.sha256='${"c".repeat(64)}']`,
        ]);

        expect(library.checkFileHash("a".repeat(32))).toBeDefined();
        expect(library.checkFileHash("b".repeat(40))).toBeDefined();
        expect(library.checkFileHash("c".repeat(64))).toBeDefined();
        expect(library.checkFileHash("d".repeat(64))).toBeUndefined();
    });

    it("matches a hash regardless of case", () => {
        const library = libraryWith([`[file:hashes.sha256='${"AB".repeat(32)}']`]);
        expect(library.checkFileHash("ab".repeat(32))).toBeDefined();
    });

    it("matches a truncated process name against a longer indicator", () => {
        // The kernel's comm field is 16 bytes, so ps reports 15 characters. An
        // indicator longer than that could otherwise never match.
        const library = libraryWith(["[process:name='com.evil.persistent.daemon']"]);

        expect(library.checkProcess("com.evil.persis")).toBeDefined();
        expect(library.checkProcess("com.evil.persis")?.message).toMatch(/truncated/);
        // A short observation is not enough to conclude truncation.
        expect(library.checkProcess("com.evil")).toBeUndefined();
    });

    it("matches a process name exactly when it fits", () => {
        const library = libraryWith(["[process:name='evildaemon']"]);

        expect(library.checkProcess("evildaemon")).toBeDefined();
        expect(library.checkProcess("evildaemon2")).toBeUndefined();
    });

    it("matches files inside an indicator directory, on a segment boundary", () => {
        const library = libraryWith(["[file:path='/data/local/tmp/evil']"]);

        expect(library.checkFilePath("/data/local/tmp/evil")).toBeDefined();
        expect(library.checkFilePath("/data/local/tmp/evil/payload.so")).toBeDefined();
        // Must not match a sibling whose name merely starts the same way.
        expect(library.checkFilePath("/data/local/tmp/evilish")).toBeUndefined();
        expect(library.checkFilePath("/data/local/tmp")).toBeUndefined();
    });

    it("matches a subdomain of a flagged domain, but not a lookalike", () => {
        const library = libraryWith(["[domain-name:value='evil.example']"]);

        expect(library.checkDomain("evil.example")).toBeDefined();
        expect(library.checkDomain("c2.evil.example")).toBeDefined();
        expect(library.checkDomain("deep.c2.evil.example")).toBeDefined();
        // The critical negative: a different domain that ends in the same text.
        expect(library.checkDomain("notevil.example")).toBeUndefined();
    });

    it("does not treat a flagged domain as flagging its parent", () => {
        const library = libraryWith(["[domain-name:value='c2.evil.example']"]);

        expect(library.checkDomain("c2.evil.example")).toBeDefined();
        expect(library.checkDomain("evil.example")).toBeUndefined();
    });

    it("never matches a public suffix as a parent domain", () => {
        // Walking every parent label would make an indicator for a domain imply
        // its TLD, flagging the entire internet.
        const library = libraryWith(["[domain-name:value='evil.example']"]);
        expect(library.checkDomain("unrelated.example")).toBeUndefined();
    });

    it("reduces a URL to its host", () => {
        const library = libraryWith(["[domain-name:value='evil.example']"]);

        expect(library.checkDomain("https://evil.example/payload?x=1")).toBeDefined();
        expect(library.checkDomain("evil.example:8443")).toBeDefined();
    });

    it("matches certificate hashes and property names", () => {
        const library = libraryWith([
            "[app:cert.sha256='deadbeef']",
            "[android-property:name='persist.sys.spy']",
        ]);

        expect(library.checkAppCertificateHash("DEADBEEF")).toBeDefined();
        expect(library.checkAndroidPropertyName("persist.sys.spy")).toBeDefined();
        expect(library.checkAndroidPropertyName("persist.sys.timezone")).toBeUndefined();
    });

    it("treats paths and process names as case-sensitive", () => {
        // Android filesystems and process names are case-sensitive, so folding
        // case here would manufacture matches that are not real.
        const library = libraryWith([
            "[file:path='/data/local/tmp/evil']",
            "[process:name='evildaemon']",
        ]);

        expect(library.checkFilePath("/data/local/tmp/evil")).toBeDefined();
        expect(library.checkFilePath("/DATA/LOCAL/TMP/EVIL")).toBeUndefined();
        expect(library.checkProcess("evildaemon")).toBeDefined();
        expect(library.checkProcess("EvilDaemon")).toBeUndefined();
    });

    it("ignores empty observations", () => {
        const library = libraryWith(["[app:id='com.example.spy']"]);

        expect(library.checkAppId("")).toBeUndefined();
        expect(library.checkFileHash("")).toBeUndefined();
        expect(library.checkDomain("")).toBeUndefined();
    });

    it("reports nothing at all when no bundles are loaded", () => {
        const library = new IndicatorLibrary();

        expect(library.isEmpty).toBe(true);
        expect(library.checkAppId("com.example.spy")).toBeUndefined();
    });

    it("does not double-count a bundle loaded twice", () => {
        // An examiner adding a directory that overlaps the shipped snapshot must
        // not inflate the indicator counts in the report.
        const library = new IndicatorLibrary();
        const content = bundle([indicator("[app:id='com.example.spy']")]);

        library.add(parseStix2Bundle("a.stix2", content, "bundled"));
        library.add(parseStix2Bundle("a-copy.stix2", content, "supplied"));

        expect(library.bundles).toHaveLength(1);
        expect(library.total).toBe(1);
    });

    it("forgets indicators from a removed bundle", () => {
        const library = new IndicatorLibrary();
        const loaded = parseStix2Bundle(
            "a.stix2",
            bundle([indicator("[app:id='com.example.spy']")]),
            "supplied",
        );
        library.add(loaded);
        expect(library.checkAppId("com.example.spy")).toBeDefined();

        library.remove(loaded.sha256);
        expect(library.checkAppId("com.example.spy")).toBeUndefined();
        expect(library.isEmpty).toBe(true);
    });

    it("reports counts by type for the report's provenance", () => {
        const library = libraryWith([
            "[app:id='com.example.spy']",
            "[domain-name:value='evil.example']",
            "[domain-name:value='evil2.example']",
        ]);

        expect(library.countsByType).toEqual({ app_id: 1, domain: 2 });
    });
});
