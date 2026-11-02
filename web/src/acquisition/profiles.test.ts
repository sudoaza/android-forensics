import { describe, expect, it } from "vitest";

import { PROFILES, profileFor, type ProfileId } from "./profiles.js";

/**
 * The connection-test profile exists to prove the transport works in seconds
 * without moving bulk data. That guarantee is structural — it holds only while
 * no expensive module is in its list — so it is asserted rather than trusted to
 * survive future edits.
 */

/** Modules that transfer files or unbounded output, by module id. */
const EXPENSIVE_MODULES: readonly string[] = [
    "packages",
    "package-detail",
    "bugreport",
    "dumpsys",
    "logcat",
    "system-logs",
    "log-directories",
    "tmp-directories",
];

describe("connection-test profile", () => {
    const profile = profileFor("connection-test");

    it("contains no module that pulls files or unbounded output", () => {
        const ids = profile.modules.map((module) => module.id);
        expect(ids.filter((id) => EXPENSIVE_MODULES.includes(id))).toEqual([]);
    });

    it("uses the capped logcat tail rather than the full dump", () => {
        const ids = profile.modules.map((module) => module.id);
        expect(ids).toContain("logcat-tail");
        expect(ids).not.toContain("logcat");
    });

    it("still captures the identity and boot state an examiner needs", () => {
        const ids = profile.modules.map((module) => module.id);
        expect(ids).toContain("getprop");
        expect(ids).toContain("boot-state");
    });

    it("is the smallest profile", () => {
        for (const id of ["quick", "standard", "full"] as ProfileId[]) {
            expect(profile.modules.length).toBeLessThan(PROFILES[id].modules.length);
        }
    });
});

describe("profiles", () => {
    it("expose unique module ids, so progress rows and log attribution stay distinct", () => {
        for (const id of Object.keys(PROFILES) as ProfileId[]) {
            const ids = PROFILES[id].modules.map((module) => module.id);
            expect(new Set(ids).size).toBe(ids.length);
        }
    });

    it("order cheap state before bulk transfer in every profile", () => {
        // An interrupted run must still have captured device state, so no
        // expensive module may precede the identity probes.
        for (const id of Object.keys(PROFILES) as ProfileId[]) {
            const ids = PROFILES[id].modules.map((module) => module.id);
            const firstExpensive = ids.findIndex((moduleId) =>
                EXPENSIVE_MODULES.includes(moduleId),
            );
            if (firstExpensive === -1) continue;
            expect(ids.indexOf("getprop")).toBeLessThan(firstExpensive);
            expect(ids.indexOf("boot-state")).toBeLessThan(firstExpensive);
        }
    });
});
