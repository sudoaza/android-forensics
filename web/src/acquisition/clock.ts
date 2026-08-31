import type { AdbClient } from "../adb/client.js";

/**
 * Host/device clock correlation.
 *
 * Every timestamp inside logcat, dumpsys and Intrusion Logs is on the device's
 * clock, while the acquisition record is on the host's. Without a measured
 * offset the two cannot be aligned against external telemetry.
 *
 * Offset is estimated with the NTP-style minimum-RTT heuristic: the sample with
 * the shortest round trip has the least room for asymmetric delay, so its
 * offset is the most trustworthy. `date +%s%3N` is read once per sample and
 * assumed to be observed at the midpoint of the round trip.
 */

export interface ClockSample {
    readonly hostBeforeMs: number;
    readonly hostAfterMs: number;
    readonly deviceMs: number;
    readonly roundTripMs: number;
    /** deviceMs - host midpoint. Negative means the device is behind the host. */
    readonly offsetMs: number;
}

export interface ClockCorrelation {
    readonly at: string;
    readonly samples: readonly ClockSample[];
    /** Offset from the minimum-RTT sample. */
    readonly bestOffsetMs: number;
    readonly bestRoundTripMs: number;
    /** Present when the device clock could not be read at all. */
    readonly error?: string;
}

const SAMPLE_COUNT = 5;

export async function correlateClocks(client: AdbClient): Promise<ClockCorrelation> {
    const at = new Date().toISOString();
    const samples: ClockSample[] = [];
    let lastError: string | undefined;

    for (let index = 0; index < SAMPLE_COUNT; index += 1) {
        const hostBeforeMs = Date.now();
        try {
            const result = await client.exec(["date", "+%s%3N"]);
            const hostAfterMs = Date.now();

            const deviceMs = Number.parseInt(result.stdout.trim(), 10);
            if (!Number.isFinite(deviceMs)) {
                lastError = `Unparseable device time: ${result.stdout.trim().slice(0, 80)}`;
                continue;
            }

            const roundTripMs = hostAfterMs - hostBeforeMs;
            samples.push({
                hostBeforeMs,
                hostAfterMs,
                deviceMs,
                roundTripMs,
                offsetMs: deviceMs - (hostBeforeMs + roundTripMs / 2),
            });
        } catch (error) {
            lastError = error instanceof Error ? error.message : String(error);
        }
    }

    if (samples.length === 0) {
        return {
            at,
            samples: [],
            bestOffsetMs: 0,
            bestRoundTripMs: 0,
            error: lastError ?? "No clock samples could be taken.",
        };
    }

    const best = samples.reduce((a, b) => (b.roundTripMs < a.roundTripMs ? b : a));

    return {
        at,
        samples,
        bestOffsetMs: Math.round(best.offsetMs),
        bestRoundTripMs: best.roundTripMs,
    };
}
