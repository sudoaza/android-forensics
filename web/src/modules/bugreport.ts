import type { AcquisitionContext, AcquisitionModule, ModuleResult } from "../acquisition/artifact.js";
import { ResultBuilder } from "../acquisition/artifact.js";

/**
 * Bugreport acquisition.
 *
 * MVT runs its bugreport analysis automatically when `bugreport.zip` exists
 * inside an AndroidQF acquisition, so this is high-value despite being the
 * slowest module.
 *
 * The native `adb bugreport` command is not a single device call: the CLI
 * orchestrates the `bugreport` service, parses progress, then pulls the
 * resulting file. Rather than reimplement that protocol, this module drives
 * `bugreportz` directly, which is the same mechanism the CLI uses underneath
 * and reports a path in a documented, parseable format:
 *
 *   BEGIN:/data/user_de/0/com.android.shell/files/bugreports/bugreport-...zip
 *   PROGRESS:12/100
 *   OK:/data/user_de/0/com.android.shell/files/bugreports/bugreport-...zip
 *   FAIL:<reason>
 *
 * The ZIP is then pulled over ADB sync and deleted from the device, since the
 * acquisition should not leave artifacts behind.
 *
 * Portability caveat: `bugreportz` exists from Android 7 (API 24) onward and
 * `-p` progress from the same release, but generation time and OEM behaviour
 * vary widely. This is flagged in the design as needing per-device testing.
 */

const BUGREPORT_TIMEOUT_MS = 15 * 60 * 1000;

interface BugreportzOutcome {
    readonly path: string | undefined;
    readonly failure: string | undefined;
    readonly raw: string;
}

/**
 * Runs `bugreportz -p` and follows its progress lines.
 *
 * Streamed rather than buffered so progress reaches the UI live: a bugreport
 * can take many minutes, and a silent progress bar is indistinguishable from a
 * hang.
 */
async function runBugreportz(ctx: AcquisitionContext): Promise<BugreportzOutcome> {
    const command = ctx.device.capabilities.bugreportzProgress
        ? ["bugreportz", "-p"]
        : ["bugreportz"];

    const timeout = new AbortController();
    const timer = setTimeout(() => timeout.abort(), BUGREPORT_TIMEOUT_MS);

    // Abort on either the user's cancellation or the timeout.
    const onAbort = (): void => timeout.abort();
    ctx.signal.addEventListener("abort", onAbort, { once: true });

    try {
        const stream = await ctx.client.execStream(command, timeout.signal);

        let raw = "";
        let pending = "";
        const decoder = new TextDecoder();
        const reader = stream.stdout.getReader();

        try {
            for (;;) {
                const { done, value } = await reader.read();
                if (done) {
                    break;
                }

                const text = decoder.decode(value, { stream: true });
                raw += text;
                pending += text;

                // Progress lines are separated by \r so the shell can overwrite
                // them in place; split on both.
                const parts = pending.split(/[\r\n]/);
                pending = parts.pop() ?? "";

                for (const part of parts) {
                    const line = part.trim();
                    const progress = /^PROGRESS:(\d+)\/(\d+)$/.exec(line);
                    if (progress?.[1] !== undefined && progress[2] !== undefined) {
                        ctx.progress(
                            "Generating bugreport on device",
                            Number.parseInt(progress[1], 10),
                            Number.parseInt(progress[2], 10),
                        );
                    }
                }
            }
        } finally {
            reader.releaseLock();
        }

        raw += decoder.decode();

        const okMatch = /^OK:(.+)$/m.exec(raw);
        if (okMatch?.[1] !== undefined) {
            return { path: okMatch[1].trim(), failure: undefined, raw };
        }

        const failMatch = /^FAIL:(.*)$/m.exec(raw);
        if (failMatch !== null) {
            return { path: undefined, failure: failMatch[1]?.trim() ?? "unknown", raw };
        }

        // Some OEM builds print only the path, with no OK: prefix.
        const beginMatch = /^BEGIN:(.+)$/m.exec(raw);
        if (beginMatch?.[1] !== undefined) {
            return {
                path: beginMatch[1].trim(),
                failure: undefined,
                raw,
            };
        }

        return {
            path: undefined,
            failure: `Unrecognized bugreportz output: ${raw.trim().slice(0, 200)}`,
            raw,
        };
    } finally {
        clearTimeout(timer);
        ctx.signal.removeEventListener("abort", onAbort);
    }
}

export const bugreportModule: AcquisitionModule = {
    id: "bugreport",
    label: "Bugreport",
    supports: (device) => device.capabilities.bugreportz,

    async run(ctx: AcquisitionContext): Promise<ModuleResult> {
        const result = new ResultBuilder();
        const startedAt = new Date().toISOString();

        let outcome: BugreportzOutcome;
        try {
            ctx.progress("Generating bugreport on device (this takes several minutes)");
            outcome = await runBugreportz(ctx);
        } catch (error) {
            result.error("bugreportz", error);
            return result.build();
        }

        // The raw transcript is evidence of how the bugreport was produced.
        try {
            await ctx.writeText("bugreport.log", outcome.raw.endsWith("\n") ? outcome.raw : `${outcome.raw}\n`);
            result.artifact("bugreport.log");
        } catch (error) {
            result.error("bugreport.log", error);
        }

        ctx.log.append({
            module: ctx.module,
            command: ctx.device.capabilities.bugreportzProgress
                ? ["bugreportz", "-p"]
                : ["bugreportz"],
            startedAt,
            completedAt: new Date().toISOString(),
            durationMs: Date.parse(new Date().toISOString()) - Date.parse(startedAt),
            deviceTime: undefined,
            exitCode: outcome.failure === undefined ? 0 : 1,
            protocol: ctx.device.hasShellV2 ? "shell-v2" : "none",
            bytes: outcome.raw.length,
            artifact: "bugreport.log",
            sha256: undefined,
            stderr: "",
            error: outcome.failure,
        });

        if (outcome.path === undefined) {
            result.error("bugreportz", outcome.failure ?? "No bugreport path reported", true);
            return result.build();
        }

        ctx.progress("Transferring bugreport.zip");
        try {
            await ctx.pullToArtifact(outcome.path, "bugreport.zip");
            result.artifact("bugreport.zip");
            result.note("device_path", outcome.path);
        } catch (error) {
            result.error(outcome.path, error);
            return result.build();
        }

        // Remove the generated file so the acquisition leaves no residue. A
        // failure here is worth recording but does not invalidate the artifact.
        try {
            await ctx.run(["rm", "-f", outcome.path]);
        } catch (error) {
            result.error(`rm -f ${outcome.path}`, error, true);
        }

        return result.build();
    },
};
