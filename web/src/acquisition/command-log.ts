import type { ShellProtocol } from "../adb/client.js";

/**
 * Chronological record of every device interaction.
 *
 * Failures are recorded with the same weight as successes. A missing artifact
 * with a logged "Permission denied" is a finding; a missing artifact with no
 * explanation is a gap in the record.
 */

export interface CommandLogEntry {
    readonly sequence: number;
    readonly module: string;
    /** Argv as sent to the device, never a re-quoted shell string. */
    readonly command: readonly string[];
    readonly startedAt: string;
    readonly completedAt: string;
    readonly durationMs: number;
    /** Device wall clock near execution, when a sample was taken. */
    readonly deviceTime: string | undefined;
    readonly exitCode: number | undefined;
    readonly protocol: ShellProtocol;
    readonly bytes: number;
    /** Archive path of the artifact produced, when any. */
    readonly artifact: string | undefined;
    readonly sha256: string | undefined;
    readonly stderr: string;
    readonly error: string | undefined;
}

export class CommandLog {
    readonly #entries: CommandLogEntry[] = [];

    append(entry: Omit<CommandLogEntry, "sequence">): CommandLogEntry {
        const recorded: CommandLogEntry = { sequence: this.#entries.length + 1, ...entry };
        this.#entries.push(recorded);
        return recorded;
    }

    get entries(): readonly CommandLogEntry[] {
        return this.#entries;
    }

    /**
     * Human-readable log, in the shape the design specifies. Each command
     * produces START / EXIT / SHA256 lines so it can be read without tooling;
     * `command.log.json` carries the same data for machines.
     */
    render(): string {
        const lines: string[] = [];

        for (const entry of this.#entries) {
            const argv = entry.command.join(" ");
            lines.push(`${entry.startedAt} START [${entry.module}] ${argv}`);

            if (entry.deviceTime !== undefined) {
                lines.push(`${entry.startedAt} DEVICE_TIME ${entry.deviceTime}`);
            }

            lines.push(
                `${entry.completedAt} EXIT ${
                    entry.exitCode === undefined ? "unknown (none-protocol)" : entry.exitCode
                } (${entry.durationMs}ms, ${entry.bytes} bytes)`,
            );

            if (entry.stderr.trim().length > 0) {
                for (const line of entry.stderr.trimEnd().split("\n")) {
                    lines.push(`${entry.completedAt} STDERR ${line}`);
                }
            }

            if (entry.artifact !== undefined && entry.sha256 !== undefined) {
                lines.push(`${entry.completedAt} ARTIFACT ${entry.artifact}`);
                lines.push(`${entry.completedAt} SHA256 ${entry.sha256}`);
            }

            if (entry.error !== undefined) {
                lines.push(`${entry.completedAt} ERROR ${entry.error}`);
            }
        }

        return `${lines.join("\n")}\n`;
    }

    toJson(): string {
        return `${JSON.stringify(this.#entries, undefined, 2)}\n`;
    }
}
