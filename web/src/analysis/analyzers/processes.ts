import type { Rule } from "../alerts.js";
import type { AnalysisContext, Analyzer } from "../analyzer.js";

/**
 * Running process analysis.
 *
 * Reads `processes.txt` (this collector) or `ps.txt` (AndroidQF). Process names
 * are the surface where an implant that has deleted its package is still
 * visible, so this is the main non-package route to identifying a running
 * payload.
 *
 * There is deliberately no standalone heuristic here — no "unexpected root
 * process" rule. On OEM builds dozens of vendor daemons legitimately run
 * privileged with undocumented names, so any such rule produces a page of benign
 * findings, and a report an examiner learns to skim is worse than one that stays
 * quiet. This analyzer therefore reports only indicator matches, and states as
 * much when no indicators are loaded.
 */

const PROCESS_PATTERNS = ["*/processes.txt", "*/ps.txt"];

const RULES = {
    indicatorProcess: {
        id: "process.matched_indicator",
        level: "critical",
        rationale:
            "A running process matches a published indicator of compromise. Note that " +
            "the kernel truncates process names to 15 characters, so the match may be " +
            "on a prefix.",
    },
} as const satisfies Record<string, Rule>;

export const PROCESS_RULES: readonly Rule[] = Object.values(RULES);

export interface ProcessEntry {
    readonly user: string;
    readonly pid: number;
    readonly ppid: number | undefined;
    readonly name: string;
}

/**
 * Parses `ps` output.
 *
 * Column layout varies across OEM builds and across the `ps` flags the collector
 * falls back through, so the header is read to locate columns rather than
 * assuming fixed positions.
 *
 * The name column is located explicitly instead of taking the last field. Under
 * `ARGS`/`CMD` layouts the final column is a full command line, so the last
 * field is an argument — `--zygote`, not `app_process` — and an indicator would
 * never match it.
 */
export function parseProcesses(content: string): readonly ProcessEntry[] {
    const lines = content.split("\n").filter((line) => line.trim() !== "");
    if (lines.length === 0) {
        return [];
    }

    const header = lines[0] ?? "";
    const columns = header.trim().split(/\s+/);
    const hasHeader = /\b(PID|CMD|NAME|COMMAND|ARGS)\b/i.test(header) && !/^\s*\d/.test(header);

    const indexOf = (...names: readonly string[]): number => {
        for (const name of names) {
            const index = columns.findIndex((column) => column.toUpperCase() === name);
            if (index >= 0) {
                return index;
            }
        }
        return -1;
    };

    const userColumn = hasHeader ? indexOf("USER", "UID") : 0;
    const pidColumn = hasHeader ? indexOf("PID") : 1;
    const ppidColumn = hasHeader ? indexOf("PPID") : -1;
    const nameColumn = hasHeader ? indexOf("NAME", "CMD", "COMMAND", "ARGS") : -1;

    const entries: ProcessEntry[] = [];
    for (const line of lines.slice(hasHeader ? 1 : 0)) {
        const fields = line.trim().split(/\s+/);
        if (fields.length < 2) {
            continue;
        }

        const pid = Number.parseInt(fields[pidColumn < 0 ? 1 : pidColumn] ?? "", 10);
        if (!Number.isFinite(pid)) {
            continue;
        }

        // Under a command-line column the first token is the executable and the
        // rest are arguments, so only the first token is taken. Kernel threads
        // are reported in brackets, which are stripped so the name can match an
        // indicator.
        const raw =
            nameColumn >= 0 && nameColumn < fields.length
                ? (fields[nameColumn] ?? "")
                : (fields[fields.length - 1] ?? "");
        const name = raw.replace(/^\[/, "").replace(/\]$/, "");
        if (name === "") {
            continue;
        }

        const ppidRaw = ppidColumn >= 0 ? Number.parseInt(fields[ppidColumn] ?? "", 10) : Number.NaN;

        entries.push({
            user: fields[userColumn < 0 ? 0 : userColumn] ?? "",
            pid,
            ppid: Number.isFinite(ppidRaw) ? ppidRaw : undefined,
            name,
        });
    }

    return entries;
}

export const processesAnalyzer: Analyzer = {
    id: "processes",
    label: "Running processes",
    inputs: PROCESS_PATTERNS,
    rules: PROCESS_RULES,

    async run(ctx: AnalysisContext): Promise<void> {
        const name = PROCESS_PATTERNS.flatMap((pattern) => [...ctx.source.match(pattern)])[0];
        if (name === undefined) {
            return;
        }

        let processes: readonly ProcessEntry[];
        try {
            processes = parseProcesses(await ctx.source.text(name));
        } catch (error) {
            ctx.note(name, error instanceof Error ? error.message : String(error));
            return;
        }

        if (processes.length === 0) {
            ctx.note(name, "No processes could be parsed.");
            return;
        }
        ctx.examined(name);

        if (ctx.indicators === undefined) {
            return;
        }

        for (const process of processes) {
            ctx.signal.throwIfAborted();

            const hit = ctx.indicators.checkProcess(process.name);
            if (hit !== undefined) {
                ctx.alerts.indicatorMatch("processes", hit, hit.message, {
                    artifact: name,
                    evidence: {
                        process: process.name,
                        pid: process.pid,
                        ppid: process.ppid ?? null,
                        user: process.user,
                    },
                });
            }

            // A process name that looks like a path is also checked as one: some
            // indicators are published as the executable's path rather than its
            // command name.
            if (process.name.startsWith("/")) {
                const pathHit = ctx.indicators.checkFilePath(process.name);
                if (pathHit !== undefined) {
                    ctx.alerts.indicatorMatch("processes", pathHit, pathHit.message, {
                        artifact: name,
                        evidence: { process: process.name, pid: process.pid },
                    });
                }
            }
        }
    },
};
