import type { Analyzer, AnalysisContext } from "../analyzer.js";
import type { Rule } from "../alerts.js";
import { SETTING_RULES, evaluateSettings } from "../rules/settings.js";

/**
 * Settings analysis.
 *
 * Reads the three `settings_*.txt` artifacts, which the collector writes from
 * `settings list <namespace>` as plain `key=value` lines.
 *
 * A second layout is also accepted: the tabular `_id:… name:… pkg:… value:…`
 * form that appears in a bugreport's `dumpsys settings` section. Supporting both
 * costs a few lines and means the same rule table covers an imported bugreport
 * without a parallel implementation.
 */

const SETTINGS_PATTERN = "*/settings_*.txt";

/** `settings list` output: `key=value`, with values that may contain `=`. */
export function parseSettingsList(content: string): Map<string, string> {
    const settings = new Map<string, string>();

    for (const line of content.split("\n")) {
        const trimmed = line.trim();
        if (trimmed === "") {
            continue;
        }
        const separator = trimmed.indexOf("=");
        if (separator <= 0) {
            continue;
        }
        settings.set(trimmed.slice(0, separator), trimmed.slice(separator + 1));
    }

    return settings;
}

/**
 * `dumpsys settings` output.
 *
 * Rows look like:
 *   `_id:12 name:adb_enabled pkg:android value:1 default:0 defaultSystemSet:true`
 *
 * `value` is captured up to the optional `default:` tail, since a value may
 * itself contain spaces.
 */
export function parseSettingsDumpsys(content: string): Map<string, Map<string, string>> {
    const namespaces = new Map<string, Map<string, string>>();
    let current: Map<string, string> | undefined;

    for (const line of content.split("\n")) {
        const trimmed = line.trim();

        const heading = /^(CONFIG|GLOBAL|SECURE|SYSTEM) SETTINGS \(user (\d+)\)$/.exec(trimmed);
        if (heading !== null) {
            const namespace = `${heading[1]?.toLowerCase() ?? "unknown"}:user_${heading[2] ?? "0"}`;
            current = new Map<string, string>();
            namespaces.set(namespace, current);
            continue;
        }

        if (current === undefined || !trimmed.startsWith("_id:")) {
            continue;
        }

        const row = /^_id:\S+\s+name:(.*?)\s+pkg:\S+\s+value:(.*?)(?:\s+default:.*)?$/.exec(
            trimmed,
        );
        const key = row?.[1];
        const value = row?.[2];
        if (key !== undefined && value !== undefined) {
            current.set(key, value);
        }
    }

    return namespaces;
}

/** Derives the namespace from an artifact name, e.g. `settings_secure.txt` -> `secure`. */
function namespaceOf(artifactName: string): string {
    const filename = artifactName.split("/").pop() ?? artifactName;
    return filename.replace(/^settings_/, "").replace(/\.txt$/, "");
}

export const settingsAnalyzer: Analyzer = {
    id: "settings",
    label: "Settings and platform protections",
    inputs: [SETTINGS_PATTERN],
    rules: SETTING_RULES satisfies readonly Rule[],

    async run(ctx: AnalysisContext): Promise<void> {
        const namespaces = new Map<string, ReadonlyMap<string, string>>();
        const artifactByNamespace = new Map<string, string>();

        const files = ctx.source.match(SETTINGS_PATTERN);
        for (const [index, name] of files.entries()) {
            ctx.signal.throwIfAborted();
            ctx.progress(name, index, files.length);

            let content: string;
            try {
                content = await ctx.source.text(name);
            } catch (error) {
                ctx.note(name, error instanceof Error ? error.message : String(error));
                continue;
            }

            // The dumpsys form is recognised by its section headings; anything
            // else is treated as `settings list` output.
            const dumpsys = parseSettingsDumpsys(content);
            if (dumpsys.size > 0) {
                for (const [namespace, settings] of dumpsys) {
                    namespaces.set(namespace, settings);
                    artifactByNamespace.set(namespace, name);
                }
                ctx.examined(name);
                continue;
            }

            const namespace = namespaceOf(name);
            const parsed = parseSettingsList(content);
            if (parsed.size === 0) {
                ctx.note(name, "No settings could be parsed from this artifact.");
                continue;
            }
            namespaces.set(namespace, parsed);
            artifactByNamespace.set(namespace, name);
            ctx.examined(name);
        }

        for (const finding of evaluateSettings(namespaces)) {
            const artifact = artifactByNamespace.get(finding.namespace);
            ctx.alerts.fire(
                "settings",
                finding.rule,
                `${finding.rule.finding} — "${finding.namespace}" setting ` +
                    `${finding.rule.key} = ${finding.value} (expected ${finding.rule.expected})`,
                {
                    ...(artifact === undefined ? {} : { artifact }),
                    evidence: {
                        namespace: finding.namespace,
                        key: finding.rule.key,
                        value: finding.value,
                        expected: finding.rule.expected,
                    },
                },
            );
        }
    },
};
