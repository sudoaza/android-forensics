/**
 * Findings, and where they came from.
 *
 * Two properties matter more than the alerting itself:
 *
 *   1. **Every alert cites the rule that produced it.** An examiner reading
 *      `analysis.json` months later, or opposing counsel reading it in court,
 *      must be able to establish exactly what was checked and why it fired.
 *      A bare message is an assertion; a message plus a rule id, a severity, an
 *      artifact and the observed values is a reproducible finding.
 *
 *   2. **Severity is not a verdict.** These levels order findings for review;
 *      they do not score the device. Presence of a root binary is `high` because
 *      it warrants explanation, not because it proves compromise — and a
 *      competently hidden implant produces no alerts at all. The report says so.
 *
 * Levels are deliberately named to match the vocabulary MVT reports in, so an
 * examiner moving between the two tools reads them the same way.
 */

export type AlertLevel = "informational" | "low" | "medium" | "high" | "critical";

export const ALERT_LEVELS: readonly AlertLevel[] = [
    "informational",
    "low",
    "medium",
    "high",
    "critical",
];

const LEVEL_ORDER: Readonly<Record<AlertLevel, number>> = {
    informational: 0,
    low: 10,
    medium: 20,
    high: 30,
    critical: 40,
};

export function compareLevels(left: AlertLevel, right: AlertLevel): number {
    return LEVEL_ORDER[right] - LEVEL_ORDER[left];
}

/**
 * A matched indicator, recorded on an alert.
 *
 * The collection name and source file are carried, not just the value, because
 * "this hash is known bad" is only meaningful with the authority for that claim
 * attached.
 */
export interface IndicatorReference {
    readonly type: string;
    readonly value: string;
    /** Collection name, e.g. the malware or report the indicator belongs to. */
    readonly collection: string;
    /** Filename of the bundle it was loaded from. */
    readonly source: string;
}

export interface Alert {
    readonly level: AlertLevel;
    /** Analyzer id, e.g. "settings". */
    readonly analyzer: string;
    /**
     * Rule that fired. Absent only for indicator matches, where the indicator
     * reference is the identity instead.
     */
    readonly ruleId: string | undefined;
    readonly message: string;
    /** Archive-relative artifact the finding came from. */
    readonly artifact: string | undefined;
    /**
     * Device-reported time of the underlying event, when there is one. Empty for
     * state observations, which have no event time — a disabled verifier is a
     * condition, not an occurrence.
     */
    readonly eventTime: string | undefined;
    /** The observed data, so the finding can be re-derived. */
    readonly evidence: Readonly<Record<string, unknown>>;
    readonly matchedIndicator: IndicatorReference | undefined;
}

/**
 * A detection rule, as data.
 *
 * Rules are values rather than code so the whole rule set can be enumerated,
 * reported and diffed between runs. `rationale` exists because a finding an
 * examiner cannot explain to a court is not useful: it states why the condition
 * matters, in the report itself.
 */
export interface Rule {
    readonly id: string;
    readonly level: AlertLevel;
    /** What the condition means, in one line, for the report. */
    readonly rationale: string;
}

export class AlertStore {
    readonly #alerts: Alert[] = [];

    add(alert: Alert): void {
        this.#alerts.push(alert);
    }

    /** Records a finding from a declared rule. */
    fire(
        analyzer: string,
        rule: Rule,
        message: string,
        options?: {
            artifact?: string;
            eventTime?: string;
            evidence?: Readonly<Record<string, unknown>>;
            matchedIndicator?: IndicatorReference;
        },
    ): void {
        this.add({
            level: rule.level,
            analyzer,
            ruleId: rule.id,
            message,
            artifact: options?.artifact,
            eventTime: options?.eventTime,
            evidence: options?.evidence ?? {},
            matchedIndicator: options?.matchedIndicator,
        });
    }

    /**
     * Records an indicator match.
     *
     * Always `critical`: an indicator match means content on this device appears
     * in a published set of known-malicious artifacts, which is categorically
     * different from a configuration weakness.
     */
    indicatorMatch(
        analyzer: string,
        indicator: IndicatorReference,
        message: string,
        options?: {
            artifact?: string;
            eventTime?: string;
            evidence?: Readonly<Record<string, unknown>>;
        },
    ): void {
        this.add({
            level: "critical",
            analyzer,
            ruleId: undefined,
            message,
            artifact: options?.artifact,
            eventTime: options?.eventTime,
            evidence: options?.evidence ?? {},
            matchedIndicator: indicator,
        });
    }

    get alerts(): readonly Alert[] {
        return this.#alerts;
    }

    /** Highest severity first, then by analyzer, for review order. */
    get sorted(): readonly Alert[] {
        return [...this.#alerts].sort(
            (left, right) =>
                compareLevels(left.level, right.level) ||
                left.analyzer.localeCompare(right.analyzer) ||
                left.message.localeCompare(right.message),
        );
    }

    count(level: AlertLevel): number {
        return this.#alerts.filter((alert) => alert.level === level).length;
    }

    get counts(): Readonly<Record<AlertLevel, number>> {
        return {
            informational: this.count("informational"),
            low: this.count("low"),
            medium: this.count("medium"),
            high: this.count("high"),
            critical: this.count("critical"),
        };
    }

    /** Alerts with an event time, oldest first. Feeds the timeline export. */
    get timeline(): readonly Alert[] {
        return this.#alerts
            .filter((alert) => alert.eventTime !== undefined && alert.eventTime !== "")
            .sort((left, right) => (left.eventTime ?? "").localeCompare(right.eventTime ?? ""));
    }

    extend(alerts: readonly Alert[]): void {
        for (const alert of alerts) {
            this.add(alert);
        }
    }
}
