import type { Alert, AlertStore, Rule } from "./alerts.js";
import { ALERT_LEVELS } from "./alerts.js";
import type { Analyzer, AnalyzerReport } from "./analyzer.js";
import type { VerificationReport } from "./source.js";

/**
 * Analysis output.
 *
 * The report is written to be defensible rather than merely readable, which
 * drives three things that a simpler design would omit:
 *
 *   1. **Rule-set provenance.** Every rule that *could* have fired is listed,
 *      not only those that did. Without it, a report showing no findings is
 *      indistinguishable from a report produced with an empty rule set.
 *
 *   2. **Indicator-set provenance.** Which bundles were loaded, their SHA-256,
 *      and how many indicators of each type they contributed. "No IOC matches"
 *      means nothing unless the indicator set is identified.
 *
 *   3. **Explicit limits.** What this analysis does not do is stated in the
 *      report itself, so an absent capability cannot be mistaken for a negative
 *      finding.
 *
 * Analysis is derived data. It is written as new artifacts alongside the
 * evidence, never over it, and is marked as derived so it can never be confused
 * with something the device reported.
 */

export const ANALYSIS_FORMAT = "webadb-forensics-analysis";
export const ANALYSIS_FORMAT_VERSION = 1;

export const ANALYSIS_FILENAME = "analysis.json";
export const ALERTS_FILENAME = "analysis_alerts.csv";
export const TIMELINE_FILENAME = "analysis_timeline.csv";

/** Provenance for one loaded indicator bundle. */
export interface IndicatorSourceInfo {
    readonly filename: string;
    readonly sha256: string;
    /** "bundled" ships with the application; "supplied" came from the examiner. */
    readonly origin: "bundled" | "supplied";
    readonly collections: readonly {
        readonly name: string;
        readonly counts: Readonly<Record<string, number>>;
    }[];
    readonly totalIndicators: number;
}

export interface AnalysisReportInput {
    readonly acquisitionId: string;
    readonly sourceOrigin: "opfs" | "zip";
    readonly startedAt: string;
    readonly completedAt: string;
    readonly cancelled: boolean;
    readonly analyzers: readonly Analyzer[];
    readonly reports: readonly AnalyzerReport[];
    readonly alerts: AlertStore;
    readonly indicatorSources: readonly IndicatorSourceInfo[];
    readonly verification: VerificationReport | undefined;
}

/**
 * Capabilities deliberately absent, stated in the report.
 *
 * Each of these is something an examiner familiar with MVT would expect, so its
 * absence is recorded rather than left to be discovered. Silence about a missing
 * check reads as a passed check.
 */
const DECLARED_LIMITS: readonly string[] = [
    "No network requests are made. URL shorteners are not expanded and no reputation " +
        "service (for example VirusTotal) is queried, so no data about this device leaves " +
        "the examiner's machine.",
    "Findings are observations requiring interpretation, not a verdict. Severity orders " +
        "them for review and does not score the device.",
    "Detection of rooting and of known malware is name-, path- and hash-based. A renamed " +
        "package, a relocated binary, or a recompiled payload will not be identified.",
    "An absence of findings is not evidence of integrity. A competently implemented " +
        "implant leaves none of the traces this analysis examines.",
];

export function buildAnalysisReport(input: AnalysisReportInput): string {
    const alerts = input.alerts.sorted;

    const report = {
        format: ANALYSIS_FORMAT,
        format_version: ANALYSIS_FORMAT_VERSION,
        /**
         * Marks this file as produced by analysing the acquisition rather than by
         * collecting from the device.
         */
        derived: true,

        acquisition_id: input.acquisitionId,
        source: input.sourceOrigin,
        started: input.startedAt,
        completed: input.completedAt,
        cancelled: input.cancelled,

        analyzer: {
            name: ANALYSIS_FORMAT,
            version: ANALYSIS_FORMAT_VERSION,
            user_agent: typeof navigator === "undefined" ? null : navigator.userAgent,
        },

        /**
         * Whether the archive's contents still match its own `hashes.csv`. Absent
         * for a just-collected acquisition, whose artifacts were verified by
         * re-read at collection time instead.
         */
        integrity:
            input.verification === undefined
                ? null
                : {
                      status: input.verification.status,
                      reason: input.verification.reason ?? null,
                      artifacts_checked: input.verification.checked,
                      mismatches: input.verification.mismatches,
                      missing_from_archive: input.verification.missing,
                      absent_from_manifest: input.verification.unlisted,
                  },

        summary: {
            total: alerts.length,
            by_level: countByLevel(alerts),
            indicator_matches: alerts.filter((alert) => alert.matchedIndicator !== undefined).length,
        },

        alerts: alerts.map(serialiseAlert),

        analyzers: input.reports.map((report) => ({
            id: report.id,
            label: report.label,
            status: report.status,
            artifacts_matched: report.inputsFound,
            artifacts_examined: report.examined,
            alerts: report.alertCount,
            problems: report.problems,
            duration_ms: report.durationMs,
        })),

        /**
         * The complete rule set in force, whether or not each rule fired. This is
         * what makes a clean report meaningful.
         */
        rule_set: input.analyzers.flatMap((analyzer) =>
            analyzer.rules.map((rule) => ({
                id: rule.id,
                analyzer: analyzer.id,
                level: rule.level,
                rationale: rule.rationale,
                fired: alerts.some((alert) => alert.ruleId === rule.id),
            })),
        ),

        indicator_set: {
            sources: input.indicatorSources,
            total_indicators: input.indicatorSources.reduce(
                (sum, source) => sum + source.totalIndicators,
                0,
            ),
            /**
             * Stated explicitly: with no indicators loaded, the absence of
             * indicator matches carries no information at all.
             */
            note:
                input.indicatorSources.length === 0
                    ? "No indicator bundles were loaded. No conclusion about known malware " +
                      "can be drawn from this report."
                    : null,
        },

        limits: DECLARED_LIMITS,
    };

    return `${JSON.stringify(report, undefined, 2)}\n`;
}

function countByLevel(alerts: readonly Alert[]): Record<string, number> {
    const counts: Record<string, number> = {};
    for (const level of ALERT_LEVELS) {
        counts[level] = alerts.filter((alert) => alert.level === level).length;
    }
    return counts;
}

function serialiseAlert(alert: Alert): Record<string, unknown> {
    return {
        level: alert.level,
        analyzer: alert.analyzer,
        rule_id: alert.ruleId ?? null,
        message: alert.message,
        artifact: alert.artifact ?? null,
        event_time: alert.eventTime ?? null,
        evidence: alert.evidence,
        matched_indicator:
            alert.matchedIndicator === undefined
                ? null
                : {
                      type: alert.matchedIndicator.type,
                      value: alert.matchedIndicator.value,
                      collection: alert.matchedIndicator.collection,
                      source: alert.matchedIndicator.source,
                  },
    };
}

/** RFC 4180 field: always quoted, embedded quotes doubled. */
function csvField(value: unknown): string {
    const text =
        value === undefined || value === null
            ? ""
            : typeof value === "string"
              ? value
              : JSON.stringify(value);
    return `"${text.replaceAll('"', '""')}"`;
}

export function buildAlertsCsv(alerts: AlertStore): string {
    const lines = [
        ["Level", "Analyzer", "Rule", "Message", "Artifact", "Indicator", "Evidence"]
            .map(csvField)
            .join(","),
    ];

    for (const alert of alerts.sorted) {
        lines.push(
            [
                csvField(alert.level),
                csvField(alert.analyzer),
                csvField(alert.ruleId),
                csvField(alert.message),
                csvField(alert.artifact),
                csvField(
                    alert.matchedIndicator === undefined
                        ? ""
                        : `${alert.matchedIndicator.type}=${alert.matchedIndicator.value} ` +
                              `(${alert.matchedIndicator.collection})`,
                ),
                csvField(alert.evidence),
            ].join(","),
        );
    }

    return `${lines.join("\n")}\n`;
}

/**
 * Timeline of alerts that have a device-reported event time.
 *
 * State observations are excluded rather than stamped with the analysis time:
 * placing "Play Protect is disabled" at the moment of examination would imply
 * the device recorded it then, which it did not.
 */
export function buildTimelineCsv(alerts: AlertStore): string {
    const lines = [
        ["Event Time", "Level", "Analyzer", "Message", "Artifact"].map(csvField).join(","),
    ];

    for (const alert of alerts.timeline) {
        lines.push(
            [
                csvField(alert.eventTime),
                csvField(alert.level),
                csvField(alert.analyzer),
                csvField(alert.message),
                csvField(alert.artifact),
            ].join(","),
        );
    }

    return `${lines.join("\n")}\n`;
}

/** Rules declared across a set of analyzers, for display before a run. */
export function ruleInventory(analyzers: readonly Analyzer[]): readonly (Rule & {
    analyzer: string;
})[] {
    return analyzers.flatMap((analyzer) =>
        analyzer.rules.map((rule) => ({ ...rule, analyzer: analyzer.id })),
    );
}
