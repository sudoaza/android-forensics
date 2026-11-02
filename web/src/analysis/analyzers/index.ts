import type { Analyzer } from "../analyzer.js";
import { getpropAnalyzer } from "./getprop.js";
import { networkAnalyzer } from "./network.js";
import { packagesAnalyzer } from "./packages.js";
import { processesAnalyzer } from "./processes.js";
import { rootAnalyzer } from "./root.js";
import { settingsAnalyzer } from "./settings.js";

/**
 * The analyzer set, in report order.
 *
 * Ordered so that findings which qualify the trustworthiness of everything else
 * come first: if verified boot failed or the system partition is writable, that
 * changes how every subsequent finding should be read.
 *
 * `network` runs last because it is the only analyzer that scans large artifacts
 * (a logcat can exceed 100 MB), so every cheap finding is already on screen
 * before it starts.
 */
export function defaultAnalyzers(options?: { now?: () => Date }): readonly Analyzer[] {
    return [
        getpropAnalyzer(options?.now),
        rootAnalyzer,
        settingsAnalyzer,
        packagesAnalyzer,
        processesAnalyzer,
        networkAnalyzer,
    ];
}
