import { useState } from "react";

import { COLLECTOR_VERSION } from "../acquisition/manifest.js";
import { AcquisitionScreen } from "./AcquisitionScreen.js";
import { AnalysisScreen } from "./AnalysisScreen.js";
import { CompleteScreen } from "./CompleteScreen.js";
import { ConnectScreen } from "./ConnectScreen.js";
import { IndicatorPanel } from "./IndicatorPanel.js";
import { PreflightScreen } from "./PreflightScreen.js";
import { useAcquisition } from "./use-acquisition.js";
import { useAnalysis } from "./use-analysis.js";

export function App() {
    const acquisition = useAcquisition();
    const analysis = useAnalysis();

    /**
     * Analysis is a view over the acquisition rather than a stage of it, so it is
     * tracked separately. This is what lets an examiner analyse an imported
     * archive with no device connected, and return to the acquisition afterwards
     * without having lost it.
     */
    const [showAnalysis, setShowAnalysis] = useState(false);

    const deviceLabel =
        acquisition.device === undefined
            ? "device"
            : `${acquisition.device.manufacturer ?? ""} ${
                  acquisition.device.model ?? acquisition.device.usbName
              }`.trim();

    const onAnalyseArchive = (file: File): void => {
        setShowAnalysis(true);
        void analysis.analyseArchive(file);
    };

    return (
        <div className="app">
            <header className="masthead">
                <h1>Android Forensic Acquisition</h1>
                <span className="version">v{COLLECTOR_VERSION}</span>
            </header>

            {/* On the complete screen the error is rendered in context by
                CompleteScreen, alongside the export controls. */}
            {acquisition.error !== undefined &&
                !showAnalysis &&
                acquisition.screen !== "acquiring" &&
                acquisition.screen !== "complete" && (
                    <div className="notice error">
                        <strong>{acquisition.error}</strong>
                    </div>
                )}

            {showAnalysis ? (
                <AnalysisScreen
                    analysis={analysis}
                    onBack={() => {
                        setShowAnalysis(false);
                        analysis.reset();
                    }}
                />
            ) : (
                <>
                    {acquisition.screen === "connect" && (
                        <>
                            <ConnectScreen
                                supported={acquisition.supported}
                                knownDevices={acquisition.knownDevices}
                                busy={acquisition.busy}
                                caseDetails={acquisition.caseDetails}
                                onCaseDetailsChange={acquisition.setCaseDetails}
                                onRequestDevice={() => void acquisition.requestDevice()}
                                onConnect={(handle) => void acquisition.connectTo(handle)}
                            />
                            {/* Reachable with no device attached: an imported
                                archive is analysed without one. */}
                            <IndicatorPanel
                                analysis={analysis}
                                onAnalyseArchive={onAnalyseArchive}
                            />
                        </>
                    )}

                    {acquisition.screen === "preflight" && acquisition.device !== undefined && (
                        <PreflightScreen
                            device={acquisition.device}
                            onStart={(profile) => void acquisition.startAcquisition(profile)}
                            onDisconnect={() => void acquisition.disconnect()}
                        />
                    )}

                    {acquisition.screen === "acquiring" && acquisition.progress !== undefined && (
                        <AcquisitionScreen
                            deviceLabel={deviceLabel}
                            progress={acquisition.progress}
                            error={acquisition.error}
                            onCancel={acquisition.cancel}
                        />
                    )}

                    {acquisition.screen === "complete" && acquisition.outcome !== undefined && (
                        <CompleteScreen
                            summary={acquisition.outcome.summary}
                            store={acquisition.outcome.store}
                            runError={acquisition.error}
                            indicatorCount={analysis.indicators.total}
                            indicatorsLoading={analysis.indicators.loading}
                            persistedReports={analysis.persisted}
                            onAnalyse={() => {
                                setShowAnalysis(true);
                                if (acquisition.outcome !== undefined) {
                                    void analysis.analyseStore(acquisition.outcome.store);
                                }
                            }}
                            onDisconnect={() => void acquisition.disconnect()}
                            onReset={() => void acquisition.reset()}
                        />
                    )}

                    {/* A run that failed before anything was spooled has no evidence to
                        offer, so the examiner just needs a way back. */}
                    {acquisition.screen === "complete" && acquisition.outcome === undefined && (
                        <div className="card">
                            <h2>Acquisition failed</h2>
                            <p>
                                The acquisition could not be started, so no evidence was collected.
                            </p>
                            <div className="actions">
                                <button
                                    className="primary"
                                    onClick={() => void acquisition.reset()}
                                >
                                    Start over
                                </button>
                            </div>
                        </div>
                    )}
                </>
            )}
        </div>
    );
}
