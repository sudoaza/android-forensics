import { COLLECTOR_VERSION } from "../acquisition/manifest.js";
import { AcquisitionScreen } from "./AcquisitionScreen.js";
import { CompleteScreen } from "./CompleteScreen.js";
import { ConnectScreen } from "./ConnectScreen.js";
import { PreflightScreen } from "./PreflightScreen.js";
import { useAcquisition } from "./use-acquisition.js";

export function App() {
    const acquisition = useAcquisition();

    const deviceLabel =
        acquisition.device === undefined
            ? "device"
            : `${acquisition.device.manufacturer ?? ""} ${
                  acquisition.device.model ?? acquisition.device.usbName
              }`.trim();

    return (
        <div className="app">
            <header className="masthead">
                <h1>Android Forensic Acquisition</h1>
                <span className="version">v{COLLECTOR_VERSION}</span>
            </header>

            {/* On the complete screen the error is rendered in context by
                CompleteScreen, alongside the export controls. */}
            {acquisition.error !== undefined &&
                acquisition.screen !== "acquiring" &&
                acquisition.screen !== "complete" && (
                    <div className="notice error">
                        <strong>{acquisition.error}</strong>
                    </div>
                )}

            {acquisition.screen === "connect" && (
                <ConnectScreen
                    supported={acquisition.supported}
                    knownDevices={acquisition.knownDevices}
                    busy={acquisition.busy}
                    caseDetails={acquisition.caseDetails}
                    onCaseDetailsChange={acquisition.setCaseDetails}
                    onRequestDevice={() => void acquisition.requestDevice()}
                    onConnect={(handle) => void acquisition.connectTo(handle)}
                />
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
                        <button className="primary" onClick={() => void acquisition.reset()}>
                            Start over
                        </button>
                    </div>
                </div>
            )}
        </div>
    );
}
