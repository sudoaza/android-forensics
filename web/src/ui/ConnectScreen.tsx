import { useState } from "react";

import type { DeviceHandle } from "../adb/client.js";
import type { CaseDetails } from "./use-acquisition.js";

interface ConnectScreenProps {
    supported: boolean | undefined;
    knownDevices: readonly DeviceHandle[];
    busy: string | undefined;
    caseDetails: CaseDetails;
    onCaseDetailsChange: (details: CaseDetails) => void;
    onRequestDevice: () => void;
    onConnect: (handle: DeviceHandle) => void;
}

export function ConnectScreen({
    supported,
    knownDevices,
    busy,
    caseDetails,
    onCaseDetailsChange,
    onRequestDevice,
    onConnect,
}: ConnectScreenProps) {
    const secure = isSecureContext;
    const hasWebUsb = typeof navigator !== "undefined" && navigator.usb !== undefined;
    const hasOpfs = navigator.storage?.getDirectory !== undefined;

    // Capability check still in flight. Rendering the "unsupported" verdict here
    // would flash a false negative on every load.
    if (supported === undefined) {
        return (
            <div className="card">
                <h2>Checking environment…</h2>
                <p style={{ marginBottom: 0 }}>
                    Verifying WebUSB, secure context, and local evidence storage.
                </p>
            </div>
        );
    }

    if (!supported) {
        return (
            <div className="card">
                <h2>Unsupported browser</h2>
                <p>
                    This tool requires WebUSB and the Origin Private File System, and must be
                    served over HTTPS. It deliberately refuses to run in a degraded mode rather
                    than risk an incomplete acquisition.
                </p>
                <dl className="facts">
                    <dt>WebUSB</dt>
                    <dd>
                        <Status ok={hasWebUsb} okLabel="available" failLabel="unavailable" />
                    </dd>
                    <dt>Secure context</dt>
                    <dd>
                        <Status ok={secure} okLabel="yes" failLabel="no (HTTPS required)" />
                    </dd>
                    <dt>Local evidence storage</dt>
                    <dd>
                        <Status ok={hasOpfs} okLabel="available" failLabel="unavailable" />
                    </dd>
                </dl>
                <p className="muted" style={{ marginTop: 20, marginBottom: 0 }}>
                    Use Chrome, Chromium, or Edge on desktop.
                </p>
            </div>
        );
    }

    return (
        <>
            <div className="card">
                <h2>Case</h2>
                <p>
                    Recorded in the acquisition manifest. The station name also identifies the ADB
                    key this workstation presents to devices.
                </p>

                <div className="row">
                    <div className="field">
                        <label htmlFor="case-id">Case reference</label>
                        <input
                            id="case-id"
                            value={caseDetails.caseId}
                            placeholder="optional"
                            onChange={(event) =>
                                onCaseDetailsChange({ ...caseDetails, caseId: event.target.value })
                            }
                        />
                    </div>
                    <div className="field">
                        <label htmlFor="examiner">Examiner</label>
                        <input
                            id="examiner"
                            value={caseDetails.examiner}
                            placeholder="optional"
                            onChange={(event) =>
                                onCaseDetailsChange({
                                    ...caseDetails,
                                    examiner: event.target.value,
                                })
                            }
                        />
                    </div>
                </div>

                <div className="field">
                    <label htmlFor="station">Workstation</label>
                    <input
                        id="station"
                        value={caseDetails.station}
                        onChange={(event) =>
                            onCaseDetailsChange({ ...caseDetails, station: event.target.value })
                        }
                    />
                </div>
            </div>

            <div className="card">
                <h2>Connect device</h2>
                <p>
                    Enable USB debugging on the device, connect it, then authorize this
                    workstation when the device prompts.
                </p>

                <dl className="facts">
                    <dt>WebUSB</dt>
                    <dd>
                        <Status ok okLabel="supported" failLabel="" />
                    </dd>
                    <dt>Secure context</dt>
                    <dd>
                        <Status ok={secure} okLabel="yes" failLabel="no" />
                    </dd>
                    <dt>ADB key</dt>
                    <dd>
                        <span className="pill ok">{caseDetails.station}</span>
                    </dd>
                </dl>

                {knownDevices.length > 0 && (
                    <>
                        <h3>Previously authorized</h3>
                        <div className="profiles">
                            {knownDevices.map((handle) => (
                                <button
                                    key={handle.serial}
                                    className="profile"
                                    disabled={busy !== undefined}
                                    onClick={() => onConnect(handle)}
                                >
                                    <div className="name">{handle.name}</div>
                                    <div className="detail">{handle.serial}</div>
                                </button>
                            ))}
                        </div>
                    </>
                )}

                <div className="actions">
                    <button className="primary" disabled={busy !== undefined} onClick={onRequestDevice}>
                        {busy ?? "Connect Android device"}
                    </button>
                </div>

                <p className="muted" style={{ marginTop: 20, marginBottom: 0 }}>
                    If the device is not listed, close any running <code>adb</code> server with{" "}
                    <code>adb kill-server</code> — it holds the USB interface exclusively.
                </p>
            </div>

            <CredentialNotice />
        </>
    );
}

function CredentialNotice() {
    const [expanded, setExpanded] = useState(false);

    return (
        <div className="notice warn">
            <strong>ADB key is stored unencrypted in this browser profile.</strong>{" "}
            <button
                style={{
                    background: "none",
                    border: "none",
                    padding: 0,
                    font: "inherit",
                    color: "var(--accent)",
                    cursor: "pointer",
                }}
                onClick={() => setExpanded(!expanded)}
            >
                {expanded ? "Hide" : "Details"}
            </button>
            {expanded && (
                <p style={{ margin: "10px 0 0" }}>
                    WebAuthn-backed encryption of the ADB private key exists only in Tango 3.0
                    beta; this build pins the stable 2.6 line, which stores the key unwrapped in
                    IndexedDB. Anyone with access to this browser profile can impersonate this
                    workstation to a device that has authorized it. Treat the profile as
                    sensitive, and use a dedicated one for field work.
                </p>
            )}
        </div>
    );
}

function Status({
    ok,
    okLabel,
    failLabel,
}: {
    ok: boolean;
    okLabel: string;
    failLabel: string;
}) {
    return <span className={ok ? "pill ok" : "pill error"}>{ok ? okLabel : failLabel}</span>;
}
