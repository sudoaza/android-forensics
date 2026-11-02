import type { DeviceContext } from "../acquisition/device-context.js";
import { PROFILES, type ProfileId } from "../acquisition/profiles.js";

interface PreflightScreenProps {
    device: DeviceContext;
    onStart: (profile: ProfileId) => void;
    onDisconnect: () => void;
}

export function PreflightScreen({ device, onStart, onDisconnect }: PreflightScreenProps) {
    const bootState = device.verifiedBootState;
    const selinux = device.selinux;

    return (
        <>
            <div className="card">
                <h2>
                    {device.manufacturer ?? ""} {device.model ?? device.usbName}
                </h2>
                <p>{device.buildFingerprint ?? device.serial}</p>

                <dl className="facts">
                    <dt>Serial</dt>
                    <dd>{device.serial}</dd>

                    <dt>Android</dt>
                    <dd>
                        {device.androidRelease ?? "unknown"}
                        {device.sdk === undefined ? "" : ` (API ${device.sdk})`}
                    </dd>

                    <dt>Security patch</dt>
                    <dd>{device.securityPatch ?? "unknown"}</dd>

                    <dt>Architecture</dt>
                    <dd>{device.abi ?? "unknown"}</dd>

                    <dt>Verified boot</dt>
                    <dd>
                        <span
                            className={
                                bootState === "green"
                                    ? "pill ok"
                                    : bootState === undefined
                                      ? "pill"
                                      : "pill warn"
                            }
                        >
                            {bootState ?? "unknown"}
                        </span>
                    </dd>

                    <dt>Bootloader</dt>
                    <dd>
                        <span
                            className={
                                device.bootloaderLocked === true
                                    ? "pill ok"
                                    : device.bootloaderLocked === false
                                      ? "pill warn"
                                      : "pill"
                            }
                        >
                            {device.bootloaderLocked === true
                                ? "locked"
                                : device.bootloaderLocked === false
                                  ? "unlocked"
                                  : "unknown"}
                        </span>
                    </dd>

                    <dt>SELinux</dt>
                    <dd>
                        <span
                            className={
                                selinux === "Enforcing"
                                    ? "pill ok"
                                    : selinux === undefined
                                      ? "pill"
                                      : "pill warn"
                            }
                        >
                            {selinux ?? "unknown"}
                        </span>
                    </dd>

                    <dt>Shell user</dt>
                    <dd>
                        <span className={device.isRootShell ? "pill warn" : "pill"}>
                            {device.shellUser ?? "unknown"}
                        </span>
                    </dd>

                    <dt>Shell protocol</dt>
                    <dd>
                        <span className={device.hasShellV2 ? "pill ok" : "pill warn"}>
                            {device.hasShellV2 ? "shell_v2" : "legacy (no exit codes)"}
                        </span>
                    </dd>

                    <dt>Bugreport</dt>
                    <dd>
                        <span className={device.capabilities.bugreportz ? "pill ok" : "pill warn"}>
                            {device.capabilities.bugreportz ? "bugreportz available" : "unavailable"}
                        </span>
                    </dd>

                    <dt>Intrusion Logs</dt>
                    <dd>
                        <span className="pill">{device.capabilities.intrusionLogging}</span>
                    </dd>
                </dl>

                {!device.hasShellV2 && (
                    <div className="notice warn" style={{ marginTop: 20, marginBottom: 0 }}>
                        <strong>This device does not support shell protocol v2.</strong> Command
                        exit codes and stderr are unavailable, so command success is inferred from
                        output text. Failures are recorded as such in the command log.
                    </div>
                )}

                {device.bootloaderLocked === false && (
                    <div className="notice warn" style={{ marginTop: 12, marginBottom: 0 }}>
                        <strong>The bootloader is unlocked.</strong> The system partition may have
                        been modified, which qualifies every finding in this acquisition.
                    </div>
                )}
            </div>

            <div className="card">
                <h2>Acquisition profile</h2>
                <p>
                    Modules run cheapest-first, so an interrupted acquisition still preserves
                    device state. Duration is not estimated: APK volume and bugreport generation
                    time vary by orders of magnitude across devices.
                </p>

                <div className="profiles">
                    {(Object.keys(PROFILES) as ProfileId[]).map((id) => {
                        const profile = PROFILES[id];
                        return (
                            <button
                                key={id}
                                className="profile"
                                onClick={() => onStart(id)}
                            >
                                <div className="name">
                                    {profile.label}
                                    <span className="muted" style={{ marginLeft: 8 }}>
                                        {profile.modules.length} modules
                                    </span>
                                </div>
                                <div className="detail">{profile.description}</div>
                            </button>
                        );
                    })}
                </div>

                <div className="actions">
                    <button onClick={onDisconnect}>Disconnect</button>
                </div>
            </div>
        </>
    );
}
