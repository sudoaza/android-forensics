/**
 * The single boundary between this application and Tango.
 *
 * Nothing outside `src/adb/` may import `@yume-chan/*`. Tango's daemon
 * authentication API is actively changing (2.x exposes
 * `AdbDaemonTransport.authenticate` + `credentialStore`; 3.0-beta moves to
 * `adbDaemonAuthenticate` + `credentialManager`), so the adapter absorbs that
 * churn and the acquisition engine never sees it.
 *
 * Commands are `readonly string[]` argv, never shell strings. Tango's
 * `splitCommand` does not strip quote characters from the tokens it produces,
 * so `logcat -b all '*:V'` would arrive at the device as a literal `'*:V'`
 * including quotes. Argv also gives the command log an unambiguous record.
 * Use `["sh", "-c", "..."]` explicitly when shell semantics are required.
 */

export interface DeviceIdentity {
    /** USB serial as reported by the device. Primary identity for resume. */
    readonly serial: string;
    /** Human-readable USB product string, for the device chooser. */
    readonly name: string;
    readonly product: string | undefined;
    readonly model: string | undefined;
    readonly device: string | undefined;
    /** ADB protocol features negotiated with this device. */
    readonly features: readonly string[];
    readonly maxPayloadSize: number;
}

export interface CommandResult {
    readonly command: readonly string[];
    readonly stdout: string;
    readonly stderr: string;
    /**
     * `undefined` when the device only supports the legacy none-protocol
     * shell, which multiplexes stderr into stdout and reports no exit status.
     */
    readonly exitCode: number | undefined;
    readonly protocol: ShellProtocol;
}

export type ShellProtocol = "shell-v2" | "none";

export interface CommandStream {
    readonly command: readonly string[];
    readonly protocol: ShellProtocol;
    /**
     * Under `none` protocol this carries stdout and stderr interleaved.
     * Under `shell-v2` it carries stdout only; `stderr` is collected separately.
     */
    readonly stdout: ReadableStream<Uint8Array>;
    /** Resolves once the process exits. `undefined` under `none` protocol. */
    readonly exitCode: Promise<number | undefined>;
    /** Resolves to captured stderr text. Always empty under `none` protocol. */
    readonly stderr: Promise<string>;
}

export interface FileStat {
    readonly path: string;
    readonly size: number;
    /** Unix mtime in milliseconds, or `undefined` when unavailable. */
    readonly mtimeMs: number | undefined;
    readonly mode: number;
    readonly type: "file" | "directory" | "link" | "other";
}

export interface DirectoryEntry {
    readonly name: string;
    readonly size: number;
    readonly mtimeMs: number | undefined;
    readonly type: "file" | "directory" | "link" | "other";
}

export interface AdbClient {
    readonly identity: DeviceIdentity;

    /** Resolves when the transport drops, for either planned or unplanned reasons. */
    readonly disconnected: Promise<void>;

    /** True once `close()` has run or the transport has dropped. */
    readonly closed: boolean;

    /** Runs a command to completion and buffers its output as text. */
    exec(command: readonly string[], signal?: AbortSignal): Promise<CommandResult>;

    /**
     * Runs a command and exposes stdout as a stream, for outputs too large to
     * buffer (`bugreportz`, `logcat -b all`, full `dumpsys`).
     *
     * The caller MUST fully read or cancel `stdout`. ADB multiplexes every
     * logical stream over one USB connection, so an abandoned stream stalls
     * the entire transport.
     */
    execStream(command: readonly string[], signal?: AbortSignal): Promise<CommandStream>;

    /** Streams a file off the device over the ADB sync service. */
    pull(remotePath: string, signal?: AbortSignal): Promise<ReadableStream<Uint8Array>>;

    /** `lstat`-equivalent. Throws `PullFailedError` when the path is unreachable. */
    stat(remotePath: string): Promise<FileStat>;

    listDirectory(remotePath: string): Promise<readonly DirectoryEntry[]>;

    close(): Promise<void>;
}

/** Discovery and connection, kept separate so the UI never touches Tango. */
export interface AdbConnector {
    /** False when the browser lacks WebUSB or the context is insecure. */
    isSupported(): boolean;

    /** Opens the browser device chooser. Requires a user gesture. */
    requestDevice(): Promise<DeviceHandle | undefined>;

    /** Previously authorized devices, available without a chooser. */
    listDevices(): Promise<readonly DeviceHandle[]>;

    /** The ADB host public key presented to devices, recorded in the manifest. */
    hostPublicKey(): Promise<string>;
}

export interface DeviceHandle {
    readonly serial: string;
    readonly name: string;
    /**
     * Performs the ADB handshake. Blocks until the user accepts the RSA
     * fingerprint prompt on the device the first time this key is seen.
     */
    connect(signal?: AbortSignal): Promise<AdbClient>;
}
