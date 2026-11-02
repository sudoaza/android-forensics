/**
 * Error taxonomy for the acquisition engine.
 *
 * The distinction that matters forensically is between:
 *
 *   - `expected`  the device legitimately refused or lacks the artifact
 *                 (permission denied, missing path, unsupported service).
 *                 This is *evidence*, recorded and not retried.
 *
 *   - transport   the link to the device broke. Acquisition of the current
 *                 artifact is void and the engine must stop.
 *
 * Never conflate them: "permission denied" on /proc/kmsg is a normal finding,
 * while a USB stall means every subsequent artifact is untrustworthy.
 */

export class AcquisitionError extends Error {
    /** Machine-readable code recorded in the manifest. */
    readonly code: string;

    /** True when this is a normal device refusal rather than a tooling fault. */
    readonly expected: boolean;

    constructor(
        code: string,
        message: string,
        options?: { expected?: boolean; cause?: unknown },
    ) {
        super(message, options?.cause !== undefined ? { cause: options.cause } : undefined);
        this.name = new.target.name;
        this.code = code;
        this.expected = options?.expected ?? false;
    }
}

/** The USB link or ADB transport failed. Acquisition cannot continue. */
export class TransportError extends AcquisitionError {
    constructor(message: string, cause?: unknown) {
        super("transport_failed", message, { expected: false, cause });
    }
}

/** Another process (usually a native `adb server`) owns the USB interface. */
export class DeviceBusyError extends AcquisitionError {
    constructor(cause?: unknown) {
        super(
            "device_busy",
            "The device is claimed by another process. Run `adb kill-server`, " +
                "close other WebADB tabs, then reconnect.",
            { expected: true, cause },
        );
    }
}

/** The user cancelled, or the device never authorized the RSA key. */
export class AuthorizationError extends AcquisitionError {
    constructor(message: string, cause?: unknown) {
        super("not_authorized", message, { expected: true, cause });
    }
}

/** A shell command exited non-zero, or its output indicates refusal. */
export class CommandFailedError extends AcquisitionError {
    readonly exitCode: number | undefined;
    readonly stderr: string;

    constructor(
        command: readonly string[],
        exitCode: number | undefined,
        stderr: string,
        expected: boolean,
    ) {
        super(
            "command_failed",
            `Command failed${exitCode === undefined ? "" : ` (exit ${exitCode})`}: ` +
                `${command.join(" ")}${stderr ? ` — ${stderr.trim().slice(0, 300)}` : ""}`,
            { expected },
        );
        this.exitCode = exitCode;
        this.stderr = stderr;
    }
}

/** A pull failed because the path is absent or unreadable. */
export class PullFailedError extends AcquisitionError {
    readonly path: string;

    constructor(path: string, reason: string, expected: boolean, cause?: unknown) {
        super("pull_failed", `Cannot read ${path}: ${reason}`, { expected, cause });
        this.path = path;
    }
}

/**
 * Recognizes device refusals that are routine during forensic collection.
 *
 * Matched against combined stdout+stderr because the none-protocol shell
 * (Android < 7 / no shell_v2) merges the two and reports no exit code, so
 * text is the only available signal.
 */
const EXPECTED_REFUSAL_PATTERNS: readonly RegExp[] = [
    /permission denied/i,
    /operation not permitted/i,
    /no such file or directory/i,
    /not found/i,
    /can'?t find service/i,
    /service .* does not exist/i,
    /unknown service/i,
    /inaccessible or not found/i,
    /read-only file system/i,
    /device or resource busy/i,
    /\bEACCES\b/,
    /\bENOENT\b/,
];

export function isExpectedRefusal(text: string): boolean {
    return EXPECTED_REFUSAL_PATTERNS.some((pattern) => pattern.test(text));
}

/** Normalizes an unknown throwable into an `AcquisitionError`. */
export function toAcquisitionError(error: unknown): AcquisitionError {
    if (error instanceof AcquisitionError) {
        return error;
    }

    if (error instanceof DOMException) {
        // WebUSB surfaces almost every hardware fault as a DOMException.
        switch (error.name) {
            case "NotFoundError":
                return new AcquisitionError("device_gone", "The USB device is no longer available.", {
                    expected: true,
                    cause: error,
                });
            case "SecurityError":
                return new AcquisitionError(
                    "usb_permission_denied",
                    "Permission to access the USB device was denied.",
                    { expected: true, cause: error },
                );
            case "NetworkError":
            case "AbortError":
            case "InvalidStateError":
                return new TransportError(`USB ${error.name}: ${error.message}`, error);
            default:
                return new TransportError(`USB ${error.name}: ${error.message}`, error);
        }
    }

    const message = error instanceof Error ? error.message : String(error);

    if (/device busy|claim|already in use/i.test(message)) {
        return new DeviceBusyError(error);
    }

    return new AcquisitionError("unknown", message, { cause: error });
}
