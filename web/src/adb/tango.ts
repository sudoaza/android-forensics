import { Adb, AdbDaemonTransport, AdbSync } from "@yume-chan/adb";
import {
    AdbDaemonWebUsbDevice,
    AdbDaemonWebUsbDeviceManager,
} from "@yume-chan/adb-daemon-webusb";
import { ConcatStringStream, TextDecoderStream } from "@yume-chan/stream-extra";

import type {
    AdbClient,
    AdbConnector,
    CommandResult,
    CommandStream,
    DeviceHandle,
    DeviceIdentity,
    DirectoryEntry,
    FileStat,
} from "./client.js";
import { openHostCredential, type HostCredential } from "./credentials.js";
import {
    AuthorizationError,
    DeviceBusyError,
    PullFailedError,
    TransportError,
    isExpectedRefusal,
    toAcquisitionError,
} from "./errors.js";

/**
 * Tango 2.6.3 adapter.
 *
 * Tango's stream classes are the platform streams in a browser, but their
 * type declarations are package-local mirrors, so the two casts below convert
 * between identical runtime objects that TypeScript sees as distinct nominal
 * types. They are the only casts in the file and mark the exact seam where
 * Tango's types stop.
 */
function asPlatformStream(stream: unknown): ReadableStream<Uint8Array> {
    return stream as ReadableStream<Uint8Array>;
}

const LINUX_FILE_TYPE_DIRECTORY = 4;
const LINUX_FILE_TYPE_FILE = 8;
const LINUX_FILE_TYPE_LINK = 10;

function mapFileType(type: number): FileStat["type"] {
    switch (type) {
        case LINUX_FILE_TYPE_DIRECTORY:
            return "directory";
        case LINUX_FILE_TYPE_FILE:
            return "file";
        case LINUX_FILE_TYPE_LINK:
            return "link";
        default:
            return "other";
    }
}

class TangoAdbClient implements AdbClient {
    readonly identity: DeviceIdentity;
    readonly disconnected: Promise<void>;

    readonly #adb: Adb;
    /**
     * One sync session is reused across the acquisition. `AdbSync` serializes
     * operations on its socket internally, and the engine pulls sequentially,
     * so this avoids a socket round-trip per file across thousands of APKs.
     */
    #sync: AdbSync | undefined;
    #closed = false;

    constructor(adb: Adb, usbName: string) {
        this.#adb = adb;

        const banner = adb.banner;
        this.identity = {
            serial: adb.serial,
            name: usbName,
            product: banner.product,
            model: banner.model,
            device: banner.device,
            features: [...adb.deviceFeatures],
            maxPayloadSize: adb.maxPayloadSize,
        };

        this.disconnected = adb.disconnected.then(() => {
            this.#closed = true;
        });
    }

    get closed(): boolean {
        return this.#closed;
    }

    async exec(command: readonly string[], signal?: AbortSignal): Promise<CommandResult> {
        this.#assertOpen();
        signal?.throwIfAborted();

        const shellProtocol = this.#adb.subprocess.shellProtocol;

        try {
            if (shellProtocol !== undefined) {
                const process = await shellProtocol.spawn(command, signal);
                // stderr must be drained concurrently with stdout: ADB
                // multiplexes both over one connection, so reading them in
                // sequence deadlocks as soon as either buffer fills.
                const [stdout, stderr, exitCode] = await Promise.all([
                    process.stdout
                        .pipeThrough(new TextDecoderStream())
                        .pipeThrough(new ConcatStringStream()),
                    process.stderr
                        .pipeThrough(new TextDecoderStream())
                        .pipeThrough(new ConcatStringStream()),
                    process.exited,
                ]);

                return { command, stdout, stderr, exitCode, protocol: "shell-v2" };
            }

            const process = await this.#adb.subprocess.noneProtocol.spawn(command, signal);
            const merged = await process.output
                .pipeThrough(new TextDecoderStream())
                .pipeThrough(new ConcatStringStream());

            // The legacy shell reports no exit status and folds stderr into
            // stdout, so refusal can only be detected from the text itself.
            return {
                command,
                stdout: merged,
                stderr: "",
                exitCode: undefined,
                protocol: "none",
            };
        } catch (error) {
            throw toAcquisitionError(error);
        }
    }

    async execStream(
        command: readonly string[],
        signal?: AbortSignal,
    ): Promise<CommandStream> {
        this.#assertOpen();
        signal?.throwIfAborted();

        const shellProtocol = this.#adb.subprocess.shellProtocol;

        try {
            if (shellProtocol !== undefined) {
                const process = await shellProtocol.spawn(command, signal);
                // Start draining stderr immediately; the caller only owns stdout.
                const stderr = process.stderr
                    .pipeThrough(new TextDecoderStream())
                    .pipeThrough(new ConcatStringStream());

                return {
                    command,
                    protocol: "shell-v2",
                    stdout: asPlatformStream(process.stdout),
                    exitCode: process.exited,
                    stderr: Promise.resolve(stderr),
                };
            }

            const process = await this.#adb.subprocess.noneProtocol.spawn(command, signal);
            return {
                command,
                protocol: "none",
                stdout: asPlatformStream(process.output),
                exitCode: process.exited.then(() => undefined),
                stderr: Promise.resolve(""),
            };
        } catch (error) {
            throw toAcquisitionError(error);
        }
    }

    async #getSync(): Promise<AdbSync> {
        this.#sync ??= await this.#adb.sync();
        return this.#sync;
    }

    async pull(
        remotePath: string,
        signal?: AbortSignal,
    ): Promise<ReadableStream<Uint8Array>> {
        this.#assertOpen();
        signal?.throwIfAborted();

        // Stat first so an unreadable path fails before a stream is handed out;
        // otherwise the failure surfaces mid-transfer as a broken artifact.
        const stat = await this.stat(remotePath);
        if (stat.type === "directory") {
            throw new PullFailedError(remotePath, "path is a directory", true);
        }

        try {
            const sync = await this.#getSync();
            return asPlatformStream(sync.read(remotePath));
        } catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            throw new PullFailedError(remotePath, message, isExpectedRefusal(message), error);
        }
    }

    async stat(remotePath: string): Promise<FileStat> {
        this.#assertOpen();

        try {
            const sync = await this.#getSync();
            // lstat (v1) works on every Android version, unlike stat v2.
            const stat = await sync.lstat(remotePath);

            // adbd reports a zeroed entry rather than an error for missing paths.
            if (stat.mode === 0 && stat.size === 0n && stat.mtime === 0n) {
                throw new PullFailedError(remotePath, "no such file or directory", true);
            }

            return {
                path: remotePath,
                size: Number(stat.size),
                mtimeMs: stat.mtime === 0n ? undefined : Number(stat.mtime) * 1000,
                mode: stat.mode,
                type: mapFileType(stat.type),
            };
        } catch (error) {
            if (error instanceof PullFailedError) {
                throw error;
            }
            const message = error instanceof Error ? error.message : String(error);
            throw new PullFailedError(remotePath, message, isExpectedRefusal(message), error);
        }
    }

    async listDirectory(remotePath: string): Promise<readonly DirectoryEntry[]> {
        this.#assertOpen();

        try {
            const sync = await this.#getSync();
            const entries = await sync.readdir(remotePath);
            return entries
                .filter((entry) => entry.name !== "." && entry.name !== "..")
                .map((entry) => ({
                    name: entry.name,
                    size: Number(entry.size),
                    mtimeMs: entry.mtime === 0n ? undefined : Number(entry.mtime) * 1000,
                    type: mapFileType(entry.type),
                }));
        } catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            throw new PullFailedError(remotePath, message, isExpectedRefusal(message), error);
        }
    }

    async close(): Promise<void> {
        if (this.#closed) {
            return;
        }
        this.#closed = true;

        // Release the sync socket before the transport, then let USB go so a
        // native `adb` server can claim the interface again.
        try {
            await this.#sync?.dispose();
        } catch {
            // A dead transport cannot be closed cleanly; nothing to salvage.
        }
        this.#sync = undefined;

        try {
            await this.#adb.close();
        } catch {
            // Same rationale.
        }
    }

    #assertOpen(): void {
        if (this.#closed) {
            throw new TransportError("The device connection is closed.");
        }
    }
}

class TangoDeviceHandle implements DeviceHandle {
    readonly serial: string;
    readonly name: string;

    readonly #device: AdbDaemonWebUsbDevice;
    readonly #credential: HostCredential;

    constructor(device: AdbDaemonWebUsbDevice, credential: HostCredential) {
        this.#device = device;
        this.#credential = credential;
        this.serial = device.serial;
        this.name = device.name;
    }

    async connect(signal?: AbortSignal): Promise<AdbClient> {
        signal?.throwIfAborted();

        let connection;
        try {
            // Claims the ADB USB interface for the lifetime of the connection.
            connection = await this.#device.connect();
        } catch (error) {
            if (error instanceof AdbDaemonWebUsbDevice.DeviceBusyError) {
                throw new DeviceBusyError(error);
            }
            throw toAcquisitionError(error);
        }

        try {
            // Blocks on the device's RSA authorization dialog the first time
            // this host key is presented.
            const transport = await AdbDaemonTransport.authenticate({
                serial: this.serial,
                connection,
                credentialStore: this.#credential.store,
            });

            return new TangoAdbClient(new Adb(transport), this.name);
        } catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            if (signal?.aborted === true) {
                throw new AuthorizationError("Connection cancelled before authorization.", error);
            }
            throw new AuthorizationError(
                `ADB authentication failed. Confirm the "Allow USB debugging" prompt on the ` +
                    `device, then retry. (${message})`,
                error,
            );
        }
    }
}

export class TangoConnector implements AdbConnector {
    readonly #credential: HostCredential;

    private constructor(credential: HostCredential) {
        this.#credential = credential;
    }

    static async create(station: string): Promise<TangoConnector> {
        return new TangoConnector(await openHostCredential(station));
    }

    get credential(): HostCredential {
        return this.#credential;
    }

    isSupported(): boolean {
        return AdbDaemonWebUsbDeviceManager.BROWSER !== undefined && isSecureContext;
    }

    async requestDevice(): Promise<DeviceHandle | undefined> {
        const manager = this.#manager();
        try {
            const device = await manager.requestDevice();
            return device === undefined
                ? undefined
                : new TangoDeviceHandle(device, this.#credential);
        } catch (error) {
            // The chooser rejects with NotFoundError when the user dismisses it.
            if (error instanceof DOMException && error.name === "NotFoundError") {
                return undefined;
            }
            throw toAcquisitionError(error);
        }
    }

    async listDevices(): Promise<readonly DeviceHandle[]> {
        const manager = this.#manager();
        const devices = await manager.getDevices();
        return devices.map((device) => new TangoDeviceHandle(device, this.#credential));
    }

    async hostPublicKey(): Promise<string> {
        return this.#credential.publicKey;
    }

    #manager(): AdbDaemonWebUsbDeviceManager {
        const manager = AdbDaemonWebUsbDeviceManager.BROWSER;
        if (manager === undefined) {
            throw new TransportError(
                "WebUSB is unavailable. Use Chromium, Chrome, or Edge over HTTPS.",
            );
        }
        return manager;
    }
}
