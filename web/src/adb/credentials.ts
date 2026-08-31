import AdbWebCredentialStore from "@yume-chan/adb-credential-web";
import { adbGeneratePublicKey } from "@yume-chan/adb";
import type { AdbCredentialStore, AdbPrivateKey } from "@yume-chan/adb";

/**
 * ADB host credential handling.
 *
 * KNOWN DEVIATION FROM THE DESIGN
 * -------------------------------
 * The design calls for the ADB private key to be encrypted at rest with
 * WebAuthn PRF (`TangoPrfStorage` / `AdbWebCryptoCredentialManager`). Those
 * exist only in Tango 3.0.0-beta; the pinned stable line
 * (`@yume-chan/adb-credential-web@2.1.0`) provides a single store that keeps an
 * unwrapped PKCS#8 key in IndexedDB.
 *
 * Rather than hand-roll crypto, 0.1 ships the plain store and is explicit about
 * it: the UI shows the credential's protection level, the public key is
 * recorded in every manifest so acquisitions remain attributable, and the key
 * can be rotated. Treat the workstation profile as sensitive until the store is
 * swapped for the PRF-backed one, which is a change confined to this file.
 */

const STORE_NAME_PREFIX = "webadb-forensics";

/** Identifies which workstation authorized a device, e.g. "Berlin-03". */
export function stationKeyName(station: string): string {
    return `${STORE_NAME_PREFIX}/${station}`;
}

export interface HostCredential {
    readonly store: AdbCredentialStore;
    /**
     * The host public key in `adbkey.pub` format: base64 of the ADB public key
     * blob, a space, then the key name. Recorded as `adb_host_public_key` in
     * `acquisition.json`, which is the field MVT's AndroidQF parser reads
     * (falling back to an `adb_host_key.pub` file).
     */
    readonly publicKey: string;
    readonly keyName: string;
    readonly protection: "indexeddb-plaintext";
}

/**
 * Wraps Tango's store so exactly one station key exists, instead of
 * accumulating a new key per `generateKey()` call.
 */
class StationCredentialStore implements AdbCredentialStore {
    readonly #inner: AdbWebCredentialStore;

    constructor(keyName: string) {
        this.#inner = new AdbWebCredentialStore(keyName);
    }

    async generateKey(): Promise<AdbPrivateKey> {
        return await this.#inner.generateKey();
    }

    iterateKeys(): AsyncGenerator<AdbPrivateKey, void, void> {
        return this.#inner.iterateKeys();
    }

    /** Returns the existing key, generating one only when the store is empty. */
    async ensureKey(): Promise<AdbPrivateKey> {
        for await (const key of this.iterateKeys()) {
            return key;
        }
        return await this.generateKey();
    }
}

function toBase64(bytes: Uint8Array): string {
    let binary = "";
    // Chunked to stay well clear of the argument-count limit on spread.
    const chunkSize = 0x8000;
    for (let offset = 0; offset < bytes.length; offset += chunkSize) {
        binary += String.fromCharCode(...bytes.subarray(offset, offset + chunkSize));
    }
    return btoa(binary);
}

export async function openHostCredential(station: string): Promise<HostCredential> {
    const keyName = stationKeyName(station);
    const store = new StationCredentialStore(keyName);
    const privateKey = await store.ensureKey();

    const publicKeyBlob = adbGeneratePublicKey(privateKey.buffer);

    return {
        store,
        publicKey: `${toBase64(publicKeyBlob)} ${privateKey.name ?? keyName}`,
        keyName,
        protection: "indexeddb-plaintext",
    };
}

/**
 * Deletes the stored key. The device will show the authorization prompt again
 * on next connection, and previously granted trust becomes unusable.
 */
export async function rotateHostCredential(): Promise<void> {
    await new Promise<void>((resolve, reject) => {
        // Tango owns this database; deleting it is the only supported reset.
        const request = indexedDB.deleteDatabase("Tango");
        request.onsuccess = () => resolve();
        request.onerror = () => reject(request.error);
        request.onblocked = () =>
            reject(
                new Error(
                    "Credential database is in use. Close other tabs of this app and retry.",
                ),
            );
    });
}
