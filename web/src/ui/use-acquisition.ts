import { useCallback, useEffect, useRef, useState } from "react";

import type { AdbClient, DeviceHandle } from "../adb/client.js";
import { TangoConnector } from "../adb/tango.js";
import { toAcquisitionError } from "../adb/errors.js";
import {
    buildDeviceContext,
    type DeviceContext,
} from "../acquisition/device-context.js";
import {
    AcquisitionEngine,
    type AcquisitionProgress,
} from "../acquisition/engine.js";
import type { AcquisitionSummary } from "../acquisition/manifest.js";
import type { ProfileId } from "../acquisition/profiles.js";
import type { EvidenceStore } from "../evidence/store.js";

export type Screen = "connect" | "preflight" | "acquiring" | "complete";

export interface CaseDetails {
    caseId: string;
    examiner: string;
    station: string;
}

interface State {
    screen: Screen;
    connector: TangoConnector | undefined;
    /**
     * `undefined` until the capability check completes. The UI must not render
     * an "unsupported" verdict before it is known, or every load flashes a
     * false negative at the examiner.
     */
    supported: boolean | undefined;
    /** Devices already authorized to this origin, found without a chooser. */
    knownDevices: readonly DeviceHandle[];
    client: AdbClient | undefined;
    device: DeviceContext | undefined;
    busy: string | undefined;
    error: string | undefined;
    progress: AcquisitionProgress | undefined;
    outcome: { summary: AcquisitionSummary; store: EvidenceStore } | undefined;
}

const STATION_STORAGE_KEY = "webadb-forensics.station";

export function useAcquisition() {
    const [state, setState] = useState<State>({
        screen: "connect",
        connector: undefined,
        supported: undefined,
        knownDevices: [],
        client: undefined,
        device: undefined,
        busy: undefined,
        error: undefined,
        progress: undefined,
        outcome: undefined,
    });

    const [caseDetails, setCaseDetails] = useState<CaseDetails>(() => ({
        caseId: "",
        examiner: "",
        station: localStorage.getItem(STATION_STORAGE_KEY) ?? "station-01",
    }));

    const engineRef = useRef<AcquisitionEngine | undefined>(undefined);

    useEffect(() => {
        localStorage.setItem(STATION_STORAGE_KEY, caseDetails.station);
    }, [caseDetails.station]);

    // The credential is keyed by station, so the connector is rebuilt when the
    // station name changes; the ADB key identifies the workstation.
    useEffect(() => {
        let cancelled = false;

        void (async () => {
            try {
                const connector = await TangoConnector.create(caseDetails.station);
                const supported = connector.isSupported();
                const knownDevices = supported ? await connector.listDevices() : [];

                if (!cancelled) {
                    setState((previous) => ({
                        ...previous,
                        connector,
                        supported,
                        knownDevices,
                    }));
                }
            } catch (error) {
                if (!cancelled) {
                    setState((previous) => ({
                        ...previous,
                        supported: false,
                        error: toAcquisitionError(error).message,
                    }));
                }
            }
        })();

        return () => {
            cancelled = true;
        };
    }, [caseDetails.station]);

    /** Preflight runs immediately after connect: no profile choice without device facts. */
    const connectTo = useCallback(async (handle: DeviceHandle) => {
        setState((previous) => ({
            ...previous,
            busy: "Waiting for authorization on the device…",
            error: undefined,
        }));

        try {
            const client = await handle.connect();

            setState((previous) => ({ ...previous, busy: "Reading device state…" }));
            const device = await buildDeviceContext(client);

            setState((previous) => ({
                ...previous,
                client,
                device,
                screen: "preflight",
                busy: undefined,
            }));
        } catch (error) {
            setState((previous) => ({
                ...previous,
                busy: undefined,
                error: toAcquisitionError(error).message,
            }));
        }
    }, []);

    const requestDevice = useCallback(async () => {
        const connector = state.connector;
        if (connector === undefined) {
            return;
        }

        try {
            // A device authorized earlier in this browser profile is already
            // accessible, so reuse it rather than making the examiner re-pick it
            // from the chooser on every run.
            const known = await connector.listDevices();
            const handle = known.length === 1 ? known[0] : await connector.requestDevice();
            if (handle === undefined) {
                return;
            }
            await connectTo(handle);
        } catch (error) {
            setState((previous) => ({
                ...previous,
                error: toAcquisitionError(error).message,
            }));
        }
    }, [state.connector, connectTo]);

    const startAcquisition = useCallback(
        async (profile: ProfileId) => {
            const { client, device, connector } = state;
            if (client === undefined || device === undefined || connector === undefined) {
                return;
            }

            const engine = new AcquisitionEngine({
                client,
                device,
                profile,
                station: caseDetails.station,
                ...(caseDetails.caseId === "" ? {} : { caseId: caseDetails.caseId }),
                ...(caseDetails.examiner === "" ? {} : { examiner: caseDetails.examiner }),
                hostPublicKey: connector.credential.publicKey,
                credentialProtection: connector.credential.protection,
            });
            engineRef.current = engine;

            const unsubscribe = engine.onProgress((progress) => {
                setState((previous) => ({ ...previous, progress }));
            });

            setState((previous) => ({
                ...previous,
                screen: "acquiring",
                progress: engine.progress,
                error: undefined,
            }));

            try {
                const outcome = await engine.run();
                setState((previous) => ({
                    ...previous,
                    screen: "complete",
                    outcome,
                    progress: engine.progress,
                }));
            } catch (error) {
                // The run failed after artifacts were already spooled and
                // verified (typically an OPFS quota failure while writing the
                // manifest). A synthetic summary is built from whatever the
                // engine recorded so the examiner can still package and export
                // the evidence; losing access to it here would be far worse
                // than an incomplete manifest.
                const partial = engine.partialOutcome();
                setState((previous) => ({
                    ...previous,
                    screen: "complete",
                    ...(partial === undefined ? {} : { outcome: partial }),
                    progress: engine.progress,
                    error: toAcquisitionError(error).message,
                }));
            } finally {
                unsubscribe();
            }
        },
        [state, caseDetails],
    );

    const cancel = useCallback(() => {
        engineRef.current?.cancel();
    }, []);

    /**
     * Closes the USB connection.
     *
     * `outcome` is deliberately preserved so the examiner can still export
     * evidence after unplugging the device — the acquisition is already on
     * local disk and does not need the phone. It is cleared only when a new
     * acquisition starts.
     */
    const disconnect = useCallback(async () => {
        await state.client?.close();
        setState((previous) => ({
            ...previous,
            client: undefined,
            device: undefined,
            screen: previous.outcome === undefined ? "connect" : previous.screen,
        }));
    }, [state.client]);

    /** Returns to the connect screen, abandoning the reference to the last run. */
    const reset = useCallback(async () => {
        await state.client?.close();
        setState((previous) => ({
            ...previous,
            client: undefined,
            device: undefined,
            screen: "connect",
            progress: undefined,
            outcome: undefined,
            error: undefined,
        }));
    }, [state.client]);

    // A mid-acquisition unplug must surface immediately rather than as a stall.
    useEffect(() => {
        const client = state.client;
        if (client === undefined) {
            return;
        }

        let active = true;
        void client.disconnected.then(() => {
            if (active) {
                engineRef.current?.cancel("Device disconnected");
                setState((previous) => ({
                    ...previous,
                    error:
                        previous.screen === "acquiring"
                            ? "The device was disconnected during acquisition. " +
                              "Completed artifacts are preserved."
                            : "The device was disconnected.",
                }));
            }
        });

        return () => {
            active = false;
        };
    }, [state.client]);

    // Guards against closing the tab mid-acquisition, which would abort every
    // in-flight transfer.
    useEffect(() => {
        if (state.screen !== "acquiring") {
            return;
        }

        const onBeforeUnload = (event: BeforeUnloadEvent): void => {
            event.preventDefault();
        };
        window.addEventListener("beforeunload", onBeforeUnload);
        return () => window.removeEventListener("beforeunload", onBeforeUnload);
    }, [state.screen]);

    return {
        ...state,
        caseDetails,
        setCaseDetails,
        requestDevice,
        connectTo,
        startAcquisition,
        cancel,
        disconnect,
        reset,
    };
}
