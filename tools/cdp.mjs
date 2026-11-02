#!/usr/bin/env node
import { readFile } from "node:fs/promises";

/**
 * CDP driver for real-device testing.
 *
 * WebUSB cannot be automated through normal page interaction: `requestDevice()`
 * opens a native chooser that lives outside the page. The Chrome DevTools
 * Protocol `DeviceAccess` domain exists for exactly this case — it reports the
 * prompt and lets a client pick a device programmatically.
 *
 * Chromium is kept running between invocations so device authorization and
 * acquisition state persist across commands.
 *
 * Usage:
 *   node tools/cdp.mjs state                 dump app state + console log
 *   node tools/cdp.mjs navigate <url>
 *   node tools/cdp.mjs connect               approve USB chooser + connect
 *   node tools/cdp.mjs click "<text>"        click a button by its text
 *   node tools/cdp.mjs eval "<expression>"
 *   node tools/cdp.mjs evalfile <path>       evaluate a script file
 *   node tools/cdp.mjs download <dir>        export the ZIP to <dir>
 *   node tools/cdp.mjs watch <seconds>       poll acquisition progress
 */

const ENDPOINT = process.env.CDP_URL ?? "http://127.0.0.1:9222";

/** Step tracing on stderr, so a hang is attributable to a specific CDP call. */
function trace(...parts) {
    process.stderr.write(`[cdp] ${parts.join(" ")}\n`);
}

let nextId = 1;
const pending = new Map();
const events = [];
const listeners = new Set();

function send(socket, method, params, sessionId) {
    const id = nextId++;
    const message = { id, method, params: params ?? {} };
    if (sessionId !== undefined) {
        message.sessionId = sessionId;
    }
    trace("->", method);
    socket.send(JSON.stringify(message));
    return new Promise((resolve, reject) => {
        pending.set(id, { resolve, reject });
        setTimeout(() => {
            if (pending.delete(id)) {
                reject(new Error(`CDP timeout: ${method}`));
            }
        }, 120_000);
    });
}

function onEvent(predicate, timeoutMs) {
    // Check already-buffered events first, so a prompt that arrived while we
    // were mid-command is not missed.
    const existing = events.find(predicate);
    if (existing !== undefined) {
        return Promise.resolve(existing);
    }
    return new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
            listeners.delete(listener);
            reject(new Error("timeout waiting for CDP event"));
        }, timeoutMs);
        const listener = (event) => {
            if (predicate(event)) {
                clearTimeout(timer);
                listeners.delete(listener);
                resolve(event);
            }
        };
        listeners.add(listener);
    });
}

async function connectBrowser() {
    trace("fetching", `${ENDPOINT}/json/version`);
    const response = await fetch(`${ENDPOINT}/json/version`);
    const { webSocketDebuggerUrl } = await response.json();

    trace("opening websocket");
    const socket = new WebSocket(webSocketDebuggerUrl);
    await new Promise((resolve, reject) => {
        socket.addEventListener("open", resolve, { once: true });
        socket.addEventListener("error", reject, { once: true });
    });
    trace("websocket open");

    socket.addEventListener("message", (raw) => {
        const message = JSON.parse(raw.data);
        if (message.id !== undefined) {
            const handler = pending.get(message.id);
            if (handler !== undefined) {
                pending.delete(message.id);
                if (message.error !== undefined) {
                    handler.reject(new Error(`${message.error.message} (${message.method ?? ""})`));
                } else {
                    handler.resolve(message.result);
                }
            }
            return;
        }
        events.push(message);
        for (const listener of [...listeners]) {
            listener(message);
        }
    });

    return socket;
}

/** Attaches to the first page target, creating one if necessary. */
async function attachPage(socket, url) {
    const { targetInfos } = await send(socket, "Target.getTargets");
    trace(
        "targets:",
        targetInfos.map((info) => `${info.type}:${info.url.slice(0, 50)}`).join(", "),
    );
    let target = targetInfos.find(
        (info) => info.type === "page" && !info.url.startsWith("devtools://"),
    );

    if (target === undefined) {
        const created = await send(socket, "Target.createTarget", {
            url: url ?? "about:blank",
        });
        target = { targetId: created.targetId };
    }

    const { sessionId } = await send(socket, "Target.attachToTarget", {
        targetId: target.targetId,
        flatten: true,
    });
    trace("attached session", sessionId);

    await send(socket, "Runtime.enable", {}, sessionId);
    await send(socket, "Log.enable", {}, sessionId);
    trace("session ready");

    return sessionId;
}

async function evaluate(socket, sessionId, expression, options = {}) {
    const result = await send(
        socket,
        "Runtime.evaluate",
        {
            expression,
            awaitPromise: options.awaitPromise ?? true,
            returnByValue: true,
            userGesture: options.userGesture ?? false,
        },
        sessionId,
    );

    if (result.exceptionDetails !== undefined) {
        const detail =
            result.exceptionDetails.exception?.description ??
            result.exceptionDetails.text ??
            "unknown error";
        throw new Error(`page exception: ${detail}`);
    }
    return result.result.value;
}

/** Serializes what the examiner would see, so assertions run on real DOM. */
const STATE_EXPRESSION = `(() => {
    const text = (selector) =>
        [...document.querySelectorAll(selector)].map((node) => node.textContent.trim());
    const rows = {};
    for (const list of document.querySelectorAll("dl.facts")) {
        const terms = [...list.querySelectorAll("dt")];
        const definitions = [...list.querySelectorAll("dd")];
        terms.forEach((term, index) => {
            rows[term.textContent.trim()] = definitions[index]?.textContent.trim() ?? null;
        });
    }
    return {
        headings: text("h1, h2"),
        facts: rows,
        buttons: [...document.querySelectorAll("button")].map((b) => ({
            label: b.textContent.trim().slice(0, 60),
            disabled: b.disabled,
        })),
        notices: text(".notice"),
        modules: [...document.querySelectorAll(".module")].map((m) => ({
            status: [...m.classList].filter((c) => c !== "module").join(" "),
            text: m.textContent.trim().replace(/\\s+/g, " ").slice(0, 120),
        })),
        totals: [...document.querySelectorAll(".totals > div")].map((t) =>
            t.textContent.trim().replace(/\\s+/g, " "),
        ),
        errors: text(".errors > div").slice(0, 40),
    };
})()`;

function consoleLog() {
    return events
        .filter(
            (event) =>
                event.method === "Runtime.consoleAPICalled" ||
                event.method === "Log.entryAdded" ||
                event.method === "Runtime.exceptionThrown",
        )
        .map((event) => {
            if (event.method === "Log.entryAdded") {
                return `[${event.params.entry.level}] ${event.params.entry.text}`;
            }
            if (event.method === "Runtime.exceptionThrown") {
                const details = event.params.exceptionDetails;
                return `[exception] ${details.exception?.description ?? details.text}`;
            }
            const args = event.params.args
                .map((arg) => arg.value ?? arg.description ?? arg.type)
                .join(" ");
            return `[${event.params.type}] ${args}`;
        });
}

async function main() {
    const [command, ...args] = process.argv.slice(2);
    const socket = await connectBrowser();

    try {
        const sessionId = await attachPage(socket, args[0]);

        switch (command) {
            case "navigate": {
                await send(socket, "Page.enable", {}, sessionId);
                await send(socket, "Page.navigate", { url: args[0] }, sessionId);
                // Settle: the capability check runs on mount.
                await new Promise((resolve) => setTimeout(resolve, 2500));
                console.log(JSON.stringify(await evaluate(socket, sessionId, STATE_EXPRESSION), null, 2));
                break;
            }

            case "connect": {
                // The chooser must be armed BEFORE the click that opens it.
                await send(socket, "DeviceAccess.enable", {}, sessionId);

                const prompted = onEvent(
                    (event) => event.method === "DeviceAccess.deviceRequestPrompted",
                    60_000,
                );

                // userGesture is required: requestDevice() rejects without one.
                await evaluate(
                    socket,
                    sessionId,
                    `(() => {
                        const button = [...document.querySelectorAll("button")]
                            .find((b) => b.textContent.includes("Connect Android device"));
                        if (!button) throw new Error("connect button not found");
                        button.click();
                        return true;
                    })()`,
                    { userGesture: true, awaitPromise: false },
                );

                const event = await prompted;
                const devices = event.params.devices ?? [];
                console.log("chooser offered:", JSON.stringify(devices));

                if (devices.length === 0) {
                    await send(socket, "DeviceAccess.cancelPrompt", { id: event.params.id }, sessionId);
                    throw new Error("chooser listed no devices — check udev/ACL access");
                }

                await send(
                    socket,
                    "DeviceAccess.selectPrompt",
                    { id: event.params.id, deviceId: devices[0].id },
                    sessionId,
                );
                console.log("selected:", devices[0].name);
                break;
            }

            case "click": {
                await evaluate(
                    socket,
                    sessionId,
                    `(() => {
                        const wanted = ${JSON.stringify(args[0])};
                        const button = [...document.querySelectorAll("button")]
                            .find((b) => b.textContent.includes(wanted));
                        if (!button) {
                            throw new Error("no button matching: " + wanted + " — have: " +
                                [...document.querySelectorAll("button")]
                                    .map((b) => b.textContent.trim()).join(" | "));
                        }
                        button.click();
                        return true;
                    })()`,
                    { userGesture: true, awaitPromise: false },
                );
                console.log("clicked:", args[0]);
                break;
            }

            case "state": {
                const state = await evaluate(socket, sessionId, STATE_EXPRESSION);
                console.log(JSON.stringify(state, null, 2));
                const logs = consoleLog();
                if (logs.length > 0) {
                    console.log("\n=== console ===");
                    console.log(logs.join("\n"));
                }
                break;
            }

            case "eval": {
                console.log(JSON.stringify(await evaluate(socket, sessionId, args[0]), null, 2));
                break;
            }

            case "evalfile": {
                const source = await readFile(args[0], "utf8");
                const result = await evaluate(socket, sessionId, source);
                console.log(typeof result === "string" ? result : JSON.stringify(result, null, 2));
                break;
            }

            case "download": {
                const directory = args[0];
                await send(socket, "Browser.setDownloadBehavior", {
                    behavior: "allow",
                    downloadPath: directory,
                    eventsEnabled: true,
                });

                // showSaveFilePicker opens a native dialog that CDP cannot drive,
                // so force the blob fallback to exercise the export end to end.
                await evaluate(socket, sessionId, "delete globalThis.showSaveFilePicker; true");

                const finished = onEvent(
                    (event) =>
                        event.method === "Browser.downloadProgress" &&
                        (event.params.state === "completed" || event.params.state === "canceled"),
                    600_000,
                );

                await evaluate(
                    socket,
                    sessionId,
                    `(() => {
                        const button = [...document.querySelectorAll("button")]
                            .find((b) => b.textContent.includes("Download acquisition ZIP"));
                        if (!button) throw new Error("download button not found");
                        button.click();
                        return true;
                    })()`,
                    { userGesture: true, awaitPromise: false },
                );

                const event = await finished;
                console.log(JSON.stringify(event.params));
                break;
            }

            case "watch": {
                const seconds = Number.parseInt(args[0] ?? "30", 10);
                const deadline = Date.now() + seconds * 1000;
                let previous = "";
                while (Date.now() < deadline) {
                    const state = await evaluate(
                        socket,
                        sessionId,
                        `(() => {
                            const running = [...document.querySelectorAll(".module.running")]
                                .map((m) => m.textContent.trim().replace(/\\s+/g, " "));
                            const done = document.querySelectorAll(
                                ".module.complete, .module.partial, .module.failed, .module.skipped",
                            ).length;
                            const total = document.querySelectorAll(".module").length;
                            const totals = [...document.querySelectorAll(".totals > div")]
                                .map((t) => t.textContent.trim().replace(/\\s+/g, " "));
                            const heading = document.querySelector("h2")?.textContent.trim();
                            return JSON.stringify({ heading, done, total, running, totals });
                        })()`,
                    );
                    if (state !== previous) {
                        console.log(`${new Date().toISOString()} ${state}`);
                        previous = state;
                    }
                    if (state.includes("Acquisition complete") || state.includes("Acquisition incomplete")) {
                        break;
                    }
                    await new Promise((resolve) => setTimeout(resolve, 1000));
                }
                break;
            }

            default:
                throw new Error(`unknown command: ${command}`);
        }
    } finally {
        socket.close();
    }
}

await main();
// The socket keeps event listeners alive, so exit explicitly rather than
// waiting for the event loop to drain.
process.exit(0);
