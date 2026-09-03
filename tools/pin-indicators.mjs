#!/usr/bin/env node
/**
 * Pins a snapshot of mvt-indicators into `web/public/indicators/`.
 *
 * Run at build-preparation time, never at runtime. The application must not
 * reach a third-party origin while examining a seized device, and an indicator
 * set that changed silently between two runs could not be cited in a report.
 * Pinning makes the set a reviewable, hash-verified part of this repository.
 *
 * Bundles are fetched by commit SHA rather than by branch, so re-running this
 * with the same `--commit` reproduces byte-identical output. The SHA-256 of each
 * bundle is written into `index.json`, and the loader refuses any bundle whose
 * content does not match — a modified indicator set would silently change what
 * the tool detects.
 *
 * Upstream is MIT licensed. Its LICENSE is copied alongside the bundles, which
 * that licence requires and which also records where this data came from.
 *
 *   node tools/pin-indicators.mjs                     # pin current upstream HEAD
 *   node tools/pin-indicators.mjs --commit <sha>      # pin a specific commit
 *   node tools/pin-indicators.mjs --verify            # check the existing snapshot
 */

import { createHash } from "node:crypto";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const REPOSITORY = "mvt-project/mvt-indicators";
const UPSTREAM = `https://github.com/${REPOSITORY}`;
const API = `https://api.github.com/repos/${REPOSITORY}`;
const RAW = `https://raw.githubusercontent.com/${REPOSITORY}`;

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const OUTPUT_DIRECTORY = join(ROOT, "web", "public", "indicators");
const INDEX_FILE = join(OUTPUT_DIRECTORY, "index.json");

function sha256(text) {
    return createHash("sha256").update(text, "utf8").digest("hex");
}

async function getJson(url) {
    const response = await fetch(url, {
        headers: {
            Accept: "application/vnd.github+json",
            "User-Agent": "webadb-forensics-pin-indicators",
        },
    });
    if (!response.ok) {
        throw new Error(`GET ${url} failed: HTTP ${response.status}`);
    }
    return response.json();
}

async function getText(url) {
    const response = await fetch(url, {
        headers: { "User-Agent": "webadb-forensics-pin-indicators" },
    });
    if (!response.ok) {
        throw new Error(`GET ${url} failed: HTTP ${response.status}`);
    }
    return response.text();
}

/** Counts indicators per type, so the index states what each bundle contributes. */
function summarise(content, path) {
    let bundle;
    try {
        bundle = JSON.parse(content);
    } catch (error) {
        throw new Error(`${path} is not valid JSON: ${error.message}`);
    }

    const objects = Array.isArray(bundle?.objects) ? bundle.objects : [];
    const indicators = objects.filter((object) => object?.type === "indicator");

    // Collection names come from the malware and report objects the indicators
    // are attributed to; they are what the UI shows as the authority for a match.
    const collections = objects
        .filter((object) => object?.type === "malware" || object?.type === "report")
        .map((object) => object?.name)
        .filter((name) => typeof name === "string" && name !== "");

    return {
        indicators: indicators.length,
        collections: [...new Set(collections)].sort(),
    };
}

async function resolveCommit(requested) {
    if (requested !== undefined) {
        // Confirm it exists and is a full SHA, so the snapshot cannot be pinned
        // to something ambiguous.
        const commit = await getJson(`${API}/commits/${requested}`);
        return commit.sha;
    }
    const commits = await getJson(`${API}/commits?per_page=1`);
    if (!Array.isArray(commits) || commits.length === 0) {
        throw new Error("Upstream returned no commits.");
    }
    return commits[0].sha;
}

async function listBundlePaths(commit) {
    const tree = await getJson(`${API}/git/trees/${commit}?recursive=1`);
    if (tree.truncated === true) {
        throw new Error(
            "Upstream tree listing was truncated, so the bundle list would be " +
                "incomplete. Pin by cloning instead of by API.",
        );
    }

    return tree.tree
        .filter((entry) => entry.type === "blob" && entry.path.endsWith(".stix2"))
        .map((entry) => entry.path)
        .sort();
}

async function pin(commit) {
    const paths = await listBundlePaths(commit);
    if (paths.length === 0) {
        throw new Error("No .stix2 bundles found upstream; refusing to write an empty snapshot.");
    }

    console.log(`Pinning ${paths.length} bundles from ${REPOSITORY}@${commit.slice(0, 12)}`);

    // Rebuilt rather than merged, so a bundle withdrawn upstream disappears here
    // too instead of lingering as a stale detection.
    await rm(OUTPUT_DIRECTORY, { recursive: true, force: true });
    await mkdir(OUTPUT_DIRECTORY, { recursive: true });

    const bundles = [];
    let totalIndicators = 0;

    for (const path of paths) {
        const content = await getText(`${RAW}/${commit}/${path}`);
        const summary = summarise(content, path);

        const destination = join(OUTPUT_DIRECTORY, path);
        await mkdir(dirname(destination), { recursive: true });
        await writeFile(destination, content, "utf8");

        const digest = sha256(content);
        bundles.push({
            // The upstream path is kept verbatim as the filename: it names the
            // report the indicators were published with, which is exactly the
            // provenance an examiner needs when citing a match.
            filename: path,
            sha256: digest,
            indicators: summary.indicators,
            collections: summary.collections,
            description: summary.collections.join(", "),
        });

        totalIndicators += summary.indicators;
        console.log(`  ${path}  ${summary.indicators} indicators  ${digest.slice(0, 12)}`);
    }

    const license = await getText(`${RAW}/${commit}/LICENSE`);
    await writeFile(join(OUTPUT_DIRECTORY, "LICENSE"), license, "utf8");

    const index = {
        pinned_at: new Date().toISOString(),
        upstream: UPSTREAM,
        commit,
        license: "MIT",
        license_file: "LICENSE",
        note:
            "Pinned snapshot of third-party indicator data, fetched at build " +
            "preparation time and served from this origin. The application makes " +
            "no network request to any third party at run time.",
        total_indicators: totalIndicators,
        bundles,
    };

    await writeFile(INDEX_FILE, `${JSON.stringify(index, undefined, 2)}\n`, "utf8");

    console.log(
        `\nWrote ${bundles.length} bundles, ${totalIndicators} indicators, to ` +
            `web/public/indicators/`,
    );
    console.log(`Pinned commit: ${commit}`);
}

/**
 * Re-hashes the snapshot on disk against its own index.
 *
 * The same check the loader performs in the browser, available in CI so a
 * corrupted or hand-edited snapshot fails the build rather than silently
 * changing what the tool detects.
 */
async function verify() {
    let index;
    try {
        index = JSON.parse(await readFile(INDEX_FILE, "utf8"));
    } catch (error) {
        throw new Error(
            `No readable snapshot at web/public/indicators/index.json (${error.message}). ` +
                `Run this script without --verify to create one.`,
        );
    }

    const problems = [];
    let checked = 0;

    for (const entry of index.bundles) {
        let content;
        try {
            content = await readFile(join(OUTPUT_DIRECTORY, entry.filename), "utf8");
        } catch {
            problems.push(`${entry.filename}: listed in index.json but missing from disk`);
            continue;
        }

        const digest = sha256(content);
        if (digest !== entry.sha256) {
            problems.push(
                `${entry.filename}: expected ${entry.sha256}, got ${digest}`,
            );
        }
        checked += 1;
    }

    if (problems.length > 0) {
        console.error(`Snapshot verification FAILED (${problems.length} problems):`);
        for (const problem of problems) {
            console.error(`  ${problem}`);
        }
        process.exitCode = 1;
        return;
    }

    console.log(
        `Snapshot verified: ${checked} bundles, ${index.total_indicators} indicators, ` +
            `pinned from ${index.upstream}@${String(index.commit).slice(0, 12)}`,
    );
}

const args = process.argv.slice(2);

if (args.includes("--verify")) {
    await verify();
} else {
    const commitFlag = args.indexOf("--commit");
    const requested = commitFlag >= 0 ? args[commitFlag + 1] : undefined;
    if (commitFlag >= 0 && (requested === undefined || requested.startsWith("--"))) {
        console.error("--commit requires a SHA");
        process.exit(1);
    }
    await pin(await resolveCommit(requested));
}
