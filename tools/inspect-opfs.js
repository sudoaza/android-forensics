/**
 * Inspects the OPFS evidence spool from outside the app.
 *
 * Evaluated in the page by `tools/cdp.mjs evalfile`. Real-device runs are the
 * only way to exercise the spool at full scale, and this reads it independently
 * of the app's own code paths so a manifest can be cross-checked against what is
 * actually on disk.
 *
 * Reports, per acquisition: every file with its size, whether each manifest
 * entry is present and its recorded size matches the bytes readable, and any
 * file present without a manifest entry.
 */
(async () => {
    const root = await navigator.storage.getDirectory();
    const acquisitions = await root.getDirectoryHandle("acquisitions");
    const runs = [];

    for await (const [id, dir] of acquisitions.entries()) {
        if (dir.kind !== "directory") continue;

        const files = [];
        const walk = async (handle, prefix) => {
            for await (const [name, child] of handle.entries()) {
                const path = prefix === "" ? name : `${prefix}/${name}`;
                if (child.kind === "directory") await walk(child, path);
                else files.push({ path, size: (await child.getFile()).size });
            }
        };
        await walk(dir, "");
        files.sort((a, b) => b.size - a.size);

        const open = async (path) => {
            const parts = path.split("/");
            let handle = dir;
            for (const part of parts.slice(0, -1)) handle = await handle.getDirectoryHandle(part);
            return await (await handle.getFileHandle(parts.at(-1))).getFile();
        };

        let manifest = {};
        const mismatches = [];
        try {
            manifest = JSON.parse(await (await open("manifest.sha256.json")).text());
        } catch (error) {
            mismatches.push({ path: "manifest.sha256.json", reason: String(error) });
        }

        // Read every byte rather than trusting File.size, so a truncated or
        // unreadable artifact is caught here rather than at export time.
        for (const [path, entry] of Object.entries(manifest)) {
            try {
                const reader = (await open(path)).stream().getReader();
                let read = 0;
                for (;;) {
                    const chunk = await reader.read();
                    if (chunk.done) break;
                    read += chunk.value.byteLength;
                }
                if (read !== entry.size) {
                    mismatches.push({ path, reason: `read ${read} != manifest ${entry.size}` });
                }
            } catch (error) {
                mismatches.push({ path, reason: String(error) });
            }
        }

        const onDisk = new Set(files.map((f) => f.path));
        runs.push({
            id,
            fileCount: files.length,
            totalBytes: files.reduce((sum, f) => sum + f.size, 0),
            manifestEntries: Object.keys(manifest).length,
            missingFromDisk: Object.keys(manifest).filter((p) => !onDisk.has(p)),
            // manifest.sha256.json cannot contain its own hash, so it is the one
            // expected member of this list.
            absentFromManifest: [...onDisk].filter((p) => manifest[p] === undefined),
            mismatches,
            largest: files.slice(0, 10),
        });
    }

    const estimate = await navigator.storage.estimate();
    return JSON.stringify(
        { quotaMB: Math.round(estimate.quota / 1e6), usageMB: Math.round(estimate.usage / 1e6), runs },
        null,
        2,
    );
})()
