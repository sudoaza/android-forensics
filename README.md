# webadb-forensics

Zero-install Android forensic acquisition **and analysis** in the browser.
Chromium is the only software that touches the phone: no `adb` binary, no Android
SDK, no Python, no Node, no native daemon, no extension, no local agent — and no
separate analysis tool.

```
Open the page  →  plug in over USB  →  authorize on device  →  choose profile
→  acquire  →  SHA-256 while streaming  →  verify  →  analyse  →  download ZIP
```

The app is a static bundle. It can be hosted on GitHub Pages and has no backend.

## Status

0.1, pre-field-testing. **Not yet validated against physical devices** — see
[Verification status](#verification-status). Every layer typechecks, builds, and
passes unit tests, and the UI has been confirmed to load with a strict CSP.

## How it works

```
Android adbd
     │  USB
Chromium WebUSB
     │
Tango adapter          ← the only place @yume-chan/* types appear
     │
Acquisition engine     ← declarative modules, sequential, failure-isolated
     │
Evidence pipeline      ← stream → incremental SHA-256 → OPFS → re-read verify
     │
     ├── client-zip     → acquisition ZIP on the examiner's disk
     │
Analysis engine        ← rules as data + STIX2 indicators, in the same browser
     │
     └── analysis.json / analysis_alerts.csv / analysis_timeline.csv
```

## Analysis

Analysis is first-party and runs in the browser, over either the acquisition just
collected or an archive imported from elsewhere. It reports configuration
weaknesses, rooting and boot-state problems, and matches against STIX2 indicator
bundles.

### Rules are data, and the whole rule set is reported

Detection logic is expressed as rule records — a settings table, package lists,
thresholds — rather than as code, so the complete set of conditions checked can be
enumerated, displayed and diffed between runs.

Every report lists **every rule that was in force, including those that did not
fire**. Without that, a report showing no findings cannot be distinguished from a
report produced with an empty rule set.

The rules are a clean-room implementation. Heuristics were written from observable
device behaviour in our own wording; no MVT code is carried over, which keeps this
repository single-licensed. The severity vocabulary deliberately matches MVT's, so
an examiner moving between the two tools reads the levels the same way.

### Indicators come from disk, never from the network

STIX2 bundles reach the analysis two ways, both offline:

1. a **pinned snapshot** shipped as static assets under `indicators/`, served
   from the app's own origin — so the CSP is unchanged and it works air-gapped.
   `index.json` records each bundle's expected SHA-256 and the upstream commit;
   a bundle whose content does not match is refused rather than loaded.
2. a **file picker** for examiner-supplied bundles, which is how case-specific
   and embargoed indicators get used.

No indicator is ever fetched from a third party at run time. A workstation
examining a seized device should emit no network traffic, and an indicator set
that changes silently between runs cannot be cited in a report. Which bundles were
loaded, their hashes, and how many indicators each contributed are recorded in
`analysis.json`.

The snapshot currently pinned is **1617 indicators across 14 bundles** from
[mvt-indicators](https://github.com/mvt-project/mvt-indicators) (MIT, so bundling
is unencumbered; the licence ships alongside the data). Refresh or re-pin it with:

```bash
npm run indicators:pin                    # pin current upstream HEAD
npm run indicators:pin -- --commit <sha>  # pin a specific commit
npm run indicators:verify                 # re-hash the snapshot against its index
```

Bundles are fetched by commit SHA, so re-running with the same `--commit` produces
byte-identical output. `indicators:verify` runs in CI and gates the deploy: a
snapshot that has drifted from its own index would silently change what the
deployed tool detects.

Every pattern form in all 14 real bundles is interpreted — `domain-name`,
`ipv4-addr`, `file:hashes.sha256`, `file:path`, `file:name`, `email-addr`,
`app:id`, `app:cert.sha256`, `process:name`, `configuration-profile:id`. A test
parses the pinned snapshot and asserts **zero unsupported patterns**, cross-checked
against indicator counts computed independently by the pinning script, so it
cannot pass by parsing nothing. If upstream adopts a form this reader does not
implement, that test fails rather than the tool quietly losing detections.

Parsing an indicator is not the same as using it, so coverage is stated by where
each type is actually consumed:

| Indicator type | Count in snapshot | Consumed by |
| --- | --- | --- |
| `domain-name`, `ipv4-addr` | 1251 | `network` |
| `file:hashes.sha256` | 229 | `packages` (per-APK SHA-256) |
| `file:path`, `file:name` | 62 | `processes`, `packages` |
| `app:id` | 28 | `packages` |
| `app:cert.sha256` | 8 | `packages` |
| `process:name` | 2 | `processes` |
| `email-addr` | 36 | not yet consumed — no artifact collected carries addresses |
| `configuration-profile:id` | 1 | not applicable (iOS) |

The domain figure is why the `network` analyzer exists: without it, 77% of every
published bundle could never match anything, and "no indicator matches" would be
close to meaningless while still reading as authoritative.

### Network endpoints are matched by text scan, and the report says so

Domains are the bulk of every real indicator set, but Android does not expose a
connection history to `adb`. Rather than parse each `dumpsys` section — formats
that differ per service, per OEM and per version, each a parser able to silently
stop matching — hostnames and addresses are extracted by pattern from `logcat`,
the network `dumpsys` sections and `/proc/net/*`, then looked up.

Precision comes from the indicator set rather than from the extraction: an
arbitrary hostname is never reported, only one present in a loaded bundle. Against
all 1617 real indicators, a realistic log of Android framework chatter produces
zero findings, and version strings like `1.2.3.4` are not mistaken for addresses.

The cost is context, and each finding states it: a text match shows the endpoint
appears in an artifact, not which application contacted it, nor that a connection
succeeded. Every alert carries the artifact, line number and surrounding line so
an examiner can judge it.

### What the analysis refuses to imply

The report states its own limits, because silence about a missing check reads as a
passed check:

- an analyzer whose input was absent or unparseable is reported as
  `not-applicable` or `failed`, never as clean. Zero findings because we could not
  look must never render as zero findings because there was nothing there.
- with no indicators loaded, the absence of indicator matches is stated to carry
  no information.
- severity orders findings for review; it does not score the device.
- detection is name-, path- and hash-based. A renamed package, a relocated binary
  or a recompiled payload will not be identified, and a competently implemented
  implant leaves none of the traces examined here.

### Analysis output is derived data

Reports are written into the evidence store as new artifacts, marked
`derived: true`, alongside the collected evidence and never over it. They are
included in the archive and covered by its `hashes.csv`, so the archive is
re-planned after analysis rather than from a pre-analysis snapshot. "Discard local
copy" stays disabled until an export covers everything currently in the store.

Imported archives are treated as read-only: nothing is written back into an
archive that was already sealed with its own manifest. Before analysing one, every
entry's SHA-256 is recomputed and compared against its `hashes.csv` — findings
derived from an archive that no longer matches its manifest are not worth
computing, and an examiner has no device left to re-ask.

### Two independent hashes, without a server

The original design verified evidence by comparing a browser-computed SHA-256
against a server-computed one. With no backend, that guarantee is preserved
locally by hashing through two independent paths:

1. **write hash** — computed on bytes in flight from the device
2. **read hash** — computed by re-reading the persisted file from OPFS

Both must agree or the artifact is deleted and the failure recorded. This
detects storage corruption and truncation. It does **not** attest to what the
device reported — no client-side scheme can.

### Evidence never buffers in memory

An APK or bugreport can be hundreds of megabytes, so nothing is materialized:

```
ADB ReadableStream → hashing TransformStream → OPFS WritableStream
```

Back-pressure propagates from disk to the USB read. `crypto.subtle.digest` is
one-shot and cannot hash a stream, so SHA-256 is incremental via
`@noble/hashes`.

## Layout

```
web/src/
├── adb/            Tango isolation boundary
│   ├── client.ts       AdbClient interface — zero Tango types
│   ├── tango.ts        the only file importing @yume-chan/*
│   ├── credentials.ts  ADB host key + public key for the manifest
│   └── errors.ts       expected-refusal vs. transport-failure taxonomy
├── acquisition/
│   ├── engine.ts       sequential runner, per-module isolation
│   ├── declarative.ts  commandArtifact / commandGroup / fallback / pull
│   ├── profiles.ts     quick | standard | full
│   ├── manifest.ts     acquisition.json, MVT-compatible fields
│   ├── command-log.ts  every command, including the ones that failed
│   ├── clock.ts        host↔device offset, minimum-RTT
│   └── device-context.ts
├── modules/        the forensic probes themselves
├── analysis/       first-party analysis, no external tool
│   ├── engine.ts       sequential runner, per-analyzer isolation
│   ├── analyzer.ts     the Analyzer contract
│   ├── alerts.ts       five severities, rule identity, matched indicator
│   ├── source.ts       one read interface over OPFS or an imported ZIP
│   ├── zip-reader.ts   dependency-free random-access ZIP + CRC-32
│   ├── report.ts       analysis.json / alerts.csv / timeline.csv
│   ├── rules/          detection logic as data, not code
│   ├── analyzers/      getprop, root/mounts, settings, packages, processes, network
│   └── indicators/     STIX2 parsing, matching, bundle loading
├── evidence/       hasher, OPFS store, ZIP assembly
└── ui/             screens, plus the analysis view
```

## Adding a probe

Most modules are one declaration:

```ts
commandArtifact({
    id: "accessibility",
    label: "Accessibility services",
    command: ["dumpsys", "accessibility"],   // argv, never a shell string
    artifact: "security/accessibility.txt",
});
```

Add it to a profile in `acquisition/profiles.ts`. The engine handles hashing,
logging, verification, progress, cancellation and error classification.

**Commands are always argv arrays.** Tango's `splitCommand` does not strip quote
characters from the tokens it produces, so a shell-style string like
`logcat -b all '*:V'` reaches the device as a literal `'*:V'` *including the
quotes*, silently breaking the filterspec. Use `["sh", "-c", "…"]` when shell
semantics are genuinely needed.

## Adding a rule

Most detections are a data record, added to the relevant table in
`analysis/rules/`:

```ts
{
    id: "settings.package_verifier_disabled",
    scope: "global",
    key: "package_verifier_enable",
    expected: "1",
    level: "high",
    rationale:
        "Play Protect's install-time scan is off, so APKs install without " +
        "being checked against Google's known-malware set.",
    finding: "Package verification is disabled.",
}
```

`rationale` is not documentation: it is emitted into `analysis.json` for every
rule, fired or not, because a finding an examiner cannot explain to a court is not
useful.

A new artifact surface needs an analyzer, which declares the artifacts it reads
and the rules it can fire, then calls `ctx.examined(name)` for each artifact it
successfully parses. That call is what lets the engine separate "looked and found
nothing" from "could not look" — omitting it makes a clean device
indistinguishable from a parser failure.

## What gets collected

| Profile | Contents |
| --- | --- |
| **Connection test** | Versions, settings, boot state, service list, and a capped logcat tail. Nothing large is transferred. |
| **Quick** | Device state, settings, processes, services, security/network/scheduling dumpsys, root indicators, package inventory, logcat |
| **Standard** | Quick + third-party APKs, full dumpsys, readable diagnostic logs, temp directories, `bugreport.zip` |
| **Full** | Standard + system APKs |

**Connection test** exists because the failure modes worth ruling out first are
environmental: a charge-only cable, a missing udev rule, an unauthorized ADB key,
a competing `adb` server holding the interface. It proves the whole pipeline —
transport, collection, hashing, verification, export — against real hardware in
seconds, and still produces a complete, verified, MVT-shaped archive. Its logcat
is both tail-limited and byte-capped, since the uncapped dump reached 101 MB on a
real device.

Any artifact stopped by a size cap is marked `truncated` in
`manifest.sha256.json`, listed under `artifacts.truncated` in `acquisition.json`,
and flagged on the completion screen. The recorded digest still covers the stored
bytes exactly, so verification succeeds — but a capped artifact is not the whole
source, and nothing is allowed to imply otherwise.

Beyond AndroidQF, each of these is collected as its own file so a single surface
can be diffed across acquisitions: `appops`, `accessibility`, `device_policy`,
`role`, `notification`, `jobscheduler`, `alarm`, `connectivity`, `netpolicy`,
`usagestats`. These are where Android RAT and stalkerware persistence actually
lives.

No runtime estimates are shown anywhere. APK volume and bugreport generation
time vary by orders of magnitude across devices.

### Failure is forensic metadata

`/proc/kmsg → Permission denied` is a normal finding on a production build, not
a bug. Modules fail independently and record:

```json
{ "module": "system-logs", "status": "partial",
  "errors": [{ "artifact": "/proc/kmsg", "error": "Permission denied", "expected": true }] }
```

The error taxonomy separates *expected refusals* (recorded, acquisition
continues) from *transport failures* (acquisition stops, because everything after
it is untrustworthy). Under the legacy none-protocol shell there is no exit code
and stderr is merged into stdout, so refusal is inferred from output text — the
manifest records which protocol was used so this is auditable.

## Archive contents

```
acquisition.json      manifest, incl. adb_host_public_key (MVT reads this)
adb_host_key.pub      fallback MVT looks for
command.log           human-readable: START / EXIT / STDERR / ARTIFACT / SHA256
command.log.json      same data, machine-readable
manifest.sha256.json  per-artifact sha256 + size + timestamp
hashes.csv            AndroidQF format; always LAST, never hashes itself
getprop.txt  settings_*.txt  processes.txt  services.txt
packages.json  packages.txt  apks/
logcat.txt  logcat_old.txt  logcat_buffers.txt
dumpsys.txt  security/*  logs/*  tmp/*
root_binaries.json  bugreport.zip
analysis.json             findings, rule set, indicator provenance, limits
analysis_alerts.csv       findings, one row each
analysis_timeline.csv     findings that carry a device-reported event time
```

Every entry is nested under a single acquisition-id directory. This is not
cosmetic: MVT selects files with `fnmatch` patterns such as `*/getprop.txt`, and
because `*` matches `/` in `fnmatch`, the pattern requires at least one directory
component. A flat archive matches none of them and every module silently finds
nothing.

The three `analysis_*` files are present only once analysis has run, and are marked
`derived` — they are output, not device data.

`hashes.csv` covers every other entry and is emitted last, so it can include the
manifest, command log and analysis reports without hashing itself. Its paths stay
relative to the acquisition directory, so `sha256sum -c` works from the extracted
directory.

## Development

```bash
npm install
npm run dev         # https not required on localhost — it is a secure context
npm test
npm run typecheck
npm run build
```

Requires Chrome, Chromium, or Edge. The app refuses to run rather than degrade
in browsers without WebUSB or OPFS.

### Testing against a real device

WebUSB cannot be driven by ordinary page automation: `requestDevice()` opens a
native chooser outside the page. `tools/cdp.mjs` therefore drives Chromium over
the DevTools Protocol, whose `DeviceAccess` domain exists for exactly this case.

```bash
# Kill any adb server first — it claims the USB interface exclusively.
adb kill-server

npm run dev
chromium --remote-debugging-port=9222 --user-data-dir=/tmp/forensics-profile \
    http://localhost:5173/

node tools/cdp.mjs connect              # approve the chooser, connect
node tools/cdp.mjs click "Connection test"   # fastest end-to-end check
node tools/cdp.mjs watch 300            # poll progress
node tools/cdp.mjs download /tmp/out    # export the ZIP
node tools/cdp.mjs evalfile tools/inspect-opfs.js   # audit the spool
```

To verify the evidence chain independently of this codebase, recompute the
digests from the archive's own manifest with a host tool:

```bash
cd /tmp/out && unzip -q *.zip -d extracted && cd extracted/*/
tail -n +2 hashes.csv | sed 's/^\([a-f0-9]*\),"\(.*\)"$/\1  \2/' | sha256sum -c
```

### Cross-checking against MVT

MVT is no longer required, but corroboration by a separately implemented tool is
worth having. The archive keeps AndroidQF-compatible artifact names, so:

```bash
mvt-android check-androidqf <acquisition>.zip
```

The two will not agree exactly, and that is expected rather than a defect: the
rule sets are independent implementations, MVT reports on artifacts this collector
does not gather, and this analysis checks surfaces MVT does not. Disagreement is
information — a finding only one tool reports is worth understanding before it is
dismissed.

## Deployment

`.github/workflows/deploy.yml` publishes to GitHub Pages, gated on typecheck and
tests — a build that fails verification must never reach the URL examiners load.

No service worker, by design: a stale frontend whose acquisition semantics no
longer match the manifest it writes is worse than a slow load. Assets are
immutable and fingerprinted; `index.html` is not cached.

GitHub Pages cannot set response headers, so the CSP is delivered via a meta
tag. `frame-ancestors`, `X-Frame-Options`, `X-Content-Type-Options` and
`Referrer-Policy` are header-only and therefore **not enforced on Pages**;
`web/public/_headers` carries the full set for hosts that honour it.

## Known deviations from the design

These are deliberate and documented rather than silently skipped.

1. **ADB key is stored unencrypted.** The design calls for WebAuthn-PRF-encrypted
   key storage. That API exists only in Tango `3.0.0-beta`; this build pins the
   stable `2.6` line, whose credential store keeps an unwrapped PKCS#8 key in
   IndexedDB. Anyone with access to the browser profile can impersonate this
   workstation to a device that has authorized it. The UI states this plainly.
   Swapping it is a change confined to `adb/credentials.ts`.

2. **Acquisition runs on the main thread.** `navigator.usb` is not exposed to
   workers, so USB work cannot move off it. Hashing could, and has not yet.

3. **Evidence is stored locally.** With no backend this is unavoidable, and it
   inverts the original design's "do not persist forensic content locally" rule.
   Evidence lives in OPFS until exported, and can be discarded from the UI.

4. **Intrusion Logs** are reported as supported/unavailable/unknown but not
   collected — they need device interaction to decrypt.

5. **No on-device collector.** AndroidQF pushes a compiled ARM binary because
   shell utilities vary across OEMs. Deliberately out of scope for 0.1; note
   that AndroidQF's collector is under the MVT License 1.1 with a consensual-use
   restriction, so a clean-room implementation is required rather than a port.

6. **Analysis covers fewer surfaces than MVT.** The analyzers implemented are
   getprop/boot state, root binaries and mounts, settings, packages, processes and
   network endpoints. MVT additionally parses SMS, dumpsys
   `appops`/`accessibility`/`receivers`, `battery_daily`, and several bugreport
   sections structurally. Those artifacts are collected here and are in the
   archive; the `network` analyzer scans several of them for indicators, but none
   is parsed for structural heuristics yet. The report lists which analyzers ran,
   so an unexamined surface is visible rather than implied to be clean.

7. **STIX2 patterns are matched one comparison at a time.** Compound expressions
   (`AND`/`OR`/`FOLLOWEDBY`) are recorded as unsupported and shown in the UI
   rather than partially applied — a half-evaluated indicator would be worse than
   a declared gap. Measured against the pinned snapshot this currently costs
   nothing: all 1617 indicators across 14 real bundles are single comparisons. The
   gap would only appear if upstream published a compound pattern, and the
   snapshot test fails if that happens.

## Verification status

Verified:

- typecheck (strict, `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`)
- 162 unit tests: SHA-256 against NIST vectors and across chunk boundaries,
  `pm list` parsing, `hashes.csv` semantics, command-log rendering,
  stream-cleanup/truncation-detection contracts, size-cap exactness, root-indicator
  classification, and the connection-test profile's boundedness
- analysis specifically: end-to-end runs over synthetic compromised and clean
  archives asserting which rules fire and that a clean device produces none;
  analyzer isolation and the `failed` / `partial` / `not-applicable` distinction;
  ZIP reading with CRC-32 verification against archives built by a different
  implementation; `hashes.csv` verification including mismatch, missing and
  unlisted entries; STIX2 pattern parsing, attribution and provenance; indicator
  matching semantics (case sensitivity per type, 15-character process-name
  truncation, path prefix matching on segment boundaries); and that analysis
  reports end up inside the archive and under its `hashes.csv`
- the pinned indicator snapshot: all 14 real bundles parse, every pattern in them
  is interpreted, hashes match the index, and sample values match end to end
  through the public matcher API
- the network analyzer against the real 1617-indicator set: real indicator domains
  and their subdomains match, ordinary Android log noise produces zero findings,
  and ~12 MB of log lines is scanned in under a second (so a 101 MB logcat
  extrapolates to a few seconds rather than a hang)
- production build, and the app loading under the strict CSP with no violations
- Tango 2.6.3 API surface read from the installed `.d.ts` files, not from docs
- a code review pass focused on stream stalls and evidence integrity; six issues
  found and fixed (see below)
- **a real acquisition against a Xiaomi Redmi Note 9 Pro (Android 12, MIUI,
  locked bootloader, `shell_v2`)**: WebUSB connection, ADB handshake with an
  authorized key, Quick profile, 48 artifacts / 107 MB, streaming ZIP export, and
  cancellation mid-stream. Every artifact hash was then recomputed on the host
  with `sha256sum -c` from the archive's own `hashes.csv`: 48/48 matched, so the
  browser-side digests agree with an independent implementation across the whole
  chain. Four real bugs came out of this (see below).

Not yet verified — **still requires more devices or tooling**:

- the connection-test profile, the size cap, and the progress/elapsed UI have not
  yet been run against hardware: they are covered by unit tests and typecheck
  only, because the phone was disconnected when they were written
- **the analysis has never run against a real compromised device.** Its rules are
  exercised only by synthetic fixtures written alongside them, which proves the
  rules fire on the shapes we expect and not that those shapes match what a real
  implant leaves. This is the single largest gap.
- **no rule has been validated against a device with positive root indicators**,
  an unlocked bootloader, or a userdebug build; every hardware run so far was a
  stock locked device where the correct answer was "nothing"
- `mvt-android check-androidqf` acceptance of a produced archive, and a
  finding-by-finding comparison of its output against ours on the same archive
- APK pulls and `bugreport.zip` (Standard/Full profiles; only Quick has been run
  end to end on hardware)
- resume behaviour under a real mid-stream unplug (deliberate cancellation is
  verified; a physical disconnect is not)
- OEM command variability beyond Xiaomi/MIUI — Samsung, Motorola, OnePlus, Pixel
- `ps` output layouts beyond the ones the fallback chain was written for; the
  parser locates columns from the header, but only MIUI's has been seen
- devices with an unlocked bootloader, a root manager present, or a userdebug
  build, all of which should produce positive root indicators rather than the
  negative ones observed so far

The next milestone is validating the analysis against devices with known-positive
findings, then a finding-by-finding cross-check against MVT on the same archives,
then the rest of the device matrix.

### Findings from real-device testing

Behaviour that only appeared against physical hardware, recorded because none of
it is guessable from the specs:

- **`logcat -d -b all '*:V'` produced 101 MB on MIUI.** `logcat -g` reports
  ~121 MiB readable across the ring buffers, so this is legitimate, not a
  runaway stream. It confirms the streaming design was necessary: this artifact
  alone would defeat any buffer-in-memory approach. The buffer-size probe now
  runs *before* the dump so its size can be corroborated even if the dump is
  interrupted.
- **`new Response(stream).blob()` fails at scale.** On a 111 MB archive Chrome
  148 rejects with `TypeError: Failed to fetch`; draining the stream and passing
  the chunks to the `Blob` constructor succeeds. The fetch body path imposes
  limits the Streams API does not.
- **A shell round trip costs ~1s.** Anything per-package is therefore a
  multi-minute cost on a 443-package device, which is what made the redundant
  `pm path` calls worth eliminating rather than merely tidying.
- **Cancellation takes as long as the in-flight artifact.** Aborting during a
  94 MB write took ~30s to unwind, because the partial artifact is discarded and
  the remaining manifest work still runs. Correct, but the UI should say so.
- **Clock correlation quality varies with load.** Measured 18 ms offset at 115 ms
  RTT on an idle device, but 3468 ms at 7066 ms RTT while streaming logcat. The
  offset is within measurement noise either way; the manifest records the RTT so
  the reading can be judged, but the correlator does not yet warn on a poor
  sample.

### Issues found in review and fixed

Recorded because each was a way an acquisition could fail while appearing to
succeed:

1. **Transport stall on stream-write failure.** If `writeStream` failed before it
   consumed stdout (OPFS quota, path error), the error path awaited the process
   exit code while stdout was still unread. Since ADB stops draining an unread
   stream, the exit packet never arrived and the module hung forever, stalling
   every subsequent module. Both `writeStream` and `streamToArtifact` now cancel
   the source stream before awaiting completion.
2. **Sync-socket deadlock.** The same setup failures left a `pull()` source
   un-cancelled, holding the shared `AdbSync` socket lock for the rest of the
   acquisition.
3. **Dangling artifact records.** A failed rewrite of an existing artifact name
   (which `fallbackCommandArtifact` and `packages.txt` do legitimately) deleted
   the file but left its record, so `hashes.csv` referenced a file that no longer
   existed and ZIP export aborted mid-stream.
4. **`/proc/kmsg` collection removed.** It is the consuming `syslog(2)` reader,
   so reading it destroys the kernel ring buffer that `bugreportz` would
   otherwise capture — and it never reaches EOF, so on the rooted devices where
   it is readable the transfer would hang indefinitely. Replaced with `dmesg`.
5. **Stale manifest counts.** `acquisition.json` was built from a snapshot taken
   before the command logs were written, so its artifact count disagreed with
   `hashes.csv`. The manifest is now built after them and names the entries it
   cannot include.
6. **Unrecoverable evidence after a late failure.** If the run threw while
   writing the manifest, the UI reached the completion screen with no export
   controls, stranding verified evidence in OPFS. A partial summary is now
   constructed so it can still be exported, and "Discard local copy" stays
   disabled until an export succeeds.

### Bugs found by real-device testing and fixed

The first run against hardware found four defects that no amount of local
reasoning had surfaced:

1. **Negative findings were discarded as errors — an evidence-loss bug.**
   `ctx.run` throws on a non-zero exit, but `which su` exiting 1 *is* the
   answer: the binary is absent. Every one of the 26 root probes therefore threw,
   `root_binaries.json` shipped with `"paths": []`, and a stock device was
   reported as `28 errors, 11 unexpected`. The findings were not merely
   mislabelled, they were never recorded. Probes now opt into
   `run(..., { tolerateFailure: true })`, and the same run reports `2 errors,
   0 unexpected` with all 15 path observations present. A refusal
   (`Permission denied`) is additionally distinguished from a genuine absence via
   `indeterminate`, because "cannot tell" must never be read as "not there".
2. **ZIP export failed on real-sized acquisitions.** See the `Response.blob()`
   limit above: exporting the 111 MB archive surfaced only as a "Failed to fetch"
   notice, with the evidence intact but unreachable.
3. **Package inventory wasted 7.5 minutes.** It ran `pm path` for all 443
   packages even under Quick, where `apkPolicy: "none"` means no APK is ever
   pulled and `pm list packages -f` has already reported the base path. Paths are
   now resolved only for packages that will be pulled: 466s to ~17s. Records
   carry `splits_enumerated` so a single-entry file list is not misread as proof
   that a package has no split APKs.
4. **Optional probes counted as unexpected failures.** This device retained no
   prior-boot log buffer, so `logcat -L` fails with "Logcat read failure" — a
   device condition whose wording matches no refusal pattern. Group items can now
   be marked `optional`.

A fifth, smaller issue: an already-authorized device still forced the WebUSB
chooser on every run. The connect path now reuses a device the browser profile
has already been granted.

### Bugs found while building the analysis

Each of these would have produced a wrong answer while appearing to work, which
is the only failure mode that matters in a tool like this:

1. **A transposed digit in the CRC-32 polynomial.** `0xeda8_8320` instead of
   `0xedb8_8320` meant every entry of every imported archive would have failed its
   integrity check — reporting sound evidence as corrupt, and training an examiner
   to ignore the warning.
2. **A flat archive defeated all `fnmatch` globbing.** Entries were not nested
   under a directory, so `*/getprop.txt` matched nothing. Every MVT module, and
   every analyzer selecting inputs the same way, silently found no artifacts. The
   symptom is a clean report, which is the worst possible way for this to fail.
3. **Analyzer status could not distinguish clean from broken.** Status was derived
   from alert count, so an unparseable `packages.json` and a genuinely clean device
   both reported `complete` with zero findings. Analyzers now explicitly record
   which artifacts they parsed, and an analyzer that examined nothing is `failed`.
4. **Exact indicator matches never fired for processes and file paths.** Those two
   types were added only to the scan list and not the lookup table, so an
   indicator for a full path or an untruncated process name could not match. The
   same fix corrected case handling: paths and process names are case-sensitive on
   Android, and folding them would have manufactured matches.
5. **Empty setting values were normalised to `"0"`.** An absent setting therefore
   compared equal to an explicitly disabled one, firing findings about
   configuration that the device had simply never reported.
6. **The archive was planned before analysis ran.** `hashes.csv` and the ZIP were
   built from a snapshot of the collected artifacts, so analysis reports written
   afterwards appeared in neither. The plan is now built from the store's live
   records, and "Discard local copy" stays disabled while the last export predates
   the current analysis — otherwise the only copy of the reports could be deleted.
7. **The indicator load raced the Analyse button.** For about half a second after
   page load the UI reported "0 from 0 bundles" and stated that malware detection
   was unavailable, and an analysis started in that window genuinely ran with an
   empty indicator set — producing a legitimate-looking report that said no
   indicators were in force. Loading is now a distinct state from zero, and
   starting an analysis awaits the snapshot load.
8. **77% of every indicator bundle was unreachable.** The matcher implemented
   `checkDomain` correctly and no analyzer ever called it, so the 1251 domain and
   IP indicators in the snapshot — the large majority of any real bundle — could
   not match anything. Nothing failed; the report simply said "no indicator
   matches", which is exactly what a clean device looks like. Found by counting
   pattern types in the real snapshot against the analyzers that consume them,
   which is now a table in this README so the gap cannot reopen unnoticed.

Verified in a browser against the real snapshot: 1617 indicators load from static
assets with no CSP violations, no failed requests and no console output. The race
fix was confirmed structurally rather than by timing — the misleading warning is
gated behind `!loading && total === 0` in the shipped bundle, so it cannot render
during the load window. (Timing observation alone proved unreliable: background-tab
timer throttling clumps polls together and skips the window entirely, which would
have wrongly suggested the loading state did not exist.)

## Legal

Intended for lawful, consent-based forensic examination. Acquiring data from a
device without authorization is illegal in most jurisdictions.

External reputation lookups (e.g. VirusTotal) are **not** performed. Submitting
APK hashes discloses information about the subject device to a third party; that
must be an explicit, opt-in decision.
