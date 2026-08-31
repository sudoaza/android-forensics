# webadb-forensics

Zero-install Android forensic acquisition in the browser. Chromium is the only
software that touches the phone: no `adb` binary, no Android SDK, no Python, no
Node, no native daemon, no extension, no local agent.

```
Open the page  →  plug in over USB  →  authorize on device  →  choose profile
→  acquire  →  SHA-256 while streaming  →  verify  →  download ZIP
→  mvt-android check-androidqf <acquisition>.zip
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
client-zip             → acquisition ZIP on the examiner's disk
```

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
├── evidence/       hasher, OPFS store, ZIP assembly
└── ui/             four screens
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

## What gets collected

| Profile | Contents |
| --- | --- |
| **Quick** | Device state, settings, processes, services, security/network/scheduling dumpsys, root indicators, package inventory, logcat |
| **Standard** | Quick + third-party APKs, full dumpsys, readable diagnostic logs, temp directories, `bugreport.zip` |
| **Full** | Standard + system APKs |

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
```

`hashes.csv` covers every other entry and is emitted last, so it can include the
manifest and command log without hashing itself.

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
node tools/cdp.mjs click "Quick triage"
node tools/cdp.mjs watch 300            # poll progress
node tools/cdp.mjs download /tmp/out    # export the ZIP
node tools/cdp.mjs evalfile tools/inspect-opfs.js   # audit the spool
```

To verify the evidence chain independently of this codebase, recompute the
digests from the archive's own manifest with a host tool:

```bash
cd /tmp/out && unzip -q *.zip -d extracted && cd extracted
tail -n +2 hashes.csv | sed 's/^\([a-f0-9]*\),"\(.*\)"$/\1  \2/' | sha256sum -c
```

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

## Verification status

Verified:

- typecheck (strict, `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`)
- 46 unit tests: SHA-256 against NIST vectors and across chunk boundaries,
  `pm list` parsing, `hashes.csv` semantics, command-log rendering,
  stream-cleanup/truncation-detection contracts, and root-indicator
  classification
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

- `mvt-android check-androidqf` acceptance of a produced archive
- APK pulls and `bugreport.zip` (Standard/Full profiles; only Quick has been run
  end to end on hardware)
- resume behaviour under a real mid-stream unplug (deliberate cancellation is
  verified; a physical disconnect is not)
- OEM command variability beyond Xiaomi/MIUI — Samsung, Motorola, OnePlus, Pixel
- devices with an unlocked bootloader, a root manager present, or a userdebug
  build, all of which should produce positive root indicators rather than the
  negative ones observed so far

The next milestone is MVT compatibility artifact-by-artifact, then the rest of
the device matrix.

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

## Legal

Intended for lawful, consent-based forensic examination. Acquiring data from a
device without authorization is illegal in most jurisdictions.

External reputation lookups (e.g. VirusTotal) are **not** performed. Submitting
APK hashes discloses information about the subject device to a third party; that
must be an explicit, opt-in decision.
