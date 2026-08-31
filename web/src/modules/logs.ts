import type { AcquisitionModule } from "../acquisition/artifact.js";
import { commandGroup, pullDirectories, pullPaths } from "../acquisition/declarative.js";

/**
 * Diagnostic log collection.
 *
 * Almost every path here is unreadable to the `shell` user on a production
 * build. That is expected: each refusal is recorded as forensic metadata rather
 * than treated as a fault. `/proc/last_kmsg` and the pstore console log are the
 * exceptions worth trying anyway, since they survive a reboot and are where a
 * kernel-level compromise leaves traces.
 *
 * `/proc/kmsg` is deliberately NOT pulled. It is the consuming `syslog(2)`
 * reader: bytes read are removed from the kernel ring buffer, so collecting it
 * would destroy evidence that `bugreportz` and `dmesg` would otherwise capture.
 * It also never reaches EOF — a read simply blocks awaiting the next kernel
 * message — so on precisely the rooted/userdebug devices where it is readable,
 * the transfer would hang indefinitely. `dmesg` reads the same buffer
 * non-destructively and terminates.
 */
export const systemLogsModule: AcquisitionModule = pullPaths({
    id: "system-logs",
    label: "System logs",
    paths: [
        { remote: "/data/system/uiderrors.txt", artifact: "logs/uiderrors.txt" },
        { remote: "/proc/last_kmsg", artifact: "logs/last_kmsg.txt" },
        { remote: "/sys/fs/pstore/console-ramoops", artifact: "logs/console-ramoops.txt" },
        { remote: "/sys/fs/pstore/console-ramoops-0", artifact: "logs/console-ramoops-0.txt" },
        { remote: "/sys/fs/pstore/dmesg-ramoops-0", artifact: "logs/dmesg-ramoops-0.txt" },
        { remote: "/proc/net/arp", artifact: "logs/arp.txt" },
    ],
});

/** Non-destructive, terminating read of the kernel ring buffer. */
export const kernelLogModule: AcquisitionModule = commandGroup({
    id: "kernel-log",
    label: "Kernel log",
    items: [{ command: ["dmesg"], artifact: "logs/dmesg.txt", stream: true }],
});

/**
 * `/data/local/tmp` is the highest-value directory here: it is world-writable
 * enough to be the standard staging ground for dropped payloads, and unlike the
 * others it is readable by the `shell` user.
 */
export const logDirectoriesModule: AcquisitionModule = pullDirectories({
    id: "log-directories",
    label: "Log directories",
    maxDepth: 3,
    maxFiles: 300,
    maxFileBytes: 64 * 1024 * 1024,
    directories: [
        { remote: "/data/anr", prefix: "logs/anr" },
        { remote: "/data/log", prefix: "logs/data_log" },
        { remote: "/data/tombstones", prefix: "logs/tombstones" },
        { remote: "/sdcard/log", prefix: "logs/sdcard_log" },
    ],
});

export const tmpDirectoriesModule: AcquisitionModule = pullDirectories({
    id: "tmp-directories",
    label: "Temp directories",
    maxDepth: 3,
    maxFiles: 300,
    maxFileBytes: 64 * 1024 * 1024,
    directories: [
        { remote: "/data/local/tmp", prefix: "tmp/data_local_tmp" },
        { remote: "/sdcard/Download", prefix: "tmp/sdcard_download" },
    ],
});
