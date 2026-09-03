import type { AcquisitionModule } from "../acquisition/artifact.js";
import { commandGroup } from "../acquisition/declarative.js";

/**
 * Security and persistence state.
 *
 * This is where the collector goes beyond AndroidQF for spyware and RAT work.
 * Each of these services is a place persistence and abuse actually shows up:
 *
 *   appops           granted app operations, incl. background start and overlay
 *   accessibility    the single most abused surface for input capture and
 *                    automated clicking by Android RATs
 *   device_policy    silent device-admin / MDM ownership
 *   role             which app holds SMS, dialer, browser, home
 *   notification     notification-listener access, used to exfiltrate 2FA codes
 *   jobscheduler     periodic wakeups that survive reboot
 *   alarm            same, via AlarmManager
 *   connectivity     active VPN tunnels and proxy configuration
 *
 * Kept as separate files rather than one dumpsys blob so an analyst, or a
 * parser, can diff a single surface across acquisitions.
 */

export const securityStateModule: AcquisitionModule = commandGroup({
    id: "security-state",
    label: "Security state",
    supports: (device) => device.capabilities.dumpsys,
    items: [
        { command: ["dumpsys", "device_policy"], artifact: "security/device_policy.txt" },
        { command: ["dumpsys", "accessibility"], artifact: "security/accessibility.txt" },
        { command: ["dumpsys", "appops"], artifact: "security/appops.txt", stream: true },
        { command: ["dumpsys", "role"], artifact: "security/roles.txt" },
        { command: ["dumpsys", "notification"], artifact: "security/notifications.txt", stream: true },
    ],
});

export const networkStateModule: AcquisitionModule = commandGroup({
    id: "network-state",
    label: "Network state",
    supports: (device) => device.capabilities.dumpsys,
    items: [
        { command: ["dumpsys", "connectivity"], artifact: "security/connectivity.txt", stream: true },
        { command: ["dumpsys", "netpolicy"], artifact: "security/netpolicy.txt" },
        // vpn_management does not exist on every build; failure is recorded and
        // the group continues.
        { command: ["dumpsys", "vpn_management"], artifact: "security/vpn_management.txt" },
        { command: ["dumpsys", "wifi"], artifact: "security/wifi.txt", stream: true },
        { command: ["ip", "addr"], artifact: "security/ip_addr.txt" },
        { command: ["ip", "route"], artifact: "security/ip_route.txt" },
        { command: ["ip", "rule"], artifact: "security/ip_rule.txt" },
        { command: ["cat", "/proc/net/tcp"], artifact: "security/proc_net_tcp.txt" },
        { command: ["cat", "/proc/net/tcp6"], artifact: "security/proc_net_tcp6.txt" },
        { command: ["cat", "/proc/net/udp"], artifact: "security/proc_net_udp.txt" },
    ],
});

export const schedulingModule: AcquisitionModule = commandGroup({
    id: "scheduling",
    label: "Scheduled work",
    supports: (device) => device.capabilities.dumpsys,
    items: [
        { command: ["dumpsys", "jobscheduler"], artifact: "security/jobscheduler.txt", stream: true },
        { command: ["dumpsys", "alarm"], artifact: "security/alarms.txt", stream: true },
        { command: ["dumpsys", "activity", "processes"], artifact: "security/activity_processes.txt", stream: true },
        { command: ["dumpsys", "usagestats"], artifact: "security/usagestats.txt", stream: true },
        { command: ["dumpsys", "battery"], artifact: "security/battery.txt" },
        { command: ["dumpsys", "deviceidle"], artifact: "security/deviceidle.txt" },
    ],
});

/**
 * Verified boot, bootloader lock state, SELinux mode and mount table.
 *
 * These qualify every other finding: an unlocked bootloader or permissive
 * SELinux changes what the rest of the acquisition can be trusted to prove.
 */
export const bootStateModule: AcquisitionModule = commandGroup({
    id: "boot-state",
    label: "Verified boot and SELinux",
    items: [
        {
            command: [
                "getprop",
                "ro.boot.verifiedbootstate",
            ],
            artifact: "security/verified_boot_state.txt",
        },
        { command: ["getprop", "ro.boot.flash.locked"], artifact: "security/bootloader_locked.txt" },
        {
            command: ["getprop", "ro.boot.vbmeta.device_state"],
            artifact: "security/vbmeta_device_state.txt",
        },
        { command: ["getprop", "ro.boot.veritymode"], artifact: "security/verity_mode.txt" },
        { command: ["getenforce"], artifact: "security/selinux.txt" },
        { command: ["mount"], artifact: "security/mounts.txt" },
        { command: ["cat", "/proc/mounts"], artifact: "security/proc_mounts.txt" },
        { command: ["cat", "/proc/version"], artifact: "security/proc_version.txt" },
        // Denied to the shell user on production builds (observed on MIUI), which
        // is a device condition rather than a collection fault.
        { command: ["cat", "/proc/cmdline"], artifact: "security/proc_cmdline.txt", optional: true },
    ],
});
