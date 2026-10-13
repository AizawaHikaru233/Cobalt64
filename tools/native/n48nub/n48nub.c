/*
 * n48nub - the user-space client of the N48N native session, minimal and read-mostly.
 *
 *   n48nub [status|publish|withdraw]        (default: status)
 *
 * Talks to Navi48Bringup's native user client (IOServiceOpen type 'N48N'), says Hello, then:
 *
 *   status    Hello + QUERYINFO (struct out n48n_info, 192 B) and prints the session's view:
 *             ABI, kext build, the info flags (HUNG / S1B_POSITIVE / NATIVE_BOOT), vm id,
 *             GB_ADDR_CONFIG, GC version, VRAM pools, the ABI-1.10 budget words and so on.
 *             Also reports whether a Navi48MetalNub is already in the IORegistry, and prints
 *             the live boot-args so the expected publish verdict can be reasoned about.
 *   publish   Hello + METAL_NUB_PUBLISH (selector 19, shape 1 in / 4 out, flags 0).
 *             Refused with kIOReturnUnsupported unless boot-arg navi48-metal=1 was set, and
 *             with kIOReturnNotReady unless this boot is native with an S1b POSITIVE PASS.
 *   withdraw  Hello + METAL_NUB_WITHDRAW (selector 20, shape 1 in / 1 out, flags 0).
 *             kIOReturnNotFound when no nub was published.
 *
 * WHY THIS TOOL IS SAFE TO RUN: the kext applies the whole publish verdict BEFORE it allocates
 * anything (Navi48MetalNub::selectorPublish: `if (verdict != kOk) return verdict;` precedes
 * OSTypeAlloc), and both selectors write no register. Opening the client and saying Hello are
 * what Mesa / WindowServer do on every normal boot.
 *
 * Authority for every constant below: src/navi48-bringup/src/Navi48NativeABI.h (selectors,
 * client type, Hello shape, n48n_info) and src/navi48-bringup/src/amd/native_metal_pure.h
 * (the publish / withdraw verdict codes, which are returned verbatim as the IOReturn). The
 * offsets and the size of n48n_info are re-asserted at compile time below, so a drift between
 * this copy and the ABI header cannot go unnoticed.
 *
 * Build:  clang -arch x86_64 -mmacosx-version-min=11.0 -Wall -O1 \
 *               -framework IOKit -framework CoreFoundation n48nub.c -o n48nub
 * Run:    sudo ./n48nub status      (a non-root caller is refused by the open policy unless it
 *                                    is uid 88 with navi48-metal-ws=1)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/sysctl.h>
#include <mach/mach.h>
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/IOReturn.h>

/* ---- N48N ABI (Navi48NativeABI.h) -------------------------------------------------------------------------------------------------- */
#define N48N_UC_TYPE        0x4E34384Eu     /* 'N48N' */
#define N48N_CLIENT_ABI     1u              /* N48N_ABI_VERSION (the MAJOR) */
#define N48N_HELLO_F_MINOR  (1u << 8)       /* Hello flags bit 8: report the minor in out[0] */

enum { N48N_SEL_HELLO = 0, N48N_SEL_QUERYINFO = 1, N48N_SEL_METAL_NUB_PUBLISH = 19, N48N_SEL_METAL_NUB_WITHDRAW = 20 };

enum { N48N_INFO_HUNG = 1u << 0, N48N_INFO_S1B_POSITIVE = 1u << 1, N48N_INFO_NATIVE_BOOT = 1u << 2 };
enum { N48N_INFO_R_BUDGET_FLAGS = 3u, N48N_INFO_R_BUDGET_CAP_LO = 4u, N48N_INFO_R_BUDGET_CAP_HI = 5u,
       N48N_INFO_R_BUDGET_AVAIL_LO = 6u, N48N_INFO_R_BUDGET_AVAIL_HI = 7u };
enum { N48N_BUDGET_VALID = 1u << 0, N48N_BUDGET_APP = 1u << 1 };

/* verbatim copy of struct n48n_info (192 B). The asserts below are the ABI header's own. */
struct n48n_info {
    uint32_t abi_version, kext_build, flags, vmid;
    uint32_t gb_addr_config, gc_version, ring_size_dw, max_ibs;
    uint64_t vram_vis_total, vram_vis_free;
    uint64_t vram_hi_total, vram_hi_free;
    uint64_t gtt_cap, gtt_used, gtt_max_bo;
    uint64_t pt_cap, pt_used;
    uint64_t seq_emitted, seq_retired;
    uint64_t va_low_first, va_low_last;
    uint64_t va_high_first, va_high_last;
    uint32_t max_bos, fence_slots;
    uint32_t reserved[8];
};
_Static_assert(sizeof(struct n48n_info) == 192, "n48n_info is 192 B");
_Static_assert(__builtin_offsetof(struct n48n_info, vram_vis_total) == 32, "info.vram_vis_total at 32");
_Static_assert(__builtin_offsetof(struct n48n_info, gtt_cap) == 64, "info.gtt_cap at 64");
_Static_assert(__builtin_offsetof(struct n48n_info, seq_emitted) == 104, "info.seq_emitted at 104");
_Static_assert(__builtin_offsetof(struct n48n_info, va_low_first) == 120, "info.va_low_first at 120");
_Static_assert(__builtin_offsetof(struct n48n_info, max_bos) == 152, "info.max_bos at 152");
_Static_assert(__builtin_offsetof(struct n48n_info, reserved) == 160, "info.reserved at 160");

/* ---- the publish / withdraw verdict codes (native_metal_pure.h): returned verbatim as the IOReturn --------------------------------- */
struct verdict { kern_return_t kr; const char *name; const char *why; };
static const struct verdict kPublishVerdicts[] = {
    { (kern_return_t)0x00000000u, "kIOReturnSuccess  (kOk)",        "the nub was published" },
    { (kern_return_t)0xe00002c7u, "kIOReturnUnsupported (kUnsupported)", "boot-arg navi48-metal is absent or 0: the feature does not exist on this boot" },
    { (kern_return_t)0xe00002d8u, "kIOReturnNotReady (kNotReady)",   "no Hello, or not a native boot with an S1b POSITIVE PASS, or the GPU is HUNG" },
    { (kern_return_t)0xe00002c2u, "kIOReturnBadArgument (kBadArg)",  "the flags word was not 0" },
    { (kern_return_t)0xe00002c5u, "kIOReturnExclusiveAccess (kExclusive)", "a nub is already published, or a Navi48DisplayNub holds the interlock" },
    { (kern_return_t)0xe00002d5u, "kIOReturnBusy (kBusy)",           "a previous nub is still terminating" },
    { (kern_return_t)0xe00002bdu, "kIOReturnNoMemory (kNoMemory)",   "the lock or the allocation failed" },
    { (kern_return_t)0x00000000u, NULL, NULL }
};
static const struct verdict kWithdrawVerdicts[] = {
    { (kern_return_t)0x00000000u, "kIOReturnSuccess  (kOk)",         "the published nub is now terminating" },
    { (kern_return_t)0xe00002f0u, "kIOReturnNotFound (kNotFound)",   "no nub was published" },
    { (kern_return_t)0xe00002d8u, "kIOReturnNotReady (kNotReady)",   "no Hello" },
    { (kern_return_t)0xe00002c2u, "kIOReturnBadArgument (kBadArg)",  "the flags word was not 0" },
    { (kern_return_t)0xe00002d5u, "kIOReturnBusy (kBusy)",           "a previous nub is still terminating" },
    { (kern_return_t)0x00000000u, NULL, NULL }
};

static const char *rc_name(kern_return_t kr) {
    switch (kr) {
    case kIOReturnSuccess:         return "kIOReturnSuccess";
    case kIOReturnBadArgument:     return "kIOReturnBadArgument";
    case kIOReturnUnsupported:     return "kIOReturnUnsupported";
    case kIOReturnNotReady:        return "kIOReturnNotReady";
    case kIOReturnExclusiveAccess: return "kIOReturnExclusiveAccess";
    case kIOReturnBusy:            return "kIOReturnBusy";
    case kIOReturnNotFound:        return "kIOReturnNotFound";
    case kIOReturnNoMemory:        return "kIOReturnNoMemory";
    case kIOReturnNotPrivileged:   return "kIOReturnNotPrivileged";
    case kIOReturnNotPermitted:    return "kIOReturnNotPermitted";
    case kIOReturnNotOpen:         return "kIOReturnNotOpen";
    case kIOReturnError:           return "kIOReturnError";
    default:                       return "(unnamed)";
    }
}
static const char *verdict_why(const struct verdict *tab, kern_return_t kr) {
    for (const struct verdict *v = tab; v->name; ++v)
        if (v->kr == kr) return v->why;
    return "(not a nub verdict: see the IOReturn name above)";
}

/* ---- helpers ----------------------------------------------------------------------------------------------------------------------- */
static void print_bootargs(void) {
    size_t len = 0;
    if (sysctlbyname("kern.bootargs", NULL, &len, NULL, 0) != 0 || len == 0) { printf("  boot-args: (unavailable)\n"); return; }
    char *buf = calloc(1, len + 1);
    if (!buf) return;
    if (sysctlbyname("kern.bootargs", buf, &len, NULL, 0) == 0) {
        printf("  boot-args: %s\n", buf);
        printf("  navi48-metal in boot-args: %s\n", strstr(buf, "navi48-metal=1") ? "YES" : "NO  -> a publish must be refused with kIOReturnUnsupported");
        printf("  navi48-native in boot-args: %s\n", strstr(buf, "navi48-native=1") ? "yes" : "no");
    }
    free(buf);
}
static void probe_nub(void) {
    /* a published Metal nub is an IOService of class Navi48MetalNub under Navi48Bringup */
    io_iterator_t it = IO_OBJECT_NULL;
    CFMutableDictionaryRef m = IOServiceMatching("Navi48MetalNub");
    if (!m) { printf("  Navi48MetalNub lookup: (no match dictionary)\n"); return; }
    if (IOServiceGetMatchingServices(0, m, &it) != KERN_SUCCESS) { printf("  Navi48MetalNub lookup: failed\n"); return; }
    int n = 0;
    io_service_t svc;
    while ((svc = IOIteratorNext(it))) {
        uint64_t id = 0;
        IORegistryEntryGetRegistryEntryID(svc, &id);
        ++n;
        printf("  Navi48MetalNub #%d: registry entry ID %#llx%s\n", n, (unsigned long long)id,
               n == 1 ? "   <- a nub is PUBLISHED right now" : "");
        IOObjectRelease(svc);
    }
    IOObjectRelease(it);
    if (n == 0) printf("  Navi48MetalNub: none in the IORegistry (nothing published)\n");
}

int main(int argc, char **argv) {
    const char *verb = (argc > 1) ? argv[1] : "status";
    if (strcmp(verb, "status") && strcmp(verb, "publish") && strcmp(verb, "withdraw") && strcmp(verb, "hello")) {
        printf("usage: n48nub [status|publish|withdraw]\n"); return 64;
    }
    printf("== n48nub %s  (client type '%c%c%c%c' = %#x)\n", verb,
           (char)(N48N_UC_TYPE >> 24), (char)(N48N_UC_TYPE >> 16), (char)(N48N_UC_TYPE >> 8), (char)N48N_UC_TYPE, N48N_UC_TYPE);
    printf("   euid %u%s\n", (unsigned)geteuid(), geteuid() == 0 ? " (root: the open policy admits an administrator)" : " (NOT root: the open policy will refuse unless uid 88 with navi48-metal-ws=1)");
    print_bootargs();

    io_service_t svc = IOServiceGetMatchingService(0, IOServiceMatching("Navi48Bringup"));
    if (!svc) { printf("  Navi48Bringup: NOT FOUND in the IORegistry -> the bring-up kext is not loaded/armed on this boot\n"); return 2; }
    uint64_t svcID = 0;
    IORegistryEntryGetRegistryEntryID(svc, &svcID);
    printf("  Navi48Bringup: found (registry entry ID %#llx)\n", (unsigned long long)svcID);

    io_connect_t conn = IO_OBJECT_NULL;
    kern_return_t kr = IOServiceOpen(svc, mach_task_self(), N48N_UC_TYPE, &conn);
    printf("  IOServiceOpen('N48N') -> %#x %s\n", kr, rc_name(kr));
    if (kr != KERN_SUCCESS) { IOObjectRelease(svc); return 3; }

    uint64_t hi[2] = { N48N_CLIENT_ABI, N48N_HELLO_F_MINOR };
    uint64_t ho[4] = { 0, 0, 0, 0 };
    uint32_t hoCnt = 4;
    kr = IOConnectCallScalarMethod(conn, N48N_SEL_HELLO, hi, 2, ho, &hoCnt);
    printf("  HELLO -> %#x %s  out[%u] = {%#llx, %#llx, %#llx, %#llx}\n", kr, rc_name(kr), hoCnt,
           (unsigned long long)ho[0], (unsigned long long)ho[1], (unsigned long long)ho[2], (unsigned long long)ho[3]);
    if (kr == KERN_SUCCESS) {
        uint32_t major = (uint32_t)(ho[0] & 0xffffu), minor = (uint32_t)((ho[0] >> 16) & 0xffffu);
        printf("     kernel ABI %u.%u | kext build %u | max IBs %u | vmid %u\n", major, minor,
               (unsigned)ho[1], (unsigned)ho[2], (unsigned)ho[3]);
    }
    if (kr != KERN_SUCCESS) { IOServiceClose(conn); IOObjectRelease(svc); return 4; }
    if (!strcmp(verb, "hello")) { IOServiceClose(conn); IOObjectRelease(svc); return 0; }

    if (!strcmp(verb, "status")) {
        struct n48n_info info;
        memset(&info, 0, sizeof info);
        size_t infoSize = sizeof info;
        kr = IOConnectCallStructMethod(conn, N48N_SEL_QUERYINFO, NULL, 0, &info, &infoSize);
        printf("  QUERYINFO -> %#x %s  (struct out %zu B)\n", kr, rc_name(kr), infoSize);
        if (kr == KERN_SUCCESS && infoSize == sizeof info) {
            printf("     abi_version %u | kext_build %u | flags %#x (%s%s%s) | vmid %u\n", info.abi_version, info.kext_build, info.flags,
                   (info.flags & N48N_INFO_HUNG) ? "HUNG " : "",
                   (info.flags & N48N_INFO_S1B_POSITIVE) ? "S1B_POSITIVE " : "",
                   (info.flags & N48N_INFO_NATIVE_BOOT) ? "NATIVE_BOOT" : "", info.vmid);
            printf("     gb_addr_config %#x | gc_version %#x ((maj<<16)|(min<<8)|rev) | ring_size_dw %u | max_ibs %u\n",
                   info.gb_addr_config, info.gc_version, info.ring_size_dw, info.max_ibs);
            printf("     vram visible total %llu MiB free %llu MiB | above-BAR0 total %llu MiB free %llu MiB\n",
                   (unsigned long long)(info.vram_vis_total >> 20), (unsigned long long)(info.vram_vis_free >> 20),
                   (unsigned long long)(info.vram_hi_total >> 20), (unsigned long long)(info.vram_hi_free >> 20));
            printf("     gtt cap %llu MiB used %llu MiB max_bo %llu | pt cap %llu used %llu\n",
                   (unsigned long long)(info.gtt_cap >> 20), (unsigned long long)(info.gtt_used >> 20),
                   (unsigned long long)info.gtt_max_bo, (unsigned long long)info.pt_cap, (unsigned long long)info.pt_used);
            printf("     seq emitted %llu retired %llu | max_bos %u fence_slots %u\n",
                   (unsigned long long)info.seq_emitted, (unsigned long long)info.seq_retired, info.max_bos, info.fence_slots);
            printf("     va low [%#llx, %#llx] high [%#llx, %#llx]\n",
                   (unsigned long long)info.va_low_first, (unsigned long long)info.va_low_last,
                   (unsigned long long)info.va_high_first, (unsigned long long)info.va_high_last);
            uint64_t cap = ((uint64_t)info.reserved[N48N_INFO_R_BUDGET_CAP_HI] << 32) | info.reserved[N48N_INFO_R_BUDGET_CAP_LO];
            uint64_t avail = ((uint64_t)info.reserved[N48N_INFO_R_BUDGET_AVAIL_HI] << 32) | info.reserved[N48N_INFO_R_BUDGET_AVAIL_LO];
            printf("     reserved[2] (ABI minor) %u | budget flags %#x%s%s cap %llu MiB avail %llu MiB\n",
                   info.reserved[2], info.reserved[N48N_INFO_R_BUDGET_FLAGS],
                   (info.reserved[N48N_INFO_R_BUDGET_FLAGS] & N48N_BUDGET_VALID) ? " VALID" : "",
                   (info.reserved[N48N_INFO_R_BUDGET_FLAGS] & N48N_BUDGET_APP) ? " APP" : "",
                   (unsigned long long)(cap >> 20), (unsigned long long)(avail >> 20));
            printf("     => publish gate inputs visible here: %s%s%s\n",
                   (info.flags & N48N_INFO_NATIVE_BOOT) ? "native boot OK " : "NOT a native boot ",
                   (info.flags & N48N_INFO_S1B_POSITIVE) ? "+ S1b POSITIVE " : "+ S1b NOT positive ",
                   (info.flags & N48N_INFO_HUNG) ? "+ HUNG (publish refused)" : "+ not HUNG");
        }
    } else if (!strcmp(verb, "publish")) {
        uint64_t pi[1] = { 0 };                 /* [0] flags, must be 0 */
        uint64_t po[4] = { 0, 0, 0, 0 };        /* state, nub registry entry ID, N48_METAL_ABI, sizeof(N48MetalOps) */
        uint32_t poCnt = 4;
        kr = IOConnectCallScalarMethod(conn, N48N_SEL_METAL_NUB_PUBLISH, pi, 1, po, &poCnt);
        printf("  METAL_NUB_PUBLISH -> %#x %s\n", kr, rc_name(kr));
        printf("     why: %s\n", verdict_why(kPublishVerdicts, kr));
        printf("     out[%u] = { state %#llx, nub registry entry ID %#llx, N48_METAL_ABI %#llx, sizeof(N48MetalOps) %#llx }\n",
               poCnt, (unsigned long long)po[0], (unsigned long long)po[1], (unsigned long long)po[2], (unsigned long long)po[3]);
    } else {
        uint64_t wi[1] = { 0 };
        uint64_t wo[1] = { 0 };
        uint32_t woCnt = 1;
        kr = IOConnectCallScalarMethod(conn, N48N_SEL_METAL_NUB_WITHDRAW, wi, 1, wo, &woCnt);
        printf("  METAL_NUB_WITHDRAW -> %#x %s\n", kr, rc_name(kr));
        printf("     why: %s\n", verdict_why(kWithdrawVerdicts, kr));
        printf("     out[%u] = { previous state %#llx }\n", woCnt, (unsigned long long)wo[0]);
    }

    printf("  -- now that the session exists, look for a nub:\n");
    probe_nub();

    IOServiceClose(conn);
    IOObjectRelease(svc);
    printf("== done (session closed)\n");
    return 0;
}
