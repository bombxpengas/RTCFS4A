/*
 * rtmem_helper — minimal root-privileged process-memory tool for live RAM
 * corruption on a rooted Android device.
 *
 * This must be invoked as root (the app always runs it via `su -c`) because
 * it uses ptrace() to attach to another process, which the kernel only
 * allows for root (or a process with CAP_SYS_PTRACE and a permissive Yama
 * ptrace_scope) on stock Android.
 *
 * There is no Android equivalent to BizHawk's cooperative "memory domain"
 * API that the real RTCV integrates with — no mainstream Android emulator
 * exposes its emulated RAM to outside tools on purpose. This takes the same
 * fallback approach tools like GameGuardian use instead: attach directly to
 * the target process and read/write its real memory via /proc/<pid>/mem.
 *
 * Usage:
 *   rtmem_helper list_processes
 *       -> one line per process: "<pid>\t<cmdline argv0>"
 *
 *   rtmem_helper list_maps <pid>
 *       -> one line per /proc/<pid>/maps entry, passed through as-is
 *
 *   rtmem_helper read <pid> <hex_address> <length> <output_file>
 *       -> writes the raw bytes read to output_file, prints OK or ERR <msg>
 *
 *   rtmem_helper write <pid> <hex_address> <input_file>
 *       -> writes input_file's exact contents into the process at that
 *          address, prints OK or ERR <msg>
 *
 *   rtmem_helper patch <pid> <hex_region_start> <hex_region_end> <patch_file>
 *       -> anti-crash write path. Applies many small writes in ONE ptrace
 *          attach instead of rewriting a whole region. patch_file is a
 *          sequence of records: u64 address (LE), u32 length (LE), <length>
 *          bytes. Before touching anything it validates (a) every record
 *          lies inside [region_start, region_end) and (b) that whole region
 *          is *still* mapped read+write and non-executable in the target's
 *          current /proc/<pid>/maps — if the emulator freed or remapped the
 *          region since it was scanned, this refuses instead of scribbling
 *          over whatever now lives at that address (usually a crash).
 *
 *   rtmem_helper cpatch <pid> <hex_region_start> <hex_region_end> <patch_file>
 *       -> the safest write path (used by Anti-crash). Like `patch`, but:
 *          (1) it FREEZES EVERY THREAD of the target (PTRACE_SEIZE +
 *          PTRACE_INTERRUPT on each /proc/<pid>/task/<tid>), not just the
 *          main one. A game keeps allocating/freeing on its other threads
 *          while a single-thread attach is held, so the snapshot we corrupted
 *          can be stale by the time we write; (2) every record carries the
 *          bytes we *expect* to find (the snapshot) followed by the new
 *          bytes, and a record is only written if the target's memory STILL
 *          equals the expectation — compare-and-swap. A block the app
 *          freed, re-allocated or rewrote since the snapshot is skipped, never
 *          scribbled over; (3) each record is checked against the current
 *          maps individually, so one unmapped hole in a big region no longer
 *          cancels the whole write.
 *          Record: u64 address (LE), u32 length (LE), <length> expected
 *          bytes, <length> new bytes.
 *          Prints: OK applied=N skipped=N unmapped=N failed=N frozen=N
 *
 *   rtmem_helper alive <pid> <name>
 *       -> ALIVE | STOPPED | DEAD [reason]. <name> must match the pid's
 *          argv[0], so a recycled pid is reported as DEAD, not ALIVE.
 *
 * Reads/writes go through a file instead of stdout/argv specifically so
 * multi-megabyte regions (PS1/N64-sized RAM and up) don't hit shell
 * argument-length limits or slow line-buffered pipe reads.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
/* 64-bit file offsets even in the 32-bit (armeabi-v7a) build: /proc/<pid>/mem
 * is addressed by virtual address, and with a 32-bit off_t every address
 * above 2 GiB would come out negative and fail with EINVAL. */
#ifndef _FILE_OFFSET_BITS
#define _FILE_OFFSET_BITS 64
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <inttypes.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

#ifndef __WALL
#define __WALL 0x40000000
#endif

/* Signal the target was actually stopped by when we attached. Normally the
 * SIGSTOP that PTRACE_ATTACH itself sends; if the thread was already stopped
 * on some other signal (e.g. a SIGSEGV it was about to die from) that signal
 * must be re-delivered on detach, not silently swallowed — swallowing it
 * turns a clean crash into a hang or a re-fault loop. */
static int g_stopsig = 0;

static int attach(pid_t pid) {
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) != 0) return -1;

    int status = 0;
    for (;;) {
        pid_t w = waitpid(pid, &status, __WALL);
        if (w == pid) break;
        if (w < 0 && errno == EINTR) continue;
        int saved = errno;
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        errno = saved ? saved : ESRCH;
        return -1;
    }
    if (!WIFSTOPPED(status)) { /* it exited while we were attaching */
        errno = ESRCH;
        return -1;
    }
    int sig = WSTOPSIG(status);
    g_stopsig = (sig == SIGSTOP) ? 0 : sig;
    return 0;
}

static void detach(pid_t pid) {
    ptrace(PTRACE_DETACH, pid, NULL, (void *)(long) g_stopsig);
    /* PTRACE_ATTACH's SIGSTOP can leave the target in group-stop after the
     * detach (the app just appears frozen). SIGCONT is a harmless no-op if it
     * isn't stopped. We only get here if the attach succeeded, which means no
     * debuggerd/tombstoned crash dump was holding the process. */
    kill(pid, SIGCONT);
}

/* pread/pwrite wrappers that handle short transfers and EINTR. */
static int pread_full(int fd, unsigned char *buf, size_t len, uint64_t addr) {
    size_t done = 0;
    while (done < len) {
        ssize_t n = pread(fd, buf + done, len - done, (off_t)(addr + done));
        if (n < 0) { if (errno == EINTR) continue; return -1; }
        if (n == 0) { errno = EIO; return -1; }
        done += (size_t) n;
    }
    return 0;
}

static int pwrite_full(int fd, const unsigned char *buf, size_t len, uint64_t addr) {
    size_t done = 0;
    while (done < len) {
        ssize_t n = pwrite(fd, buf + done, len - done, (off_t)(addr + done));
        if (n < 0) { if (errno == EINTR) continue; return -1; }
        if (n == 0) { errno = EIO; return -1; }
        done += (size_t) n;
    }
    return 0;
}

/* True if [start, end) is fully covered by mappings that are readable,
 * writable and NOT executable right now. /proc/<pid>/maps is sorted by
 * address, so this is a single forward walk looking for holes. */
static int range_is_plain_rw(pid_t pid, uint64_t start, uint64_t end) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f) return 0;

    char line[4096];
    uint64_t cursor = start;
    int ok = 0;
    while (fgets(line, sizeof(line), f)) {
        unsigned long long s, e;
        char perms[8];
        if (sscanf(line, "%llx-%llx %7s", &s, &e, perms) != 3) continue;
        if ((uint64_t) e <= cursor) continue;
        if ((uint64_t) s > cursor) break; /* hole inside the range */
        if (perms[0] != 'r' || perms[1] != 'w' || perms[2] == 'x') break;
        cursor = (uint64_t) e;
        if (cursor >= end) { ok = 1; break; }
    }
    fclose(f);
    return ok;
}

static void cmd_list_processes(void) {
    DIR *d = opendir("/proc");
    if (!d) { printf("ERR cannot open /proc: %s\n", strerror(errno)); return; }

    struct dirent *entry;
    while ((entry = readdir(d)) != NULL) {
        pid_t pid = (pid_t)atoi(entry->d_name);
        if (pid <= 0) continue;

        char path[64];
        snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
        FILE *f = fopen(path, "rb");
        if (!f) continue;

        char cmdline[256] = {0};
        size_t n = fread(cmdline, 1, sizeof(cmdline) - 1, f);
        fclose(f);
        if (n == 0) continue; // kernel threads etc. have an empty cmdline

        // cmdline is NUL-separated argv; keep argv[0] (the package/binary name).
        printf("%d\t%s\n", pid, cmdline);
    }
    closedir(d);
}

static void cmd_list_maps(pid_t pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f) { printf("ERR cannot open maps for pid %d: %s\n", pid, strerror(errno)); return; }

    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\n")] = 0;
        printf("%s\n", line);
    }
    fclose(f);
}

static void cmd_alive(pid_t pid, const char *expectName) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    FILE *f = fopen(path, "r");
    if (!f) { printf("DEAD no-such-process\n"); return; }

    char stat[1024] = {0};
    size_t n = fread(stat, 1, sizeof(stat) - 1, f);
    fclose(f);
    stat[n] = 0;

    /* "pid (comm) S ..." — comm can itself contain ')' and spaces, so the
     * state letter is the first non-space char after the LAST ')'. */
    char *paren = strrchr(stat, ')');
    char state = '?';
    if (paren) {
        char *p = paren + 1;
        while (*p == ' ') p++;
        state = *p;
    }
    if (state == 'Z' || state == 'X') { printf("DEAD zombie\n"); return; }

    snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
    f = fopen(path, "rb");
    if (!f) { printf("DEAD no-such-process\n"); return; }
    char cmdline[256] = {0};
    n = fread(cmdline, 1, sizeof(cmdline) - 1, f);
    fclose(f);
    if (n == 0 || strcmp(cmdline, expectName) != 0) { printf("DEAD pid-reused\n"); return; }

    if (state == 'T' || state == 't') { printf("STOPPED\n"); return; }
    printf("ALIVE\n");
}

static void cmd_read(pid_t pid, uint64_t address, size_t length, const char *outPath) {
    if (length == 0) { printf("ERR length must be greater than 0\n"); return; }
    if (attach(pid) != 0) { printf("ERR attach failed: %s\n", strerror(errno)); return; }

    char memPath[64];
    snprintf(memPath, sizeof(memPath), "/proc/%d/mem", pid);
    int fd = open(memPath, O_RDONLY | O_CLOEXEC);
    if (fd < 0) { int e = errno; detach(pid); printf("ERR open mem failed: %s\n", strerror(e)); return; }

    unsigned char *buf = malloc(length);
    if (!buf) { close(fd); detach(pid); printf("ERR out of memory\n"); return; }

    int rc = pread_full(fd, buf, length, address);
    int readErr = errno;
    close(fd);
    detach(pid);

    if (rc != 0) {
        free(buf);
        printf("ERR read failed at 0x%" PRIx64 ": %s\n", address, strerror(readErr));
        return;
    }

    int outFd = open(outPath, O_CREAT | O_WRONLY | O_TRUNC | O_CLOEXEC, 0666);
    if (outFd < 0) { free(buf); printf("ERR cannot open output file: %s\n", strerror(errno)); return; }
    int wrc = pwrite_full(outFd, buf, length, 0);
    int wrErr = errno;
    close(outFd);
    free(buf);
    chmod(outPath, 0666); // so the (unprivileged) app can read it back afterward

    if (wrc != 0) {
        printf("ERR writing output file failed: %s\n", strerror(wrErr));
        return;
    }
    printf("OK\n");
}

static unsigned char *slurp(const char *path, size_t *outSize, const char **err) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) { *err = "cannot open input file"; return NULL; }
    off_t size = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);
    if (size <= 0) { close(fd); *err = "empty input file"; return NULL; }
    unsigned char *buf = malloc((size_t) size);
    if (!buf) { close(fd); *err = "out of memory"; return NULL; }
    size_t done = 0;
    while (done < (size_t) size) {
        ssize_t n = read(fd, buf + done, (size_t) size - done);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { free(buf); close(fd); *err = "reading input file failed"; return NULL; }
        done += (size_t) n;
    }
    close(fd);
    *outSize = (size_t) size;
    return buf;
}

static void cmd_write(pid_t pid, uint64_t address, const char *inPath) {
    size_t size = 0;
    const char *err = NULL;
    unsigned char *buf = slurp(inPath, &size, &err);
    if (!buf) { printf("ERR %s: %s\n", err, strerror(errno)); return; }

    if (attach(pid) != 0) { int e = errno; free(buf); printf("ERR attach failed: %s\n", strerror(e)); return; }

    char memPath[64];
    snprintf(memPath, sizeof(memPath), "/proc/%d/mem", pid);
    int fd = open(memPath, O_WRONLY | O_CLOEXEC);
    if (fd < 0) { int e = errno; free(buf); detach(pid); printf("ERR open mem failed: %s\n", strerror(e)); return; }

    int rc = pwrite_full(fd, buf, size, address);
    int wErr = errno;
    close(fd);
    detach(pid);
    free(buf);

    if (rc != 0) {
        printf("ERR write failed at 0x%" PRIx64 ": %s\n", address, strerror(wErr));
        return;
    }
    printf("OK\n");
}

static void cmd_patch(pid_t pid, uint64_t regionStart, uint64_t regionEnd, const char *patchPath) {
    if (regionEnd <= regionStart) { printf("ERR bad region\n"); return; }

    size_t size = 0;
    const char *err = NULL;
    unsigned char *buf = slurp(patchPath, &size, &err);
    if (!buf) { printf("ERR patch file: %s\n", err); return; }

    /* Validate every record BEFORE attaching, so a malformed patch can never
     * leave the target half-written. */
    size_t pos = 0;
    while (pos < size) {
        if (size - pos < 12) { free(buf); printf("ERR truncated patch record\n"); return; }
        uint64_t addr; uint32_t len;
        memcpy(&addr, buf + pos, 8);
        memcpy(&len, buf + pos + 8, 4);
        pos += 12;
        if (len == 0 || len > size - pos) { free(buf); printf("ERR bad patch length\n"); return; }
        if (addr < regionStart || addr > regionEnd || (uint64_t) len > regionEnd - addr) {
            free(buf);
            printf("ERR patch outside region 0x%" PRIx64 "-0x%" PRIx64 "\n", regionStart, regionEnd);
            return;
        }
        pos += len;
    }

    if (attach(pid) != 0) { int e = errno; free(buf); printf("ERR attach failed: %s\n", strerror(e)); return; }

    /* Re-check the mapping with the target stopped: if the emulator freed or
     * re-purposed this region since the scan, refuse rather than corrupt
     * whatever (code, allocator metadata, a guard page...) lives there now. */
    if (!range_is_plain_rw(pid, regionStart, regionEnd)) {
        detach(pid);
        free(buf);
        printf("ERR region 0x%" PRIx64 "-0x%" PRIx64 " is no longer mapped read/write (target moved or freed it)\n",
               regionStart, regionEnd);
        return;
    }

    char memPath[64];
    snprintf(memPath, sizeof(memPath), "/proc/%d/mem", pid);
    int fd = open(memPath, O_WRONLY | O_CLOEXEC);
    if (fd < 0) { int e = errno; free(buf); detach(pid); printf("ERR open mem failed: %s\n", strerror(e)); return; }

    pos = 0;
    int failed = 0;
    int failErr = 0;
    uint64_t failAddr = 0;
    while (pos < size) {
        uint64_t addr; uint32_t len;
        memcpy(&addr, buf + pos, 8);
        memcpy(&len, buf + pos + 8, 4);
        pos += 12;
        if (pwrite_full(fd, buf + pos, len, addr) != 0) {
            failed = 1; failErr = errno; failAddr = addr;
            break;
        }
        pos += len;
    }
    close(fd);
    detach(pid);
    free(buf);

    if (failed) {
        printf("ERR write failed at 0x%" PRIx64 ": %s\n", failAddr, strerror(failErr));
        return;
    }
    printf("OK\n");
}

/* ------------------------------------------------------------------ */
/* cpatch: freeze all threads + compare-and-swap writes                 */
/* ------------------------------------------------------------------ */

#ifndef PTRACE_SEIZE
#define PTRACE_SEIZE 0x4206
#endif
#ifndef PTRACE_INTERRUPT
#define PTRACE_INTERRUPT 0x4207
#endif
#ifndef PTRACE_EVENT_STOP
#define PTRACE_EVENT_STOP 128
#endif

#define MAX_TIDS 4096

typedef struct {
    pid_t tid;
    int sig;  /* a real signal the thread was already stopped on: re-deliver on detach */
    int ok;   /* 1 = actually stopped by us (only these get detached) */
} Tracee;

typedef struct {
    Tracee t[MAX_TIDS];
    int n;
} TraceeSet;

static int set_has(const TraceeSet *s, pid_t tid) {
    for (int i = 0; i < s->n; i++) if (s->t[i].tid == tid) return 1;
    return 0;
}

/* Stops one thread. SEIZE + INTERRUPT (rather than ATTACH's SIGSTOP) means no
 * group-stop is left behind and an interrupted syscall is restarted cleanly
 * on detach. Returns 0 when stopped, -1 (errno set) otherwise. */
static int freeze_thread(pid_t tid, int *sigOut) {
    *sigOut = 0;
    if (ptrace(PTRACE_SEIZE, tid, NULL, NULL) != 0) return -1;
    if (ptrace(PTRACE_INTERRUPT, tid, NULL, NULL) != 0) {
        int e = errno;
        ptrace(PTRACE_DETACH, tid, NULL, NULL);
        errno = e;
        return -1;
    }
    for (int i = 0; i < 4000; i++) { /* ~2 s at most per thread */
        int status = 0;
        pid_t w = waitpid(tid, &status, __WALL | WNOHANG);
        if (w == tid) {
            if (!WIFSTOPPED(status)) { errno = ESRCH; return -1; } /* it exited */
            int sig = WSTOPSIG(status);
            /* A plain signal-delivery-stop (e.g. the SIGSEGV/SIGABRT it was about
             * to die from) must be handed back on detach, never swallowed. An
             * event-stop (our own INTERRUPT) carries nothing to re-deliver. */
            if ((status >> 16) == 0 && sig != SIGTRAP) *sigOut = sig;
            return 0;
        }
        if (w < 0 && errno != EINTR) return -1;
        usleep(500);
    }
    /* Never stopped (uninterruptible sleep). We can't detach a running
     * tracee; the kernel releases it when this helper exits a moment later. */
    errno = ETIMEDOUT;
    return -1;
}

static int list_tids(pid_t pid, pid_t *out, int max) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/task", pid);
    DIR *d = opendir(path);
    if (!d) return 0;
    int n = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL && n < max) {
        pid_t tid = (pid_t) atoi(e->d_name);
        if (tid > 0) out[n++] = tid;
    }
    closedir(d);
    return n;
}

/* Freezes the whole process. The main thread MUST stop (else -1, errno set —
 * EPERM here means debuggerd/crash_dump already owns the process, i.e. it is
 * mid-crash); other threads are best effort. New threads spawned while we
 * were stopping the others are picked up by re-listing until a pass adds none. */
static int freeze_all(pid_t pid, TraceeSet *set) {
    set->n = 0;
    int sig = 0;
    if (freeze_thread(pid, &sig) != 0) return -1;
    set->t[set->n].tid = pid; set->t[set->n].sig = sig; set->t[set->n].ok = 1; set->n++;

    pid_t tids[MAX_TIDS];
    for (int pass = 0; pass < 8; pass++) {
        int n = list_tids(pid, tids, MAX_TIDS);
        int added = 0;
        for (int i = 0; i < n && set->n < MAX_TIDS; i++) {
            if (set_has(set, tids[i])) continue;
            int ok = (freeze_thread(tids[i], &sig) == 0);
            set->t[set->n].tid = tids[i];
            set->t[set->n].sig = ok ? sig : 0;
            set->t[set->n].ok = ok;
            set->n++;
            added++;
        }
        if (added == 0) break;
    }
    return 0;
}

static int frozen_count(const TraceeSet *set) {
    int c = 0;
    for (int i = 0; i < set->n; i++) c += set->t[i].ok;
    return c;
}

static void thaw_all(TraceeSet *set) {
    /* Others first, main thread last. */
    for (int i = set->n - 1; i >= 0; i--) {
        if (!set->t[i].ok) continue;
        ptrace(PTRACE_DETACH, set->t[i].tid, NULL, (void *)(long) set->t[i].sig);
    }
}

typedef struct { uint64_t s, e; } Range;

/* Reads the target's CURRENT plain read/write (non-exec) mappings, merging
 * adjacent ones. Returns the count; *out is malloc'd (caller frees). */
static int load_rw_ranges(pid_t pid, Range **out) {
    *out = NULL;
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    int cap = 256, n = 0;
    Range *r = malloc(sizeof(Range) * cap);
    if (!r) { fclose(f); return 0; }
    char line[4096];
    while (fgets(line, sizeof(line), f)) {
        unsigned long long s, e;
        char perms[8];
        if (sscanf(line, "%llx-%llx %7s", &s, &e, perms) != 3) continue;
        if (perms[0] != 'r' || perms[1] != 'w' || perms[2] == 'x') continue;
        if (n > 0 && r[n - 1].e == (uint64_t) s) { r[n - 1].e = (uint64_t) e; continue; }
        if (n == cap) {
            cap *= 2;
            Range *nr = realloc(r, sizeof(Range) * cap);
            if (!nr) break;
            r = nr;
        }
        r[n].s = (uint64_t) s; r[n].e = (uint64_t) e; n++;
    }
    fclose(f);
    *out = r;
    return n;
}

static int range_covered(const Range *r, int n, uint64_t addr, uint64_t len) {
    uint64_t end = addr + len;
    if (end < addr) return 0;
    for (int i = 0; i < n; i++) {
        if (r[i].s <= addr && end <= r[i].e) return 1;
    }
    return 0;
}

static void cmd_cpatch(pid_t pid, uint64_t regionStart, uint64_t regionEnd, const char *patchPath) {
    if (regionEnd <= regionStart) { printf("ERR bad region\n"); return; }

    size_t size = 0;
    const char *err = NULL;
    unsigned char *buf = slurp(patchPath, &size, &err);
    if (!buf) { printf("ERR patch file: %s\n", err); return; }

    /* Validate the whole file BEFORE freezing anything. */
    size_t pos = 0;
    uint32_t maxLen = 0;
    while (pos < size) {
        if (size - pos < 12) { free(buf); printf("ERR truncated patch record\n"); return; }
        uint64_t addr; uint32_t len;
        memcpy(&addr, buf + pos, 8);
        memcpy(&len, buf + pos + 8, 4);
        pos += 12;
        if (len == 0 || (uint64_t) len * 2 > size - pos) { free(buf); printf("ERR bad patch length\n"); return; }
        if (addr < regionStart || addr > regionEnd || (uint64_t) len > regionEnd - addr) {
            free(buf);
            printf("ERR patch outside region 0x%" PRIx64 "-0x%" PRIx64 "\n", regionStart, regionEnd);
            return;
        }
        if (len > maxLen) maxLen = len;
        pos += (size_t) len * 2;
    }

    unsigned char *cur = malloc(maxLen ? maxLen : 1);
    TraceeSet *set = calloc(1, sizeof(TraceeSet));
    if (!cur || !set) { free(buf); free(cur); free(set); printf("ERR out of memory\n"); return; }

    if (freeze_all(pid, set) != 0) {
        int e = errno;
        free(buf); free(cur); free(set);
        printf("ERR attach failed: %s\n", strerror(e));
        return;
    }

    Range *ranges = NULL;
    int nRanges = load_rw_ranges(pid, &ranges);

    char memPath[64];
    snprintf(memPath, sizeof(memPath), "/proc/%d/mem", pid);
    int fd = open(memPath, O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        int e = errno;
        thaw_all(set);
        free(buf); free(cur); free(set); free(ranges);
        printf("ERR open mem failed: %s\n", strerror(e));
        return;
    }

    int applied = 0, skipped = 0, unmapped = 0, failed = 0;
    uint64_t failAddr = 0; int failErr = 0;
    pos = 0;
    while (pos < size) {
        uint64_t addr; uint32_t len;
        memcpy(&addr, buf + pos, 8);
        memcpy(&len, buf + pos + 8, 4);
        pos += 12;
        const unsigned char *expected = buf + pos;
        const unsigned char *fresh = buf + pos + len;
        pos += (size_t) len * 2;

        if (!range_covered(ranges, nRanges, addr, len)) { unmapped++; continue; }
        if (pread_full(fd, cur, len, addr) != 0) { skipped++; continue; }
        if (memcmp(cur, expected, len) != 0) { skipped++; continue; } /* the app changed it since the snapshot */
        if (pwrite_full(fd, fresh, len, addr) != 0) {
            if (!failed) { failAddr = addr; failErr = errno; }
            failed++;
            continue;
        }
        applied++;
    }
    close(fd);
    int frozen = frozen_count(set);
    thaw_all(set);
    free(buf); free(cur); free(set); free(ranges);

    if (applied == 0 && failed > 0) {
        printf("ERR write failed at 0x%" PRIx64 ": %s\n", failAddr, strerror(failErr));
        return;
    }
    printf("OK applied=%d skipped=%d unmapped=%d failed=%d frozen=%d\n", applied, skipped, unmapped, failed, frozen);
}

int main(int argc, char **argv) {
    if (argc < 2) { printf("ERR missing command\n"); return 1; }

    if (strcmp(argv[1], "list_processes") == 0) {
        cmd_list_processes();
        return 0;
    }
    if (strcmp(argv[1], "list_maps") == 0 && argc >= 3) {
        pid_t pid = (pid_t) atoi(argv[2]);
        if (pid <= 0) { printf("ERR bad pid\n"); return 1; }
        cmd_list_maps(pid);
        return 0;
    }
    if (strcmp(argv[1], "alive") == 0 && argc >= 4) {
        pid_t pid = (pid_t) atoi(argv[2]);
        if (pid <= 0) { printf("DEAD bad-pid\n"); return 0; }
        cmd_alive(pid, argv[3]);
        return 0;
    }
    if (strcmp(argv[1], "read") == 0 && argc >= 6) {
        pid_t pid = (pid_t) atoi(argv[2]);
        if (pid <= 0) { printf("ERR bad pid\n"); return 1; }
        uint64_t addr = strtoull(argv[3], NULL, 16);
        size_t len = (size_t) strtoull(argv[4], NULL, 10);
        cmd_read(pid, addr, len, argv[5]);
        return 0;
    }
    if (strcmp(argv[1], "write") == 0 && argc >= 5) {
        pid_t pid = (pid_t) atoi(argv[2]);
        if (pid <= 0) { printf("ERR bad pid\n"); return 1; }
        uint64_t addr = strtoull(argv[3], NULL, 16);
        cmd_write(pid, addr, argv[4]);
        return 0;
    }
    if (strcmp(argv[1], "patch") == 0 && argc >= 6) {
        pid_t pid = (pid_t) atoi(argv[2]);
        if (pid <= 0) { printf("ERR bad pid\n"); return 1; }
        uint64_t rs = strtoull(argv[3], NULL, 16);
        uint64_t re = strtoull(argv[4], NULL, 16);
        cmd_patch(pid, rs, re, argv[5]);
        return 0;
    }

    if (strcmp(argv[1], "cpatch") == 0 && argc >= 6) {
        pid_t pid = (pid_t) atoi(argv[2]);
        if (pid <= 0) { printf("ERR bad pid\n"); return 1; }
        uint64_t rs = strtoull(argv[3], NULL, 16);
        uint64_t re = strtoull(argv[4], NULL, 16);
        cmd_cpatch(pid, rs, re, argv[5]);
        return 0;
    }

    printf("ERR unknown command\n");
    return 1;
}
