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

    printf("ERR unknown command\n");
    return 1;
}
