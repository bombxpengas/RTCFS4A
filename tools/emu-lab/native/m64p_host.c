/*
 * emu-lab host: a minimal Mupen64Plus frontend (dlopens the real core) that runs a ROM headless and
 * reports the *ground truth* the detector is judged against — where the emulated RDRAM actually lives
 * in this process, taken from the core's own debug API.
 *
 *   m64p_host <bundle_dir> <plugin_dir> <rom> <seconds> [press_script]
 *
 * stdout protocol (one line each; the Python lab parses these):
 *   PID <pid>
 *   RDRAM <hex host address> <size>        (ground truth, printed once when emulation is up)
 *   FRAME <n>                              (every ~second of wall time)
 *   DONE
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include "m64p_types.h"
#include "m64p_common.h"
#include "m64p_frontend.h"
#include "m64p_config.h"
#include "m64p_debugger.h"

static void *core;
static m64p_error (*pCoreDoCommand)(m64p_command, int, void *);
static void *(*pDebugMemGetPointer)(m64p_dbg_memptr_type);
static void *(*pDebugGetCPUDataPtr)(m64p_dbg_cpu_data);
static volatile unsigned long frames;
static int run_seconds;

static void debug_cb(void *ctx, int level, const char *msg) {
    (void) ctx;
    if (level <= M64MSG_WARNING) fprintf(stderr, "[core:%d] %s\n", level, msg);
}
static void frame_cb(unsigned int f) { frames = f; }

static void *watcher(void *arg) {
    (void) arg;
    struct timespec ts = { 1, 0 };
    int printed_truth = 0;
    for (int t = 0; t < run_seconds; t++) {
        nanosleep(&ts, NULL);
        if (!printed_truth && pDebugMemGetPointer) {
            void *p = pDebugMemGetPointer(M64P_DBG_PTR_RDRAM);
            if (p) { printf("RDRAM %lx %d\n", (unsigned long) p, 8 * 1024 * 1024); printed_truth = 1; }
        }
        if (pDebugGetCPUDataPtr) { unsigned *pc = pDebugGetCPUDataPtr(M64P_CPU_PC); if (pc) printf("PC %08x\n", *pc); }
        printf("FRAME %lu\n", frames);
        fflush(stdout);
    }
    pCoreDoCommand(M64CMD_STOP, 0, NULL);
    return NULL;
}

static void *load_plugin(const char *path, m64p_plugin_type type) {
    void *h = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (!h) { fprintf(stderr, "plugin %s: %s\n", path, dlerror()); exit(2); }
    m64p_error (*startup)(m64p_dynlib_handle, void *, void (*)(void *, int, const char *)) = dlsym(h, "PluginStartup");
    if (!startup || startup(core, "plugin", debug_cb) != M64ERR_SUCCESS) { fprintf(stderr, "PluginStartup failed: %s\n", path); exit(2); }
    m64p_error (*attach)(m64p_plugin_type, m64p_dynlib_handle) = dlsym(core, "CoreAttachPlugin");
    m64p_error e = attach(type, h);
    if (e != M64ERR_SUCCESS) { fprintf(stderr, "CoreAttachPlugin(%s) failed: %d\n", path, e); exit(2); }
    return h;
}

int main(int argc, char **argv) {
    if (argc < 5) { fprintf(stderr, "usage: %s bundle_dir plugin_dir rom seconds [press]\n", argv[0]); return 1; }
    const char *bundle = argv[1], *plug = argv[2], *romPath = argv[3];
    run_seconds = atoi(argv[4]);
    if (argc > 5) setenv("EMULAB_PRESS", argv[5], 1);

    char path[1024];
    snprintf(path, sizeof(path), "%s/libmupen64plus.so.2", bundle);
    core = dlopen(path, RTLD_LAZY | RTLD_GLOBAL);
    if (!core) { fprintf(stderr, "core: %s\n", dlerror()); return 2; }

    m64p_error (*startup)(int, const char *, const char *, void *, void (*)(void *, int, const char *), void *, void (*)(void *, m64p_core_param, int)) = dlsym(core, "CoreStartup");
    pCoreDoCommand = dlsym(core, "CoreDoCommand");
    pDebugMemGetPointer = dlsym(core, "DebugMemGetPointer");
    pDebugGetCPUDataPtr = dlsym(core, "DebugGetCPUDataPtr");
    m64p_error (*cfgOpen)(const char *, m64p_handle *) = dlsym(core, "ConfigOpenSection");
    m64p_error (*cfgSet)(m64p_handle, const char *, m64p_type, const void *) = dlsym(core, "ConfigSetParameter");

    char cfgdir[1024];
    snprintf(cfgdir, sizeof(cfgdir), "/tmp/emulab-config");
    system("mkdir -p /tmp/emulab-config");
    if (startup(0x020001, cfgdir, bundle, "host", debug_cb, NULL, NULL) != M64ERR_SUCCESS) { fprintf(stderr, "CoreStartup failed\n"); return 2; }

    m64p_handle sec;
    if (cfgOpen("Core", &sec) == M64ERR_SUCCESS) {
        int emu = getenv("EMULAB_EMUMODE") ? atoi(getenv("EMULAB_EMUMODE")) : 2; /* 2 = dynarec; 0/1 = interpreters */
        cfgSet(sec, "R4300Emulator", M64TYPE_INT, &emu);
        int no = 0; cfgSet(sec, "AutoStateSlotIncrement", M64TYPE_BOOL, &no);
    }

    FILE *f = fopen(romPath, "rb");
    if (!f) { perror("rom"); return 2; }
    fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
    void *rom = malloc(n);
    if (fread(rom, 1, n, f) != (size_t) n) { fprintf(stderr, "short read\n"); return 2; }
    fclose(f);
    if (pCoreDoCommand(M64CMD_ROM_OPEN, (int) n, rom) != M64ERR_SUCCESS) { fprintf(stderr, "ROM_OPEN failed\n"); return 2; }
    free(rom);

    snprintf(path, sizeof(path), "%s/emulab-video.so", plug);  load_plugin(path, M64PLUGIN_GFX);
    snprintf(path, sizeof(path), "%s/emulab-audio.so", plug);  load_plugin(path, M64PLUGIN_AUDIO);
    snprintf(path, sizeof(path), "%s/emulab-input.so", plug);  load_plugin(path, M64PLUGIN_INPUT);
    snprintf(path, sizeof(path), "%s/mupen64plus-rsp-hle.so", bundle); load_plugin(path, M64PLUGIN_RSP);

    int off = 0; /* as fast as possible */
    pCoreDoCommand(M64CMD_CORE_STATE_SET, M64CORE_SPEED_LIMITER, &off);
    pCoreDoCommand(M64CMD_SET_FRAME_CALLBACK, 0, frame_cb);

    printf("PID %d\n", getpid()); fflush(stdout);
    pthread_t th; pthread_create(&th, NULL, watcher, NULL);
    m64p_error e = pCoreDoCommand(M64CMD_EXECUTE, 0, NULL);
    pthread_join(th, NULL);
    printf("DONE %d\n", e); fflush(stdout);
    return 0;
}
