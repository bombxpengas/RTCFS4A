/*
 * emu-lab: headless no-op plugins for Mupen64Plus (video, audio, scripted input), selected at compile
 * time with -DPLUGIN_VIDEO / -DPLUGIN_AUDIO / -DPLUGIN_INPUT. They let the real core run a ROM with no
 * display, sound card or controller, so the memory-layout work can be tested against a *real* emulator
 * process instead of guesses.
 *
 * Input script (env EMULAB_PRESS): "first-last:BUTTONS;..." in frames, BUTTONS joined by '+',
 * e.g. "300-310:START;700-705:A+START". Frame = number of GetKeys() calls on controller 0.
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "m64p_types.h"
#include "m64p_plugin.h"

#define EXPORT __attribute__((visibility("default")))
#define CALL

static void (*debug_cb)(void *, int, const char *);
static void *debug_ctx;

#if defined(PLUGIN_VIDEO)
# define PNAME "emu-lab dummy video"
# define PTYPE M64PLUGIN_GFX
# define PAPI 0x020500
#elif defined(PLUGIN_AUDIO)
# define PNAME "emu-lab dummy audio"
# define PTYPE M64PLUGIN_AUDIO
# define PAPI 0x020000
#else
# define PNAME "emu-lab scripted input"
# define PTYPE M64PLUGIN_INPUT
# define PAPI 0x020100
#endif

EXPORT m64p_error CALL PluginStartup(m64p_dynlib_handle core, void *ctx, void (*cb)(void *, int, const char *)) {
    (void) core; debug_ctx = ctx; debug_cb = cb; return M64ERR_SUCCESS;
}
EXPORT m64p_error CALL PluginShutdown(void) { return M64ERR_SUCCESS; }
EXPORT m64p_error CALL PluginGetVersion(m64p_plugin_type *type, int *version, int *api, const char **name, int *caps) {
    if (type) *type = PTYPE;
    if (version) *version = 0x010000;
    if (api) *api = PAPI;
    if (name) *name = PNAME;
    if (caps) *caps = 0;
    return M64ERR_SUCCESS;
}

#if defined(PLUGIN_VIDEO)
EXPORT int CALL RomOpen(void) { return 1; }
EXPORT void CALL RomClosed(void) {}
EXPORT void CALL ChangeWindow(void) {}
static GFX_INFO gfx;
/* A real graphics plugin raises the RDP-done interrupt after each display list; the game's scheduler
 * blocks on it, so a plugin that never does makes the game idle forever in its OS code. */
static void raise_dp(void) {
    if (gfx.MI_INTR_REG && gfx.CheckInterrupts) { *gfx.MI_INTR_REG |= 0x20; gfx.CheckInterrupts(); }
}
EXPORT int CALL InitiateGFX(GFX_INFO i) { gfx = i; return 1; }
EXPORT void CALL MoveScreen(int x, int y) { (void) x; (void) y; }
EXPORT void CALL ProcessDList(void) { raise_dp(); }
EXPORT void CALL ProcessRDPList(void) { raise_dp(); }
EXPORT void CALL ShowCFB(void) {}
EXPORT void CALL UpdateScreen(void) {}
EXPORT void CALL ViStatusChanged(void) {}
EXPORT void CALL ViWidthChanged(void) {}
EXPORT void CALL ReadScreen2(void *d, int *w, int *h, int f) { (void) d; (void) f; if (w) *w = 0; if (h) *h = 0; }
EXPORT void CALL SetRenderingCallback(void (*cb)(int)) { (void) cb; }
EXPORT void CALL ResizeVideoOutput(int w, int h) { (void) w; (void) h; }
EXPORT void CALL FBRead(unsigned int a) { (void) a; }
EXPORT void CALL FBWrite(unsigned int a, unsigned int s) { (void) a; (void) s; }
EXPORT void CALL FBGetFrameBufferInfo(void *p) { (void) p; }
#elif defined(PLUGIN_AUDIO)
EXPORT int CALL RomOpen(void) { return 1; }
EXPORT void CALL RomClosed(void) {}
EXPORT void CALL AiDacrateChanged(int t) { (void) t; }
EXPORT void CALL AiLenChanged(void) {}
EXPORT int CALL InitiateAudio(AUDIO_INFO i) { (void) i; return 1; }
EXPORT void CALL ProcessAList(void) {}
EXPORT void CALL SetSpeedFactor(int p) { (void) p; }
EXPORT void CALL VolumeUp(void) {}
EXPORT void CALL VolumeDown(void) {}
EXPORT int CALL VolumeGetLevel(void) { return 0; }
EXPORT void CALL VolumeSetLevel(int l) { (void) l; }
EXPORT void CALL VolumeMute(void) {}
EXPORT const char *CALL VolumeGetString(void) { return "muted"; }
#else
typedef struct { int first, last; unsigned bits; } Press;
static Press presses[64];
static int npress;
static unsigned long frame;
static CONTROL *controls;

static unsigned parse_buttons(const char *s) {
    unsigned v = 0;
    static const struct { const char *n; unsigned m; } map[] = {
        {"R_DPAD", 1u<<0}, {"L_DPAD", 1u<<1}, {"D_DPAD", 1u<<2}, {"U_DPAD", 1u<<3}, {"START", 1u<<4},
        {"Z", 1u<<5}, {"B", 1u<<6}, {"A", 1u<<7}, {"C_RIGHT", 1u<<8}, {"C_LEFT", 1u<<9}, {"C_DOWN", 1u<<10},
        {"C_UP", 1u<<11}, {"R", 1u<<12}, {"L", 1u<<13}
    };
    char buf[128]; strncpy(buf, s, sizeof(buf) - 1); buf[sizeof(buf) - 1] = 0;
    for (char *t = strtok(buf, "+"); t; t = strtok(NULL, "+"))
        for (unsigned i = 0; i < sizeof(map) / sizeof(map[0]); i++) if (!strcmp(t, map[i].n)) v |= map[i].m;
    return v;
}

EXPORT int CALL RomOpen(void) {
    const char *e = getenv("EMULAB_PRESS");
    npress = 0;
    if (e) {
        char *copy = strdup(e);
        for (char *p = strtok(copy, ";"); p && npress < 64; p = strtok(NULL, ";")) {
            int a, b; char btn[128];
            if (sscanf(p, "%d-%d:%127s", &a, &b, btn) == 3) { presses[npress].first = a; presses[npress].last = b; presses[npress].bits = parse_buttons(btn); npress++; }
        }
        free(copy);
    }
    return 1;
}
EXPORT void CALL RomClosed(void) {}
EXPORT void CALL ControllerCommand(int c, unsigned char *cmd) { (void) c; (void) cmd; }
EXPORT void CALL GetKeys(int c, BUTTONS *k) {
    k->Value = 0;
    if (c != 0) return;
    frame++;
    if ((frame % 30) == 0) {
        const char *ff = getenv("EMULAB_FRAMEFILE");
        if (ff) { FILE *f = fopen(ff, "w"); if (f) { fprintf(f, "%lu\n", frame); fclose(f); } }
    }
    for (int i = 0; i < npress; i++)
        if ((long) frame >= presses[i].first && (long) frame <= presses[i].last) k->Value |= presses[i].bits;
}
EXPORT void CALL InitiateControllers(CONTROL_INFO info) {
    controls = info.Controls;
    for (int i = 0; i < 4; i++) { controls[i].Present = (i == 0); controls[i].RawData = 0; controls[i].Plugin = PLUGIN_NONE; }
}
EXPORT void CALL ReadController(int c, unsigned char *cmd) { (void) c; (void) cmd; }
EXPORT void CALL SDL_KeyDown(int m, int k) { (void) m; (void) k; }
EXPORT void CALL SDL_KeyUp(int m, int k) { (void) m; (void) k; }
EXPORT void CALL RenderCallback(void) {}
EXPORT unsigned long CALL EmuLabFrame(void) { return frame; }
#endif
