# emu-lab — finding an emulated console's RAM inside an emulator process

Goal: given a running emulator (any app), locate the *emulated* console's RAM in host memory, automatically,
with a confidence you can trust, and learn each emulator's memory layout from real headless runs.

## Why not just "scan for signatures"
Every single pattern also appears by accident (the game's own code contains libultra's exception stub before
it is copied to RAM; the ROM image contains every ROM fingerprint). So nothing is decided by one match:

1. **Anchors** — per console, byte patterns the platform's own boot code/OS writes at fixed offsets from RAM
   start (N64: `osRomBase=0xB0000000`/`osMemSize` at +0x308/+0x318; libultra's 4 identical exception stubs at
   +0x000/+0x080/+0x100/+0x180) and ROM landmarks (the boot loader copies ROM+0x1000 to the entry point).
   Every verified hit **votes for one number**: "emulated address 0 is at host address X".
2. **Evidence in bits** — independent anchor groups agreeing on X add up (globals 48b, vectors 76b, ROM copy
   96b). Tiers: ≥80 certain, ≥40 high, ≥24 possible, else weak (never shown).
3. **Geometry rules** — word-aligned bases only; a base whose evidence is a strict subset of another base's is
   an alias (the identical vectors make "vector 1 is vector 0" look 3/4 convincing) and is dropped; bases
   resting on *identical* evidence are flagged ambiguous and capped at "possible".
4. **Explain-away** — the ROM image contains the bytes of the RAM copy; hits inside a recognised ROM buffer are
   not allowed to vote for RAM.
5. **Liveness** — several copies of RAM exist in real emulators (save-state/rewind buffers). Pages of each
   candidate are hashed twice; the one that changes is the live RAM, static twins are flagged `STATIC-COPY`.
6. **Training** (`profiles.py`, `train.py`) — certain detections become labels; per emulator build we learn
   laws (arena size/alignment, byte order, ROM-minus-RAM delta). A law seen ≥3 times adds corroboration bits.

Robustness details that came from real runs: partial reads never drop a chunk (arenas have holes);
`/proc/pid/pagemap` limits reading to resident pages (512 MB arena, ~44 MB read); all three N64 byte orders
(be / le32 / v64) are tried; ROM files in z64/v64/n64 order are normalised; boot-chip (CIC) detection by
bootcode CRC32 fixes the ROM-copy entry address.

## Results so far (Mupen64Plus 2.6.0, real core, ground truth from `DebugMemGetPointer`)
* SM64 and Mupen's test ROM (v64): RAM found **certain** at t≈1 s, with and without the ROM file; 6/6 training
  rounds correct. Mupen layout learned: one 512 MB anonymous arena, page-aligned RAM, le32 words,
  ROM = RAM + 0x10000000.
* `python -m emulab.selftest` — 21 controls, all pass: other byte orders, early boot (no vectors), emulator that
  skips OS globals, ROM-copy-only, empty RAM, random data + 80 planted decoys, ROM present but no RAM (reports
  the ROM, no RAM), non-emulator processes, static-vs-live duplicate copies.

## Run it
    ./native/build.sh /path/to/mupen64plus-bundle-linux64-2.6.0   # stubs for missing libs + no-op plugins + host
    python3 -m emulab.selftest
    python3 -m emulab.train --rom game.z64 --rom other.v64
The host (`native/m64p_host.c`) drives the real core with no-op video/audio and scripted input
(`EMULAB_PRESS`), so no display is needed. The video plugin raises the RDP-done interrupt like a real one —
without it the game idles forever in its OS scheduler.

## Adding a console
Subclass `systems.base.System` (needles → verify → group_bits) and add it to `systems/__init__.py`.
Good anchor sources per console: NDS copies the ROM header to 0x027FFE00; GameCube/Wii keep the game ID at
RAM+0; PS1 has BIOS vector/table data at fixed low addresses; GBA has fixed IWRAM/EWRAM sizes and BIOS flags;
for NES/SNES/Genesis RAM holds little boot-time structure, so ROM-derived and liveness evidence matter more.
Adding an emulator for training = one adapter like `lab.start_mupen` that returns the pid and (if the
emulator has one) the ground-truth RAM address.

## Android: Mupen64Plus AE (arm64, Android 16) — second capture, the game process
`org.mupen64plusae.v3.fzurita:EmulationProcess` maps libmupen64plus-core, glide64mk2, rsp-hle and rsp-parallel. It is NOT
the same layout as desktop x86_64: no unnamed 512 MB arena; instead a ~512 MB `[anon:scudo:secondary]` mapping (24 MB
resident — a malloc'd arena) and three adjacent core `.bss` blocks (9 MB fully resident ≈ an 8 MB RDRAM + 1 MB, a 32 MB
rwx dynarec cache, a 23 MB). Layout alone can't say which holds RDRAM, so the detector now runs on the phone: the app's
**Find emulator RAM** button calls the native `findn64` (a port of `emulab`, validated against live Mupen64Plus: same
base, same 124/220 bits, ROM = RAM + 0x10000000, 0.5 s, one region, 16 MB read) and logs region, offset, byte order,
evidence and ROM-RAM delta under tag `EmuRam` — that log line is the training data for the arm64 layout law.

First real capture (Mupen64Plus AE, Android 16, arm64, Xiaomi): it was taken from the app's UI process — no emulator
library and no emulated RAM mapped — so the game almost certainly runs in another process or wasn't started. It still
showed what a phone process looks like: 5175 mappings, 328 MB resident, **87.5% of it unscannable** (executable code, ART
heaps, system libs, GPU buffers); `regions.py` skips those and ranks anonymous/shared writable memory first (41 MB left).

`android/capture_maps.sh` records an emulator's mappings (resident sizes, libraries, open files) — no game or
ROM data — so layouts of Android emulators can be learned without running them here.
