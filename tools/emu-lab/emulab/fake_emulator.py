"""A stand-in 'emulator' process for controlled tests: maps a big arena, drops a memory image into it at a
chosen offset (optionally byte-order transformed / edited) and sleeps. Prints the base it used as ground truth."""
import mmap
import sys
import time


def run(blob_path: str, offset: int, arena_mb: int = 64, rom_path: str = "", rom_offset: int = 0, live_at: int = -1):
    arena = mmap.mmap(-1, arena_mb << 20, flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS)
    blob = open(blob_path, "rb").read()
    arena[offset:offset + len(blob)] = blob
    if live_at >= 0:                     # a second copy that "runs": a counter inside it keeps changing
        arena[live_at:live_at + len(blob)] = blob
    del blob                             # don't keep a private copy of the image on the Python heap
    if rom_path:
        rom = open(rom_path, "rb").read()
        arena[rom_offset:rom_offset + len(rom)] = rom
    import ctypes
    addr = ctypes.addressof(ctypes.c_char.from_buffer(arena))
    print(f"BASE {addr + (live_at if live_at >= 0 else offset):x}", flush=True)
    n = 0
    t_end = time.time() + 120
    while time.time() < t_end:
        if live_at >= 0:                  # tick the running copy at 0x400000.. (game RAM) like a real frame counter
            n += 1
            arena[live_at + 0x400000: live_at + 0x400004] = (n & 0xFFFFFFFF).to_bytes(4, "little")
            arena[live_at + 0x500000: live_at + 0x500004] = (n * 7 & 0xFFFFFFFF).to_bytes(4, "little")
        time.sleep(0.002)


if __name__ == "__main__":
    a = sys.argv[:]
    live = -1
    if "--live-copy-at" in a:
        i = a.index("--live-copy-at"); live = int(a[i + 1], 0); del a[i:i + 2]
    run(a[1], int(a[2], 0), int(a[3]), a[4] if len(a) > 4 else "", int(a[5], 0) if len(a) > 5 else 0, live)
