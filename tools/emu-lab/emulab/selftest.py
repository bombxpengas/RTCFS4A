"""Controlled experiments: does the finder find the real thing, and — just as important — does it stay quiet
when the real thing isn't there?"""
from __future__ import annotations

import os
import struct
import subprocess
import sys
import tempfile
import time
from typing import Callable, List, Optional

from .finder import find_ram, measure_liveness
from .lab import start_mupen
from .procmem import ProcessMemory
from .systems import ALL_SYSTEMS
from .systems.n64 import TRANSFORMS

ROM_SM64 = os.environ.get("EMULAB_ROM", "/mnt/user-data/uploads/Super_Mario_64__USA_.z64")
HERE = os.path.dirname(os.path.abspath(__file__))


def snapshot_rdram(run, n=8 << 20) -> bytes:
    with ProcessMemory(run.pid) as pm:
        return pm.read(run.truth, n)


def fake_process(blob: bytes, offset: int, rom: Optional[bytes] = None, rom_offset: int = 0, arena_mb: int = 64):
    tf = tempfile.NamedTemporaryFile(delete=False); tf.write(blob); tf.close()
    args = [sys.executable, "-m", "emulab.fake_emulator", tf.name, hex(offset), str(arena_mb)]
    if rom is not None:
        rf = tempfile.NamedTemporaryFile(delete=False); rf.write(rom); rf.close()
        args += [rf.name, hex(rom_offset)]
    p = subprocess.Popen(args, stdout=subprocess.PIPE, text=True, cwd=os.path.dirname(HERE))
    base = int(p.stdout.readline().split()[1], 16)
    return p, base


def verdict(rep, truth: Optional[int], min_tier="possible"):
    order = ["weak", "possible", "high", "certain"]
    strong = [d for d in rep.ram if order.index(d.tier) >= order.index(min_tier)]
    if truth is None:
        return ("PASS (silent)" if not strong else f"FAIL: false positive {strong[0].summary()}"), strong
    if not strong:
        return "MISS", strong
    top = strong[0]
    ok = top.base == truth
    extra = [d for d in strong[1:] if d.base != truth]
    return (f"PASS {top.tier} {top.bits:.0f}b" if ok else f"FAIL: top is wrong base {top.summary()}") + (f" (+{len(extra)} other candidate(s) ≥{min_tier})" if extra else ""), strong


def main():
    rom = open(ROM_SM64, "rb").read()
    rows: List[tuple] = []

    def record(name: str, text: str):
        rows.append((name, text)); print(f"{name:<58} {text}", flush=True)

    print("=== live Mupen64Plus (real emulator, ground truth from the core's own API)")
    run = start_mupen(ROM_SM64, seconds=100, press="300-310:START;600-610:A;900-910:A")
    snaps = {}
    for label, wait in (("t≈1s (just booted)", 0), ("t≈4s", 3), ("t≈12s", 8)):
        time.sleep(wait)
        with ProcessMemory(run.pid) as pm:
            r1 = find_ram(pm, ALL_SYSTEMS, rom=None)
            r2 = find_ram(pm, ALL_SYSTEMS, rom=rom)
        record(f"live {label}: no ROM file", verdict(r1, run.truth)[0] + f"   [{r1.seconds:.1f}s, {r1.bytes_read >> 20}MB]")
        record(f"live {label}: with ROM file", verdict(r2, run.truth)[0] + f"   [{r2.seconds:.1f}s]")
    from .regions import classify
    with ProcessMemory(run.pid) as pm:
        arena = [r for r in pm.regions() if r.contains(run.truth)][0]
    record("region filter: the emulator's RAM arena is HIGH priority", "PASS" if classify(arena)[0] == "HIGH" else f"FAIL {classify(arena)}")
    ram_le32 = snapshot_rdram(run)
    run.stop()
    ram_image = TRANSFORMS["le32"](ram_le32)      # canonical big-endian image: what the N64 itself sees
    del ram_le32

    print("\n=== synthetic emulator processes: other byte orders, partial state, decoys")
    def case(name, blob, offset, truth_expected=True, rom_arg=None, use_rom=None, rom_in_proc=None, rom_off=0):
        p, base = fake_process(blob, offset, rom=rom_in_proc, rom_offset=rom_off)
        try:
            with ProcessMemory(p.pid) as pm:
                rep = find_ram(pm, ALL_SYSTEMS, rom=use_rom)
            record(name, verdict(rep, base if truth_expected else None)[0] + (f"   rom-detected={len(rep.rom)}" if rom_in_proc else ""))
        finally:
            p.kill(); p.wait()

    for tf in ("be", "le32", "v64"):
        case(f"byte order {tf}, 4-aligned odd offset", TRANSFORMS[tf](ram_image), 0x1234 * 4)
    case("8 MB image, page aligned", TRANSFORMS["le32"](ram_image), 0x100000)
    case("different word-aligned offset (0x48)", TRANSFORMS["le32"](ram_image), 0x48)

    def zero_range(img, a, b):
        m = bytearray(img); m[a:b] = bytes(b - a); return bytes(m)
    be = ram_image
    L = TRANSFORMS["le32"]
    case("early boot: exception vectors not installed yet", L(zero_range(be, 0, 0x200)), 0x40000)
    case("emulator that doesn't write OS globals", L(zero_range(be, 0x300, 0x340)), 0x40000)

    # ROM copy only, with ROM file supplied to the finder
    stripped = L(zero_range(zero_range(be, 0, 0x200), 0x300, 0x340))
    p, base = fake_process(stripped, 0x40000)
    with ProcessMemory(p.pid) as pm:
        rep = find_ram(pm, ALL_SYSTEMS, rom=rom)
    record("vectors+globals wiped, only the ROM copy remains (ROM given)", verdict(rep, base)[0]); p.kill(); p.wait()
    p, base = fake_process(stripped, 0x40000)
    with ProcessMemory(p.pid) as pm:
        rep = find_ram(pm, ALL_SYSTEMS, rom=None)
    record("vectors+globals wiped, no ROM file (must stay silent)", verdict(rep, None)[0]); p.kill(); p.wait()

    case("all zeros (empty emulator)", bytes(8 << 20), 0x40000, truth_expected=False)
    import random
    rnd = random.Random(5)
    noise = bytearray(rnd.randbytes(8 << 20))
    for k in range(40):                       # plant lone osRomBase words and lone vector stubs everywhere
        o = rnd.randrange(0, (8 << 20) - 64) & ~3
        noise[o:o + 4] = (0xB0000000).to_bytes(4, "little")
        o = rnd.randrange(0, (8 << 20) - 64) & ~3
        noise[o:o + 8] = (0x03400008).to_bytes(4, "little") + bytes(4)
    case("random data + 80 planted lone decoys", bytes(noise), 0x40000, truth_expected=False)
    case("ROM image alone (no RAM), ROM file given", bytes(16), 0x1000, truth_expected=False, use_rom=rom, rom_in_proc=TRANSFORMS["le32"](rom), rom_off=0x400000)

    print("\n=== control: processes that are not emulators (fresh processes, nothing shared with this one)")
    for label, with_rom in (("plain Python process with 100 MB of random heap, no ROM", None), ("same, ROM file supplied to the finder", rom)):
        c = subprocess.Popen([sys.executable, "-c", "import os,time;d=os.urandom(100<<20);print('r',flush=True);time.sleep(60)"], stdout=subprocess.PIPE, text=True)
        c.stdout.readline()
        with ProcessMemory(c.pid) as pm:
            rep = find_ram(pm, ALL_SYSTEMS, rom=with_rom)
        record(label, verdict(rep, None)[0]); c.kill(); c.wait()

    print("\n=== two copies of RAM in one process (save-state / rewind buffer): the live one must win")
    blob = TRANSFORMS["le32"](ram_image)
    tf_ = tempfile.NamedTemporaryFile(delete=False); tf_.write(blob); tf_.close()
    p = subprocess.Popen([sys.executable, "-m", "emulab.fake_emulator", tf_.name, "0x40000", "64", "", "0", "--live-copy-at", "0x1000000"],
                         stdout=subprocess.PIPE, text=True, cwd=os.path.dirname(HERE))
    live_base = int(p.stdout.readline().split()[1], 16)
    with ProcessMemory(p.pid) as pm:
        rep = find_ram(pm, ALL_SYSTEMS, rom=None)
        measure_liveness(pm, rep)
    top = rep.ram[0]
    ok = top.base == live_base and not top.static_copy and any(d.static_copy for d in rep.ram[1:])
    record("static copy at +0x40000, live copy at +0x1000000", ("PASS" if ok else "FAIL") + f" top={top.summary()}")
    p.kill(); p.wait()

    fails = [r for r in rows if "FAIL" in r[1] or "MISS" in r[1]]
    print(f"\n{len(rows) - len(fails)}/{len(rows)} passed" + (f"; failures: {[r[0] for r in fails]}" if fails else ""))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
