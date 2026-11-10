"""Training loop: for each (emulator, ROM) job, run it headless, look at it at several moments, detect,
score against ground truth, and fold the proven layouts into the profile store.

    python -m emulab.train --rom game.z64 [--rom other.v64 ...] [--profiles profiles.json] [--rounds 3]

Ground truth comes from the emulator's own API when it has one (Mupen64Plus: DebugMemGetPointer). For an
emulator with no such API the training label is the detection that reaches 'certain' on its own evidence;
a profile is never learned from anything weaker.
"""
from __future__ import annotations

import argparse
import os
import sys
import time

from .finder import find_ram, measure_liveness
from .lab import start_mupen
from .procmem import ProcessMemory
from .profiles import ProfileStore, emulator_key
from .systems import ALL_SYSTEMS


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rom", action="append", required=True)
    ap.add_argument("--profiles", default=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "profiles.json"))
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--seconds", type=int, default=90)
    a = ap.parse_args(argv)

    store = ProfileStore(a.profiles)
    total = correct = 0
    for rom_path in a.rom:
        rom = open(rom_path, "rb").read()
        for rnd in range(a.rounds):
            run = start_mupen(rom_path, seconds=a.seconds, press="300-310:START;600-610:A;900-910:A")
            try:
                time.sleep(2 + 2 * rnd)
                with ProcessMemory(run.pid) as pm:
                    key = emulator_key(pm)
                    rep = find_ram(pm, ALL_SYSTEMS, rom=rom)
                    measure_liveness(pm, rep, seconds=0.4)
                    top = rep.ram[0] if rep.ram else None
                    total += 1
                    ok = bool(top and top.base == run.truth)
                    correct += ok
                    note = ""
                    if ok and top.tier == "certain":
                        law = store.learn(key, top, rep.rom[0] if rep.rom else None)
                        bonus = store.corroboration(key, top, rep.rom[0] if rep.rom else None)
                        note = f" learned/confirmed law (seen {law.seen}x), corroboration now +{bonus:.0f} bits"
                    print(f"{os.path.basename(rom_path)} round {rnd + 1}: {'OK ' if ok else 'BAD'} [{key}] "
                          f"{top.summary() if top else 'no detection'}{note}", flush=True)
            finally:
                run.stop()
    store.save()
    print(f"\n{correct}/{total} correct; profiles saved to {a.profiles}")
    return 0 if correct == total else 1


if __name__ == "__main__":
    sys.exit(main())
