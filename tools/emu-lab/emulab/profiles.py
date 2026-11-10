"""Training output: what each emulator's memory layout *looks like once we have proven where RAM is*.

A detection backed by strong, independent evidence is a label. From labelled detections we learn laws:
  * the arena shape the RAM lives in (anonymous rw mapping of N MB, alignment of the base inside it),
  * the byte order the emulator stores that system in,
  * where the ROM image sits relative to RAM (Mupen64Plus mirrors the physical address map: ROM = RAM + 0x10000000).
Laws are stored per emulator build (identified from the libraries mapped into the process) and used later to
(1) corroborate a detection — a candidate that also satisfies the learned law gets extra evidence, and
(2) rank/limit what to scan on a phone. A law is only trusted after it has been seen consistently several times.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional

from .finder import Detection, Report
from .procmem import ProcessMemory

TRUST_AFTER = 3
_KNOWN = re.compile(r"(mupen64plus[\w\-]*|parallel[-_]?n64|retroarch|libretro|dolphin|ppsspp|drastic|mgba|snes9x|fceu\w*|nestopia|"
                    r"gambatte|desmume|melonds|citra|duckstation|pcsx\w*|epsxe|flycast|redream|mednafen|bsnes|genesis_plus_gx|picodrive|"
                    r"m64plus\w*|rpcs3|vbam|visualboyadvance)", re.I)


def emulator_key(pm: ProcessMemory) -> str:
    """Identify the emulator build from the files mapped into the process (works the same on Android:
    libmupen64plus_next_libretro_android.so, libdolphin-emu.so, ...)."""
    names = {os.path.basename(r.path) for r in pm.regions() if r.path.startswith("/") and not r.path.endswith((".ttf", ".dat"))}
    hits = sorted({m.group(1).lower() for n in names for m in [_KNOWN.search(n)] if m})
    if hits:
        return "+".join(hits)
    try:
        return "exe:" + os.path.basename(os.readlink(f"/proc/{pm.pid}/exe"))
    except OSError:
        return "unknown"


@dataclass
class Law:
    system: str
    transform: str
    arena_mb: int                 # size of the mapping the RAM lives in (0 = unknown)
    arena_anonymous: bool
    base_alignment: int           # largest power of two (≤ 4096) dividing the RAM base
    rom_minus_ram: Optional[int]  # None if the ROM was never seen in this run
    seen: int = 1

    def key(self):
        return (self.system, self.transform, self.arena_mb, self.arena_anonymous, self.base_alignment, self.rom_minus_ram)


@dataclass
class Profile:
    emulator: str
    laws: List[Law] = field(default_factory=list)

    def trusted(self) -> List[Law]:
        return [l for l in self.laws if l.seen >= TRUST_AFTER]


class ProfileStore:
    def __init__(self, path: str):
        self.path = path
        self.profiles: Dict[str, Profile] = {}
        if os.path.exists(path):
            raw = json.load(open(path))
            for k, v in raw.items():
                self.profiles[k] = Profile(k, [Law(**l) for l in v["laws"]])

    def save(self):
        json.dump({k: {"laws": [asdict(l) for l in p.laws]} for k, p in self.profiles.items()}, open(self.path, "w"), indent=1, sort_keys=True)

    def learn(self, emulator: str, det: Detection, rom_det: Optional[Detection]) -> Law:
        r = det.region
        align = 4096
        while align > 1 and det.base % align:
            align //= 2
        law = Law(det.system, det.transform, (r.size >> 20) if r else 0, bool(r and r.anonymous), align,
                  (rom_det.base - det.base) if rom_det is not None else None)
        prof = self.profiles.setdefault(emulator, Profile(emulator))
        for l in prof.laws:
            if l.key() == law.key():
                l.seen += 1
                return l
        prof.laws.append(law)
        return law

    def corroboration(self, emulator: str, det: Detection, rom_det: Optional[Detection]) -> float:
        """Extra evidence bits when `det` obeys a trusted law of this emulator (0 if no profile / no law)."""
        prof = self.profiles.get(emulator)
        if not prof or det.region is None:
            return 0.0
        bits = 0.0
        for l in prof.trusted():
            if l.system != det.system or l.transform != det.transform:
                continue
            shape = (det.region.size >> 20) == l.arena_mb and det.region.anonymous == l.arena_anonymous
            if shape:
                bits = max(bits, 8.0)
            if shape and l.rom_minus_ram is not None and rom_det is not None and rom_det.base - det.base == l.rom_minus_ram:
                bits = max(bits, 32.0)
        return bits
