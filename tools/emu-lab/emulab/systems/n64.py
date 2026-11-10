"""Nintendo 64.

Emulators keep RDRAM in one of three byte orders, and the finder tries all of them:
    "be"   bytes exactly as the console sees them (z64 order)
    "le32" each 32-bit word stored host-endian — what Mupen64Plus does on little-endian hosts
    "v64"  16-bit halves swapped
(For 32-bit-word-aligned data like everything we search for, "le32" is the byte reversal of each word.)

Anchors, all verified against the real Mupen64Plus 2.6 core running Super Mario 64:
  globals  the boot code leaves osRomBase = 0xB0000000 at +0x308 and osMemSize = 4/8 MB at +0x318
           (also osTvType at +0x300, osRomType at +0x304). Present before the game runs a single instruction.
  vectors  libultra's osInitialize copies the same 4-instruction stub (lui k0 / addiu k0 / jr k0 / nop)
           to +0x000, +0x080, +0x100 and +0x180. Present in practically every commercial game.
  romcopy  the boot loader copies 1 MB of the ROM (from +0x1000) to the entry point; any ROM fingerprint
           found in RAM pins the base exactly, and needs the ROM file but no luck about game state.
  rom      the cartridge image itself (not RAM, but proves which ROM is loaded and where it sits).
"""
from __future__ import annotations

import random
import zlib
from typing import Dict, List, Optional

from .base import Hit, Needle, System

MAGIC_Z64 = bytes.fromhex("80371240")


def _swap32(b: bytes) -> bytes:
    a = bytearray(len(b))
    a[0::4], a[1::4], a[2::4], a[3::4] = b[3::4], b[2::4], b[1::4], b[0::4]
    return bytes(a)


def _swap16(b: bytes) -> bytes:
    a = bytearray(len(b))
    a[0::2], a[1::2] = b[1::2], b[0::2]
    return bytes(a)


# IPL3 boot-chip identification by bootcode CRC32 -> how far the entry point is shifted from the header PC
CIC_BY_CRC = {0x6170A4A1: ("6101", 0), 0x90BB6CB5: ("6102", 0), 0x0B050EE0: ("6103", -0x100000),
              0x98BC2C86: ("6105", 0), 0xACC8580A: ("6106", -0x200000), 0x009E9EA3: ("7102", 0)}


def entry_candidates(z: bytes) -> list:
    """Physical RAM address where the boot loader puts ROM+0x1000. Known chip -> one answer; unknown -> both common shifts."""
    pc = int.from_bytes(z[8:12], "big")
    cic = CIC_BY_CRC.get(zlib.crc32(z[0x40:0x1000]) & 0xFFFFFFFF)
    if cic:
        return [(pc + cic[1]) & 0x1FFFFFFF]
    return sorted({pc & 0x1FFFFFFF, (pc - 0x100000) & 0x1FFFFFFF})


TRANSFORMS = {"be": lambda b: b, "le32": _swap32, "v64": _swap16}


def to_z64(rom: bytes) -> Optional[bytes]:
    """Normalises any dump byte order to z64 (big-endian), or None if it isn't an N64 ROM."""
    if rom[:4] == MAGIC_Z64:
        return rom
    if rom[:4] == bytes.fromhex("37804012"):   # v64
        return _swap16(rom)
    if rom[:4] == bytes.fromhex("40123780"):   # n64 (little-endian words)
        return _swap32(rom)
    return None


def tword(value: int, tf: str) -> bytes:
    return TRANSFORMS[tf](value.to_bytes(4, "big"))


def read_word(pm, addr: int, tf: str) -> int:
    b = TRANSFORMS[tf](pm.read(addr, 4))      # all three transforms are their own inverse on a 4-byte word
    return int.from_bytes(b, "big")


class N64(System):
    name = "n64"
    transforms = ["be", "le32", "v64"]

    VECTOR_STRIDE = 0x80
    VECTOR_COUNT = 4

    def ram_size_hint(self):
        return [4 << 20, 8 << 20]

    # -------------------------------------------------------------------------------------
    def needles(self, rom: Optional[bytes]) -> List[Needle]:
        out: List[Needle] = []
        for tf in self.transforms:
            # libultra exception stub tail: jr k0 ; nop  (identical in all four vectors)
            out.append(Needle(tword(0x03400008, tf) + tword(0, tf), self.name, "vectors", tf))
            # osRomBase
            out.append(Needle(tword(0xB0000000, tf), self.name, "globals", tf))
        z = to_z64(rom) if rom else None
        if z is not None and len(z) >= 0x2000:
            entries = entry_candidates(z)
            copy_end = min(0x101000, len(z))          # the boot loader copies up to 1 MB; small ROMs less
            rnd = random.Random(0x64)
            def pick(lo, hi, n):
                got, seen, tries = [], set(), 0
                while hi - lo > 64 and len(got) < n and tries < 4000:
                    tries += 1
                    o = rnd.randrange(lo, hi - 32) & ~3
                    c = z[o:o + 32]
                    if len(set(c)) >= 16 and o not in seen and z.count(c) == 1:
                        seen.add(o); got.append(o)
                return got
            for tf in self.transforms:
                for o in pick(0x1000, copy_end, 4):
                    out.append(Needle(TRANSFORMS[tf](z[o:o + 32]), self.name, "romcopy", tf, {"rom_off": o, "entries": entries}))
                for o in pick(copy_end, len(z), 4) or pick(0x1000, len(z), 4):
                    out.append(Needle(TRANSFORMS[tf](z[o:o + 32]), self.name, "rom", tf, {"rom_off": o}))
            self._z = z
        return out

    # -------------------------------------------------------------------------------------
    def verify(self, nd: Needle, addr: int, pm) -> List[Hit]:
        tf = nd.transform
        hits: List[Hit] = []
        if nd.group == "vectors":
            for k in range(self.VECTOR_COUNT):
                base = addr - (k * self.VECTOR_STRIDE + 8)
                w0 = read_word(pm, base + k * self.VECTOR_STRIDE, tf)
                w1 = read_word(pm, base + k * self.VECTOR_STRIDE + 4, tf)
                if (w0 >> 16) == 0x3C1A and (w1 >> 16) == 0x275A:        # lui k0, hi ; addiu k0, k0, lo
                    hits.append(Hit(self.name, "vectors", tf, "ram", base, f"vector {k} at +0x{k*0x80:x}", {"vec": k}))
        elif nd.group == "globals":
            base = addr - 0x308
            mem = read_word(pm, base + 0x318, tf)
            tv = read_word(pm, base + 0x300, tf)
            rt = read_word(pm, base + 0x304, tf)
            if mem in (0x400000, 0x800000) and tv in (0, 1, 2) and rt in (0, 1):
                hits.append(Hit(self.name, "globals", tf, "ram", base, f"osRomBase/osMemSize={mem >> 20}MB tv={tv}"))
        elif nd.group == "rom":
            base = addr - nd.meta["rom_off"]
            if pm.read(base, 16) == TRANSFORMS[tf](self._z[:16]):
                hits.append(Hit(self.name, "rom", tf, "rom", base, "cartridge image (header matches)"))
        elif nd.group == "romcopy":
            o = nd.meta["rom_off"]
            for entry in nd.meta["entries"]:
                base = addr - (entry + (o - 0x1000))
                loc = base + entry
                if pm.read(loc, 64) == TRANSFORMS[tf](self._z[0x1000:0x1040]):
                    hits.append(Hit(self.name, "romcopy", tf, "ram", base,
                                    f"ROM+0x1000.. found at RAM+0x{entry:x}", {"copy_loc": loc}))
        return hits

    # -------------------------------------------------------------------------------------
    def group_bits(self, group: str, hits: List[Hit]) -> float:
        if group == "vectors":
            # one lone stub is also what libultra's *source copy* inside the game's code looks like
            n = len({h.meta["vec"] for h in hits})
            return {1: 16.0, 2: 36.0, 3: 56.0}.get(n, 76.0)
        if group == "globals":
            return 48.0
        if group in ("romcopy", "rom"):
            return 96.0
        return 0.0
