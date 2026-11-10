"""What a console module provides to the generic finder.

A module knows three kinds of things about its console, and nothing else is system-specific:
  * RAM *anchors*: byte patterns the platform's own boot code / OS writes at fixed offsets from the start
    of RAM (they exist in every game, with or without the ROM file);
  * ROM *landmarks*: where, in RAM, ROM content is copied at boot (so a ROM fingerprint found in RAM pins
    the RAM base);
  * which byte orders emulators store its memory in.
The finder turns every verified hit into a vote for "emulated address 0 is at host address X" and adds up
the evidence. Independent anchors agreeing on one X is what makes a detection trustworthy.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class Needle:
    core: bytes              # literal bytes searched for in the host process
    system: str
    group: str               # evidence group, e.g. "vectors", "globals", "rom", "romcopy"
    transform: str           # byte order the needle is expressed in
    meta: Dict = field(default_factory=dict)


@dataclass
class Hit:
    system: str
    group: str
    transform: str
    kind: str                # "ram" (votes for RAM base) | "rom" (votes for ROM-buffer base)
    base: int                # host address of emulated address 0 (RAM) / of ROM byte 0 (ROM)
    detail: str
    meta: Dict = field(default_factory=dict)


class System:
    name = "?"
    transforms: List[str] = []
    base_alignment = 4        # emulated words are word-aligned in any emulator; a misaligned base is impossible

    def needles(self, rom: Optional[bytes]) -> List[Needle]:
        raise NotImplementedError

    def verify(self, needle: Needle, hit_addr: int, pm) -> List[Hit]:
        raise NotImplementedError

    def group_bits(self, group: str, hits: List[Hit]) -> float:
        raise NotImplementedError

    def ram_size_hint(self) -> List[int]:
        return []
