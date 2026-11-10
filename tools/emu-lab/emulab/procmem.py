"""Robust access to another process's memory (Linux/Android, needs root or same uid + ptrace rights).

Two lessons from the first real emulator run are built in:
  * big emulator arenas contain holes: a failed read must degrade to "skip those pages", never drop a
    whole chunk (the first scan lost the ROM that way);
  * arenas are mostly never-touched pages. /proc/pid/pagemap says which pages are present, so we only
    read those — a 512 MB arena with 10 MB touched costs 10 MB of reads, which is what keeps this light
    enough to run on a phone next to a running game.
"""
from __future__ import annotations

import os
import re
import struct
from dataclasses import dataclass
from typing import Iterator, List, Tuple

PAGE = 4096
_MAPS = re.compile(r"([0-9a-f]+)-([0-9a-f]+) (\S{4}) ([0-9a-f]+) \S+ \S+\s*(.*)")


@dataclass(frozen=True)
class Region:
    start: int
    end: int
    perms: str
    offset: int
    path: str

    @property
    def size(self) -> int:
        return self.end - self.start

    @property
    def readable(self) -> bool:
        return self.perms[0] == "r"

    @property
    def writable(self) -> bool:
        return self.perms[1] == "w"

    @property
    def anonymous(self) -> bool:
        return self.path == "" or self.path.startswith("[anon") or self.path in ("[heap]",)

    def contains(self, addr: int) -> bool:
        return self.start <= addr < self.end


class ProcessMemory:
    def __init__(self, pid: int):
        self.pid = pid
        self._mem = os.open(f"/proc/{pid}/mem", os.O_RDONLY)
        try:
            self._pagemap = os.open(f"/proc/{pid}/pagemap", os.O_RDONLY)
        except OSError:
            self._pagemap = None
        self.bytes_read = 0

    def close(self) -> None:
        os.close(self._mem)
        if self._pagemap is not None:
            os.close(self._pagemap)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()

    # ---- maps -----------------------------------------------------------------------------
    def regions(self) -> List[Region]:
        out = []
        with open(f"/proc/{self.pid}/maps") as f:
            for line in f:
                m = _MAPS.match(line)
                if m:
                    out.append(Region(int(m.group(1), 16), int(m.group(2), 16), m.group(3), int(m.group(4), 16), m.group(5).strip()))
        return out

    # ---- presence -------------------------------------------------------------------------
    def present_runs(self, start: int, end: int) -> List[Tuple[int, int]]:
        """Address runs [a, b) of pages that are resident (or swapped). Falls back to the whole range."""
        if self._pagemap is None:
            return [(start, end)]
        first, last = start // PAGE, (end + PAGE - 1) // PAGE
        try:
            raw = os.pread(self._pagemap, (last - first) * 8, first * 8)
        except OSError:
            return [(start, end)]
        runs: List[Tuple[int, int]] = []
        cur = None
        n = len(raw) // 8
        entries = struct.unpack(f"<{n}Q", raw[: n * 8])
        for i, e in enumerate(entries):
            present = bool(e >> 63 & 1) or bool(e >> 62 & 1)
            if present and cur is None:
                cur = first + i
            elif not present and cur is not None:
                runs.append((cur * PAGE, (first + i) * PAGE))
                cur = None
        if cur is not None:
            runs.append((cur * PAGE, (first + n) * PAGE))
        return [(max(a, start), min(b, end)) for a, b in runs]

    # ---- reads ----------------------------------------------------------------------------
    def read(self, addr: int, n: int) -> bytes:
        """Reads n bytes; unreadable pages come back as zeros (never raises for holes)."""
        try:
            data = os.pread(self._mem, n, addr)
            if len(data) == n:
                self.bytes_read += n
                return data
        except OSError:
            pass
        out = bytearray(n)
        pos = 0
        while pos < n:
            a = addr + pos
            step = min(PAGE - (a % PAGE), n - pos)
            try:
                chunk = os.pread(self._mem, step, a)
                out[pos:pos + len(chunk)] = chunk
                self.bytes_read += len(chunk)
            except OSError:
                pass
            pos += step
        return bytes(out)

    def chunks(self, region: Region, chunk: int = 4 << 20, overlap: int = 64) -> Iterator[Tuple[int, bytes]]:
        """Yields (address, bytes) over the resident parts of a region, overlapping so a needle that
        straddles two chunks is still seen. Chunks never cross a non-resident gap."""
        for a, b in self.present_runs(region.start, region.end):
            pos = a
            while pos < b:
                n = min(chunk + overlap, b - pos)
                yield pos, self.read(pos, n)
                pos += chunk
