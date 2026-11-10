"""The generic finder: scan the process once, collect verified hits, let them vote, report the evidence.

    detections = find_ram(pm, ALL_SYSTEMS, rom=rom_bytes_or_None).ram

Why voting rather than "find the pattern": every single pattern also occurs by accident somewhere
(libultra's exception stub exists once more in the game's code before it is copied to RAM; the cartridge
image contains every ROM fingerprint too). A real RAM base is the address that *several independent*
anchors agree on, so detections are scored by summed evidence and reported with their proof.
"""
from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .procmem import ProcessMemory, Region
from .regions import classify
from .systems.base import Hit, Needle, System

TIERS = [(80.0, "certain"), (40.0, "high"), (24.0, "possible")]


def tier_of(bits: float) -> str:
    for threshold, name in TIERS:
        if bits >= threshold:
            return name
    return "weak"


@dataclass
class Detection:
    system: str
    kind: str                     # "ram" | "rom"
    transform: str
    base: int
    bits: float
    evidence: Dict[str, Tuple[float, List[str]]]
    region: Optional[Region] = None
    ambiguous_with: List[int] = field(default_factory=list)   # other bases resting on exactly the same evidence
    live: Optional[float] = None       # fraction of sampled windows that changed between two looks (None = not measured)
    static_copy: bool = False          # identical evidence to a live candidate, but it never changes: save-state/rewind copy

    @property
    def tier(self) -> str:
        t = tier_of(self.bits)
        # identical evidence supports several bases (e.g. one lone exception vector could be any of four):
        # never claim more than "possible" until something else breaks the tie
        return "possible" if self.ambiguous_with and t in ("certain", "high") else t

    @property
    def region_offset(self) -> Optional[int]:
        return None if self.region is None else self.base - self.region.start

    def summary(self) -> str:
        live = "" if self.live is None else (" STATIC-COPY" if self.static_copy else f" live={self.live:.2%}")
        ev = ", ".join(f"{g}({b:.0f}b)" for g, (b, _) in self.evidence.items())
        where = f"  in {self.region.size >> 20}MB {self.region.perms} mapping +0x{self.region_offset:x}" if self.region else ""
        return f"{self.system}/{self.kind} base=0x{self.base:x} [{self.transform}] {self.bits:.0f} bits ({self.tier}){live}: {ev}{where}"


@dataclass
class Report:
    ram: List[Detection] = field(default_factory=list)
    rom: List[Detection] = field(default_factory=list)
    seconds: float = 0.0
    bytes_read: int = 0
    regions_scanned: int = 0
    needles: int = 0
    regions_skipped: int = 0
    stopped_early: bool = False


def _build(hits: List[Hit], systems: List[System], regions: List[Region]) -> Report:
    sys_by_name = {s.name: s for s in systems}
    votes: Dict[Tuple[str, str, str, int], List[Hit]] = defaultdict(list)
    for h in hits:
        if h.base % sys_by_name[h.system].base_alignment:
            continue
        votes[(h.system, h.kind, h.transform, h.base)].append(h)

    # explain away: the cartridge image also contains the bytes of the boot-time RAM copy
    rom_bases: Dict[Tuple[str, str], List[int]] = defaultdict(list)
    for k in votes:
        if k[1] == "rom":
            rom_bases[(k[0], k[2])].append(k[3])
    for k, hs in list(votes.items()):
        if k[1] != "ram":
            continue
        kept = [h for h in hs if not (h.group == "romcopy" and
                any(h.meta["copy_loc"] == rb + 0x1000 for rb in rom_bases.get((k[0], k[2]), [])))]
        if kept:
            votes[k] = kept
        else:
            del votes[k]

    # dominance: a base whose evidence is a strict subset of another base's is only an alias of it
    # (the four identical exception vectors make "vector 1 is really vector 0" look 3/4 convincing)
    def sources(hs):
        return {(h.group, h.meta["src"]) for h in hs}
    keys = list(votes)
    for k in keys:
        for k2 in keys:
            if k2 != k and k[:3] == k2[:3] and k in votes and k2 in votes:
                if sources(votes[k]) < sources(votes[k2]):
                    del votes[k]
                    break

    report = Report()
    srcmap: Dict[frozenset, List[int]] = defaultdict(list)
    for (sysname, kind, tf, base), hs in votes.items():
        srcmap[frozenset(sources(hs))].append(base)
    for (sysname, kind, tf, base), hs in votes.items():
        s = sys_by_name[sysname]
        groups: Dict[str, List[Hit]] = defaultdict(list)
        for h in hs:
            groups[h.group].append(h)
        ev = {g: (s.group_bits(g, hl), sorted({h.detail for h in hl})) for g, hl in groups.items()}
        det = Detection(sysname, kind, tf, base, sum(b for b, _ in ev.values()), ev,
                        next((r for r in regions if r.contains(base)), None),
                        [b for b in srcmap[frozenset(sources(hs))] if b != base])
        (report.ram if kind == "ram" else report.rom).append(det)
    report.ram.sort(key=lambda d: -d.bits)
    report.rom.sort(key=lambda d: -d.bits)
    return report


def find_ram(pm: ProcessMemory, systems: List[System], rom: Optional[bytes] = None,
             regions: Optional[List[Region]] = None, early_exit: bool = True, include_low: bool = True) -> Report:
    """Scans the memory worth scanning (see regions.py), highest-priority regions first, and stops as soon as a
    'certain', unambiguous detection exists — on a phone every skipped megabyte is battery and frame time."""
    t0 = time.time()
    start_bytes = pm.bytes_read
    regions = regions if regions is not None else pm.regions()
    ranked = [(classify(r), r) for r in regions]
    order = {"HIGH": 0, "LOW": 1}
    scan = sorted([(p, r) for (p, _), r in ranked if p in order and (include_low or p == "HIGH")],
                  key=lambda pr: (order[pr[0]], -pr[1].size))
    skipped = sum(1 for (p, _), r in ranked if p == "SKIP")

    by_core: Dict[bytes, List[Tuple[System, Needle]]] = defaultdict(list)
    n_needles = 0
    for s in systems:
        for nd in s.needles(rom):
            by_core[nd.core].append((s, nd))
            n_needles += 1
    max_core = max((len(c) for c in by_core), default=0)

    hits: List[Hit] = []
    seen = set()
    scanned = 0
    stopped = False
    for pri, r in scan:
        found_before = len(hits)
        for addr, data in pm.chunks(r, overlap=max_core):
            for core, owners in by_core.items():
                i = data.find(core)
                while i != -1:
                    a = addr + i
                    for s, nd in owners:
                        key = (a, id(nd))
                        if key not in seen:
                            seen.add(key)
                            for h in s.verify(nd, a, pm):
                                h.meta["src"] = a
                                hits.append(h)
                    i = data.find(core, i + 1)
        scanned += 1
        if early_exit and len(hits) > found_before:
            top = _build(hits, systems, regions).ram
            if top and top[0].tier == "certain" and not top[0].ambiguous_with and (len(top) == 1 or top[1].bits < 40):
                stopped = scanned < len(scan)
                break

    report = _build(hits, systems, regions)
    report.regions_scanned = scanned
    report.regions_skipped = skipped
    report.stopped_early = stopped
    report.needles = n_needles
    report.seconds = time.time() - t0
    report.bytes_read = pm.bytes_read - start_bytes
    return report


def measure_liveness(pm: ProcessMemory, report: Report, size_hint: int = 8 << 20, seconds: float = 0.5, top: int = 6) -> None:
    """Real RAM changes while the program runs; a save-state, rewind or duplicate buffer holding the same
    bytes does not. Hashes every 4 KB page of each candidate twice, `seconds` apart, and records the
    fraction of pages that changed. (Sparse sampling was tried first and was wrong: a game may only change a
    handful of pages per frame, and 96 random windows in 8 MB almost never land on them.)
    Candidates with equal evidence are then ordered live-first and the static ones flagged."""
    import zlib
    cands = [d for d in report.ram if d.tier != "weak"][:top]
    if not cands:
        return

    def page_hashes(d: Detection):
        out = []
        for a in range(0, size_hint, 1 << 20):
            blk = pm.read(d.base + a, min(1 << 20, size_hint - a))
            out.extend(zlib.crc32(blk[i:i + 4096]) for i in range(0, len(blk), 4096))
        return out

    before = [page_hashes(d) for d in cands]
    time.sleep(seconds)
    for d, b in zip(cands, before):
        after = page_hashes(d)
        d.live = sum(1 for x, y in zip(b, after) if x != y) / len(b)
    best_live = max(d.live for d in cands)
    for d in cands:
        d.static_copy = best_live > 0 and d.live == 0 and any(
            c.live > 0 and abs(c.bits - d.bits) < 1e-9 for c in cands)
    report.ram.sort(key=lambda d: (-d.bits, -(d.live or 0.0)))
