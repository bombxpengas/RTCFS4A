"""Which memory is worth scanning for emulated RAM — learned from a real Android capture.

A phone process is mostly memory that can never hold a console's RAM: the ART heaps (hundreds of MB, and
the biggest mappings in the process), compiled-code caches, GPU/graphics buffers, system libraries, property
areas. Scanning them wastes time and RAM next to a running game. Candidates are ranked instead:

    HIGH   anonymous rw memory (unnamed, [anon:scudo:*], [anon:libc_malloc], [heap], .bss) and big
           memfd/ashmem-style shared mappings (emulators use these to mirror memory views)
    LOW    other file-backed writable memory (libraries' .data) and read-only mappings of ROM-like files
    SKIP   everything that cannot hold RAM, with the reason (shown in diagnostics)
"""
from __future__ import annotations

from typing import Tuple

from .procmem import Region

_SKIP_EXT = (".vdex", ".odex", ".oat", ".art", ".dex", ".apk", ".jar", ".ttf", ".otf", ".db", ".pma", ".so", ".relro")
_SKIP_PATH = ("dalvik", "jit-cache", "jit-zygote", "kgsl", "/dev/", "__properties__", "linker_alloc", "[stack", "[vvar",
              "[vdso", "[vsyscall", "/system/", "/apex/", "/vendor/", "/product/", "/system_ext/", "/odm/", "framework",
              "gralloc", "dmabuf", "[anon:guard", "GWP-ASan", "Pre-zygote", "boot-image", "app_webview", "u:object_r")
_ROMLIKE = (".z64", ".n64", ".v64", ".rom", ".gba", ".nds", ".nes", ".sfc", ".smc", ".gb", ".gbc", ".md", ".bin", ".iso", ".cso")


def classify(r: Region) -> Tuple[str, str]:
    """-> (priority, reason) with priority in HIGH / LOW / SKIP."""
    p = r.path
    if not r.readable:
        return "SKIP", "not readable"
    if "x" in r.perms:
        return "SKIP", "executable (code, not data)"
    if r.size < 4096:
        return "SKIP", "tiny"
    low = p.lower()
    if low.endswith(_ROMLIKE):
        return "LOW", "ROM-like file mapping"
    for t in _SKIP_PATH:
        if t.lower() in low:
            return "SKIP", f"system/ART/GPU memory ({t.strip('/[')})"
    if low.endswith(_SKIP_EXT):
        return "SKIP", "library/oat/dex image"
    if not r.writable:
        return "SKIP", "read-only"
    if p == "" or p.startswith("[anon") or p == "[heap]" or p.startswith("/memfd:") or "ashmem" in low or "anon_shmem" in low:
        return "HIGH", "anonymous/shared writable memory"
    return "LOW", "file-backed writable (library data)"
