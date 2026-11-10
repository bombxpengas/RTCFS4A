"""Headless harness: run a real emulator on a ROM, snapshot it at several moments, run the finder against
its memory, and score the result against ground truth the emulator itself reports."""
from __future__ import annotations

import os
import subprocess
import time
from dataclasses import dataclass
from typing import List, Optional

from .finder import Report, find_ram
from .procmem import ProcessMemory
from .systems import ALL_SYSTEMS

BUNDLE = os.environ.get("EMULAB_BUNDLE", "/home/claude/emu/mupen64plus-bundle-linux64-2.6.0")
BUILD = os.environ.get("EMULAB_BUILD", "/tmp/emulab-build")


@dataclass
class Run:
    proc: subprocess.Popen
    pid: int
    truth: int

    def stop(self):
        self.proc.kill()
        self.proc.wait()


def start_mupen(rom_path: str, seconds: int = 60, press: str = "", emumode: int = 2) -> Run:
    env = dict(os.environ, LD_LIBRARY_PATH=f"{BUILD}/stubs:{BUNDLE}", EMULAB_EMUMODE=str(emumode))
    args = [f"{BUILD}/m64p_host", BUNDLE, BUILD, rom_path, str(seconds)] + ([press] if press else [])
    p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env, text=True)
    pid = truth = None
    for line in p.stdout:
        if line.startswith("PID"):
            pid = int(line.split()[1])
        elif line.startswith("RDRAM"):
            truth = int(line.split()[1], 16)
            break
    if pid is None or truth is None:
        p.kill()
        raise RuntimeError("host did not report ground truth")
    return Run(p, pid, truth)
