"""emulab: find an emulated console's RAM inside an emulator process, and prove it.

See README.md in the parent folder for the design. Public entry points:
    emulab.finder.find_ram(pm, systems, rom=None)   -> ranked Detections
    emulab.lab                                     -> headless training / evaluation harness
"""
