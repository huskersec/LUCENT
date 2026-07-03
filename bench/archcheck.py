#!/usr/bin/env python3
"""Dump the PE header fields that decide whether a binary will launch on this
OS — to pin down an ERROR_EXE_MACHINE_TYPE_MISMATCH (Win32 0n216).

Reads the COFF + optional header directly (no deps) and prints machine type,
PE32/PE32+ magic, subsystem, and the required-OS/subsystem versions, plus a
raw hexdump of the header region so you can verify by eye.

Usage: python archcheck.py [path-to-exe]   (default: <sandbox>\\vuln.exe)
"""
import os
import platform
import struct
import sys

exe = sys.argv[1] if len(sys.argv) > 1 else r"C:\lucent\sandbox\vuln.exe"

MACHINES = {0x8664: "x64 (AMD64)", 0x14c: "x86 (i386)", 0xaa64: "ARM64",
            0x1c0: "ARM", 0x1c4: "ARMNT (Thumb-2)", 0x0: "UNKNOWN/any"}
MAGICS = {0x10b: "PE32 (32-bit)", 0x20b: "PE32+ (64-bit)", 0x107: "ROM"}
SUBSYS = {1: "native", 2: "GUI", 3: "console"}

print("OS PROCESSOR_ARCHITECTURE:", os.environ.get("PROCESSOR_ARCHITECTURE"),
      "| platform.machine():", platform.machine())

try:
    data = open(exe, "rb").read()
except FileNotFoundError:
    print("MISSING:", exe)
    sys.exit(1)

print(f"{exe}  ({len(data)} bytes)")
if len(data) < 64 or data[:2] != b"MZ":
    print("  not an MZ/PE file (truncated or not an executable)")
    sys.exit(1)

e = struct.unpack("<I", data[60:64])[0]            # e_lfanew
if e + 24 > len(data) or data[e:e + 4] != b"PE\x00\x00":
    print(f"  no PE signature at e_lfanew={hex(e)} — corrupt PE")
    sys.exit(1)

machine, nsec = struct.unpack("<HH", data[e + 4:e + 8])
characteristics = struct.unpack("<H", data[e + 22:e + 24])[0]
opt = e + 24                                        # optional header start
magic = struct.unpack("<H", data[opt:opt + 2])[0]
# These fields sit at the same offset for PE32 and PE32+ (layout realigns at +32)
major_os, minor_os = struct.unpack("<HH", data[opt + 40:opt + 44])
major_sub, minor_sub = struct.unpack("<HH", data[opt + 48:opt + 52])
subsystem = struct.unpack("<H", data[opt + 68:opt + 70])[0]

print(f"  machine        : {hex(machine)} = {MACHINES.get(machine, 'UNKNOWN')}")
print(f"  opt magic      : {hex(magic)} = {MAGICS.get(magic, 'UNKNOWN')}")
print(f"  subsystem      : {subsystem} = {SUBSYS.get(subsystem, '?')}")
print(f"  min OS version : {major_os}.{minor_os}   subsystem ver: {major_sub}.{minor_sub}")
print(f"  characteristics: {hex(characteristics)}"
      f"  (DLL={'yes' if characteristics & 0x2000 else 'no'},"
      f" EXEC={'yes' if characteristics & 0x0002 else 'no'},"
      f" 32BIT={'yes' if characteristics & 0x0100 else 'no'})")
print(f"  sections       : {nsec}")

raw = data[e:e + 40]
print("  raw [PE sig | COFF hdr | opt magic]:",
      " ".join(f"{b:02x}" for b in raw))

# --- verdict ---------------------------------------------------------------
expect = {"AMD64": 0x8664, "ARM64": 0xaa64, "X86": 0x14c}.get(
    os.environ.get("PROCESSOR_ARCHITECTURE", ""), None)
if machine == 0x8664:
    print("  => x64 binary. If it still gave Win32 0n216, the cause is NOT the"
          " machine type -- look at magic / min-OS-version / corruption above.")
elif expect and machine != expect and not (machine == 0x14c and expect == 0x8664):
    print(f"  => MISMATCH: {MACHINES.get(machine)} binary on"
          f" {os.environ.get('PROCESSOR_ARCHITECTURE')} Windows == the 0n216."
          " Rebuild x64 (build.bat forces vcvars64).")
