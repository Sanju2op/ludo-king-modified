"""
patch_dice_ci.py
Patches libil2cpp.so dice range from 1-6 to 1-10.
Used by GitHub Actions CI pipeline.
"""
import struct, os, sys

try:
    from capstone import *
    from capstone.arm64 import *
except ImportError:
    os.system("pip install capstone -q")
    from capstone import *
    from capstone.arm64 import *

SO = "extracted_libs/lib/arm64-v8a/libil2cpp.so"

def parse_segs(data):
    e_phoff = struct.unpack_from('<Q', data, 0x20)[0]
    e_phentsize = struct.unpack_from('<H', data, 0x36)[0]
    e_phnum = struct.unpack_from('<H', data, 0x38)[0]
    segs = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        if struct.unpack_from('<I', data, off)[0] == 1:
            segs.append((struct.unpack_from('<Q', data, off+0x10)[0],
                         struct.unpack_from('<Q', data, off+0x08)[0],
                         struct.unpack_from('<Q', data, off+0x20)[0]))
    return segs

def rva2off(segs, rva):
    for v, fo, fsz in segs:
        if v <= rva < v + fsz:
            return fo + (rva - v)
    return None

def movz_w(reg, imm):
    v = (0b0 << 31) | (0b10 << 29) | (0b100101 << 23) | (0 << 21) | (imm << 5) | reg
    return struct.pack('<I', v)

print(f"Reading {SO}...")
with open(SO, 'rb') as f:
    data = bytearray(f.read())

segs = parse_segs(data)
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

# Anchor: BL instruction calling Random.Range at RVA 0x22927A8
BL_RVA  = 0x22927A8
BL_FILE = rva2off(segs, BL_RVA)
if BL_FILE is None:
    print("ERROR: Could not map BL_RVA to file offset!")
    sys.exit(1)

# Patch 1: ldr w1, [x19, #0x18] -> movz w1, #10  (RVA 0x2292774)
foff1 = BL_FILE + (0x2292774 - BL_RVA)
b4 = bytes(data[foff1:foff1+4])
insns = list(md.disasm(b4, 0x2292774))
if insns and insns[0].mnemonic == 'ldr':
    data[foff1:foff1+4] = movz_w(1, 10)
    print(f"[OK] Patch 1: {insns[0].mnemonic} {insns[0].op_str} -> movz w1, #10")
else:
    print(f"[WARN] Patch 1 unexpected instruction: {[i.mnemonic for i in insns]}")

# Patch 2: add w1, w8, #1 -> movz w1, #11  (RVA 0x22927A4)
foff2 = BL_FILE + (0x22927A4 - BL_RVA)
b4 = bytes(data[foff2:foff2+4])
insns = list(md.disasm(b4, 0x22927A4))
if insns and insns[0].mnemonic == 'add':
    data[foff2:foff2+4] = movz_w(1, 11)
    print(f"[OK] Patch 2: {insns[0].mnemonic} {insns[0].op_str} -> movz w1, #11")
else:
    print(f"[WARN] Patch 2 unexpected instruction: {[i.mnemonic for i in insns]}")

with open(SO, 'wb') as f:
    f.write(data)
print(f"[DONE] Patched SO written: {SO}")
