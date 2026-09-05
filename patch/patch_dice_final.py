"""
patch_dice_final.py
Targeted patch of the two dice random call sites in libil2cpp.so.

Dice call 1 (main path): RVA 0x2292774  ldr w1, [x19, #0x18] → movz w1, #10
Dice call 2 (fallback):  RVA 0x22927A4  add w1, w8, #1       → movz w1, #11
"""
import struct, shutil, os

try:
    from capstone import *
    from capstone.arm64 import *
except ImportError:
    os.system("pip install capstone -q")
    from capstone import *
    from capstone.arm64 import *

SO_SRC = r"E:\Dev\ludo-king-modified\xapk_extracted\arm64_extracted\lib\arm64-v8a\libil2cpp.so"
SO_OUT = r"E:\Dev\ludo-king-modified\xapk_extracted\arm64_extracted\lib\arm64-v8a\libil2cpp_patched.so"

# Known from disassembly + dump analysis
# File offset = 0x228E7A8 (for BL at 0x22927A8) - delta
# BL at RVA 0x22927A8 → file 0x228E7A8  (from disasm_dice_call.py output)
BL_RVA  = 0x22927A8
BL_FILE = 0x228E7A8  # confirmed from Python script output

def rva_to_file(rva):
    """Use known anchor: BL at 0x22927A8 = file 0x228E7A8"""
    return BL_FILE + (rva - BL_RVA)

def movz_w(reg, imm, shift=0):
    hw = shift // 16
    v = (0b0 << 31) | (0b10 << 29) | (0b100101 << 23) | (hw << 21) | (imm << 5) | reg
    return struct.pack('<I', v)

def main():
    print(f"Reading {SO_SRC}")
    with open(SO_SRC, 'rb') as f:
        data = bytearray(f.read())
    print(f"  Size: {len(data)/1024/1024:.1f} MB")

    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True

    patches = []

    # ── PATCH 1: ldr w1, [x19, #0x18]  at RVA 0x2292774 ──────────────────────
    # From disassembly: this loads the dice max value from the dice struct field
    # Replacing with MOVZ W1, #10 → Random.Range(0, 10) = 0-9; game adds +1 → 1-10
    rva1   = 0x2292774
    foff1  = rva_to_file(rva1)
    b4_1   = bytes(data[foff1 : foff1+4])
    insns1 = list(md.disasm(b4_1, rva1))

    if insns1:
        ins = insns1[0]
        print(f"\nPatch 1: @ RVA 0x{rva1:X} (file 0x{foff1:X})")
        print(f"  Current: {ins.mnemonic} {ins.op_str}  [{b4_1.hex()}]")
        if ins.mnemonic == 'ldr':
            new_b = movz_w(1, 10)
            patches.append((foff1, b4_1, new_b, rva1, "ldr w1,[x19,#0x18] -> movz w1,#10"))
            print(f"  Patch to: movz w1, #10  [{new_b.hex()}]  [OK]")
        else:
            print(f"  [!] Unexpected instruction, skipping")

    # ── PATCH 2: add w1, w8, #1  at RVA 0x22927A4 ────────────────────────────
    # Fallback path when dice object is null — W8 is return value of helper func
    # Replacing with MOVZ W1, #11 → Random.Range(1, 11) = 1-10
    rva2   = 0x22927A4
    foff2  = rva_to_file(rva2)
    b4_2   = bytes(data[foff2 : foff2+4])
    insns2 = list(md.disasm(b4_2, rva2))

    if insns2:
        ins = insns2[0]
        print(f"\nPatch 2: @ RVA 0x{rva2:X} (file 0x{foff2:X})")
        print(f"  Current: {ins.mnemonic} {ins.op_str}  [{b4_2.hex()}]")
        if ins.mnemonic == 'add':
            new_b = movz_w(1, 11)
            patches.append((foff2, b4_2, new_b, rva2, "add w1,w8,#1 -> movz w1,#11"))
            print(f"  Patch to: movz w1, #11  [{new_b.hex()}]  [OK]")
        else:
            print(f"  [!] Unexpected instruction, skipping")

    # ── Also check the FIRST Random.Range call at 0x2292778 ──────────────────
    # Print context so we can verify
    rva_ctx = 0x2292760
    foff_ctx = rva_to_file(rva_ctx)
    code_ctx = bytes(data[foff_ctx : foff_ctx + 80])
    print(f"\nContext verification (around first Random.Range call):")
    for ins in md.disasm(code_ctx, rva_ctx):
        marker = " <-- PATCHED" if any(p[3] == ins.address for p in patches) else ""
        print(f"  0x{ins.address:X}: {ins.mnemonic} {ins.op_str}{marker}")

    # ── Apply patches ──────────────────────────────────────────────────────────
    print(f"\nApplying {len(patches)} patches...")
    for (foff, old_b, new_b, rva, desc) in patches:
        data[foff : foff+4] = new_b
        print(f"  [OK] 0x{rva:X}: {desc}")

    shutil.copy(SO_SRC, SO_SRC + ".bak")
    with open(SO_OUT, 'wb') as f:
        f.write(data)
    print(f"\n[DONE] Written: {SO_OUT}")
    print(f"       Backup:  {SO_SRC}.bak")

if __name__ == '__main__':
    main()
