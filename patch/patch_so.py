"""
patch_so.py — TARGETED patch of libil2cpp.so to change dice range 1-6 -> 1-10
Ludo King APK Modification

Strategy:
  Only scans within exact function bodies (from RVA, scan 800 bytes max).
  Targets only dice-roll related functions identified from Il2CppDumper output.
  Changes MOVZ Wn, #7 -> MOVZ Wn, #11 only within those functions.
  (Random.Range(1, 7) gives 1-6; Random.Range(1, 11) gives 1-10)
"""

import sys, struct, os, shutil

try:
    from capstone import *
    from capstone.arm64 import *
except ImportError:
    os.system("pip install capstone -q")
    from capstone import *
    from capstone.arm64 import *

SO_SRC  = r"E:\Dev\ludo-king-modified\xapk_extracted\arm64_extracted\lib\arm64-v8a\libil2cpp.so"
SO_OUT  = r"E:\Dev\ludo-king-modified\xapk_extracted\arm64_extracted\lib\arm64-v8a\libil2cpp_patched.so"

# ONLY these dice-specific functions (from Il2CppDumper dump.cs)
# Each entry: (name, RVA, scan_size_bytes)
DICE_FUNCTIONS = [
    ("OnDiceRoll",              0x20059BC, 800),
    ("OnDiceRollForAuto",       0x200573C, 800),
    ("CompTurn",                0x2001674, 800),
    ("ExcludeCompDiceValues",   0x200CB70, 400),
    ("GetDiceValue_DicePad",    0x202B4BC, 400),
]

# ARM64 encoding helpers
def movz_w(reg, imm, shift=0):
    """MOVZ Wn, #imm (32-bit register, shift in {0,16,32,48})"""
    assert 0 <= imm <= 0xFFFF and 0 <= reg <= 30
    hw = shift // 16
    v = (0b0 << 31) | (0b10 << 29) | (0b100101 << 23) | (hw << 21) | (imm << 5) | reg
    return struct.pack('<I', v)

def decode_movz_w(b4):
    v = struct.unpack_from('<I', b4)[0]
    if (v >> 31) == 0 and ((v >> 29) & 0b11) == 0b10 and ((v >> 23) & 0b111111) == 0b100101:
        hw = (v >> 21) & 0b11
        imm = (v >> 5) & 0xFFFF
        rd  = v & 0x1F
        return rd, imm, hw * 16
    return None

def is_bl(b4):
    v = struct.unpack_from('<I', b4)[0]
    return (v >> 26) == 0b000101  # BL opcode

def is_b(b4):
    v = struct.unpack_from('<I', b4)[0]
    return (v >> 26) == 0b000100  # B opcode

def parse_load_segments(data):
    assert data[:4] == b'\x7fELF'
    e_phoff     = struct.unpack_from('<Q', data, 0x20)[0]
    e_phentsize = struct.unpack_from('<H', data, 0x36)[0]
    e_phnum     = struct.unpack_from('<H', data, 0x38)[0]
    segs = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        if struct.unpack_from('<I', data, off)[0] == 1:  # PT_LOAD
            vaddr  = struct.unpack_from('<Q', data, off + 0x10)[0]
            foff   = struct.unpack_from('<Q', data, off + 0x08)[0]
            filesz = struct.unpack_from('<Q', data, off + 0x20)[0]
            segs.append((vaddr, foff, filesz))
    return segs

def rva_to_file(segs, rva):
    for (vaddr, foff, fsz) in segs:
        if vaddr <= rva < vaddr + fsz:
            return foff + (rva - vaddr)
    return None

def patch_function(data, segs, name, rva, scan_bytes):
    """
    Disassemble [rva, rva+scan_bytes), find MOVZ Wn, #7 instructions
    that are within 6 instructions before a BL call, then patch #7 -> #11.
    Returns list of (file_offset, old_bytes, new_bytes).
    """
    foff = rva_to_file(segs, rva)
    if foff is None:
        print(f"  [!] {name}: cannot map RVA 0x{rva:X}")
        return []

    code = bytes(data[foff : foff + scan_bytes])
    md   = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True
    insns = list(md.disasm(code, rva))

    patches = []
    for i, ins in enumerate(insns):
        if ins.mnemonic != 'movz':
            continue
        info = decode_movz_w(ins.bytes)
        if info is None:
            continue
        reg, imm, shift = info
        if imm != 7 or shift != 0:
            continue
        # Look ahead: is there a BL within the next 6 instructions?
        found_bl = False
        for j in range(i + 1, min(i + 7, len(insns))):
            if is_bl(insns[j].bytes):
                found_bl = True
                break
            # Stop looking if we hit another function call or branch
            if is_b(insns[j].bytes):
                break
        if not found_bl:
            continue

        ins_file_off = foff + (ins.address - rva)
        old_b = bytes(data[ins_file_off : ins_file_off + 4])
        new_b = movz_w(reg, 11, shift)
        patches.append((ins_file_off, old_b, new_b, ins.address))
        rname = f"w{reg}" if reg < 31 else "wzr"
        print(f"  [+] {name}: MOVZ {rname}, #7 at RVA 0x{ins.address:X} "
              f"(file 0x{ins_file_off:X})  {old_b.hex()} -> {new_b.hex()}")
    return patches

def main():
    print(f"Loading {SO_SRC}")
    with open(SO_SRC, 'rb') as f:
        data = bytearray(f.read())
    print(f"  Size: {len(data)/1024/1024:.1f} MB")

    segs = parse_load_segments(data)
    print(f"  LOAD segments: {len(segs)}")
    for v, fo, fs in segs:
        print(f"    VA 0x{v:X}  File 0x{fo:X}  Size {fs/1024:.0f} KB")

    print()
    all_patches = []
    for (name, rva, size) in DICE_FUNCTIONS:
        print(f"Scanning {name}() at RVA 0x{rva:X}, {size} bytes ...")
        p = patch_function(data, segs, name, rva, size)
        all_patches.extend(p)

    print(f"\nTotal targeted patches: {len(all_patches)}")
    if not all_patches:
        print("\n[!] No patches found in targeted scan.")
        print("    This can happen if the game uses a different calling convention,")
        print("    or the dice RNG is done with a different instruction pattern.")
        print("    Trying wider scan with MOVZ W0/W1, #6 (some versions use 1-6 not 1-7)...")

        for (name, rva, size) in DICE_FUNCTIONS:
            foff = rva_to_file(segs, rva)
            if foff is None:
                continue
            code = bytes(data[foff : foff + size * 2])
            md   = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
            md.detail = True
            insns = list(md.disasm(code, rva))
            for i, ins in enumerate(insns):
                if ins.mnemonic != 'movz':
                    continue
                info = decode_movz_w(ins.bytes)
                if info is None:
                    continue
                reg, imm, shift = info
                if imm not in (6, 7) or shift != 0:
                    continue
                target_patch = 10 if imm == 6 else 11
                ins_file_off = foff + (ins.address - rva)
                old_b = bytes(data[ins_file_off : ins_file_off + 4])
                new_b = movz_w(reg, target_patch, shift)
                all_patches.append((ins_file_off, old_b, new_b, ins.address))
                rname = f"w{reg}"
                print(f"  [+] {name}: MOVZ {rname}, #{imm} at 0x{ins.address:X} -> #{target_patch}")

    if all_patches:
        for (foff, old_b, new_b, addr) in all_patches:
            data[foff:foff+4] = new_b
        shutil.copy(SO_SRC, SO_OUT + ".backup")
        with open(SO_OUT, 'wb') as f:
            f.write(data)
        print(f"\n[OK] Patched .so written to: {SO_OUT}")
        print(f"     Backup at: {SO_OUT}.backup")
    else:
        print("\n[FAIL] No patches applied. The dice logic may use a different mechanism.")
        print("  Possible reasons:")
        print("  1. Dice value comes from server (online games are server-authoritative)")
        print("  2. Different instruction pattern (LDR, ADRP+ADD, etc.)")
        print("  3. The RVA offsets need adjustment")
        sys.exit(1)

if __name__ == '__main__':
    main()
