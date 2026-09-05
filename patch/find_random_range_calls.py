"""
find_random_range_calls.py
Finds ALL calls to UnityEngine.Random.Range(int,int) in libil2cpp.so
and checks what constants are loaded before each call.
"""
import struct, os

try:
    from capstone import *
    from capstone.arm64 import *
except ImportError:
    os.system("pip install capstone -q")
    from capstone import *
    from capstone.arm64 import *

SO_PATH = r"E:\Dev\ludo-king-modified\xapk_extracted\arm64_extracted\lib\arm64-v8a\libil2cpp.so"
RANDOM_RANGE_INT_RVA = 0x47673A0   # UnityEngine.Random.Range(int minInclusive, int maxExclusive)

def parse_load_segs(data):
    e_phoff     = struct.unpack_from('<Q', data, 0x20)[0]
    e_phentsize = struct.unpack_from('<H', data, 0x36)[0]
    e_phnum     = struct.unpack_from('<H', data, 0x38)[0]
    segs = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        if struct.unpack_from('<I', data, off)[0] == 1:
            vaddr  = struct.unpack_from('<Q', data, off + 0x10)[0]
            foff   = struct.unpack_from('<Q', data, off + 0x08)[0]
            filesz = struct.unpack_from('<Q', data, off + 0x20)[0]
            segs.append((vaddr, foff, filesz))
    return segs

def rva2off(segs, rva):
    for v, fo, fsz in segs:
        if v <= rva < v + fsz:
            return fo + (rva - v)
    return None

def off2rva(segs, off):
    for v, fo, fsz in segs:
        if fo <= off < fo + fsz:
            return v + (off - fo)
    return None

def encode_bl(from_addr, to_addr):
    """Encode a BL instruction."""
    offset = (to_addr - from_addr) >> 2
    offset &= 0x3FFFFFF
    return struct.pack('<I', (0b000101 << 26) | offset)

def decode_bl_target(instr_bytes, from_addr):
    """Get target address of a BL instruction."""
    val = struct.unpack_from('<I', instr_bytes)[0]
    if (val >> 26) != 0b000101:
        return None
    imm26 = val & 0x3FFFFFF
    if imm26 & (1 << 25):
        imm26 |= ~0x3FFFFFF
    return from_addr + (imm26 << 2)

def movz_w(reg, imm, shift=0):
    hw = shift // 16
    v = (0b0 << 31) | (0b10 << 29) | (0b100101 << 23) | (hw << 21) | (imm << 5) | reg
    return struct.pack('<I', v)

def decode_movz_w(b4):
    v = struct.unpack_from('<I', b4)[0]
    if (v >> 31) == 0 and ((v >> 29) & 3) == 2 and ((v >> 23) & 0x3F) == 0x25:
        hw = (v >> 21) & 3
        imm = (v >> 5) & 0xFFFF
        rd  = v & 0x1F
        return rd, imm, hw * 16
    return None

def main():
    print(f"Reading {SO_PATH}")
    with open(SO_PATH, 'rb') as f:
        data = bytearray(f.read())
    print(f"  Size: {len(data)/1024/1024:.1f} MB")
    segs = parse_load_segs(data)

    rand_foff = rva2off(segs, RANDOM_RANGE_INT_RVA)
    print(f"  Random.Range(int,int) at RVA=0x{RANDOM_RANGE_INT_RVA:X} FileOff=0x{rand_foff:X}")

    # Scan ALL bytes in executable segments for BL to Random.Range(int,int)
    # BL encodes as: [31:26]=000101, [25:0]=signed offset/4
    print("\nSearching for all calls to Random.Range(int,int) ...")
    calls = []

    # Only scan segment 1 (the main code segment, segment 0 is small headers)
    scan_segs = [(v, fo, fsz) for v, fo, fsz in segs if fo > 0]
    
    for (seg_va, seg_fo, seg_fsz) in scan_segs:
        for i in range(0, seg_fsz - 3, 4):
            foff = seg_fo + i
            rva  = seg_va + i
            b4   = bytes(data[foff:foff+4])
            target = decode_bl_target(b4, rva)
            if target == RANDOM_RANGE_INT_RVA:
                calls.append((rva, foff))

    print(f"  Found {len(calls)} calls to Random.Range(int,int)")

    # For each call site, look back 10 instructions for MOVZ Wn, #imm
    interesting = []  # (call_rva, w0_val, w1_val, foff_of_bl)
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

    for (call_rva, call_foff) in calls:
        # Read 40 bytes before the BL (10 instructions)
        pre_foff = call_foff - 40
        if pre_foff < 0:
            continue
        pre_code = bytes(data[pre_foff : call_foff])
        pre_rva  = call_rva - 40
        
        insns = list(md.disasm(pre_code, pre_rva))
        w0_val = None
        w1_val = None

        for ins in reversed(insns):
            info = decode_movz_w(ins.bytes)
            if info:
                reg, imm, sh = info
                if sh == 0:
                    if reg == 0 and w0_val is None:
                        w0_val = imm
                    elif reg == 1 and w1_val is None:
                        w1_val = imm
            if w0_val is not None and w1_val is not None:
                break

        if w1_val is not None and 2 <= w1_val <= 20:
            interesting.append((call_rva, w0_val, w1_val, call_foff))
            marker = " <-- DICE CANDIDATE!" if w1_val in (6, 7) else ""
            print(f"  Call @ RVA 0x{call_rva:X}  W0={w0_val} W1={w1_val} (Range({w0_val},{w1_val})){marker}")

    print(f"\n{len(interesting)} calls with small max value")
    
    # Now patch those with W1=7 (Random.Range(1,7) = dice 1-6) -> W1=11
    patches = []
    for (call_rva, w0_val, w1_val, call_foff) in interesting:
        if w1_val == 7 and w0_val in (0, 1):
            # Find the MOVZ W1, #7 instruction before this call
            pre_foff = call_foff - 40
            pre_code = bytes(data[pre_foff : call_foff])
            pre_rva  = call_rva - 40
            insns = list(md.disasm(pre_code, pre_rva))
            for ins in reversed(insns):
                info = decode_movz_w(ins.bytes)
                if info and info[0] == 1 and info[1] == 7 and info[2] == 0:
                    patch_foff = pre_foff + (ins.address - pre_rva)
                    old_b = bytes(data[patch_foff:patch_foff+4])
                    new_b = movz_w(1, 11)
                    patches.append((patch_foff, old_b, new_b, ins.address))
                    print(f"  [PATCH] MOVZ W1, #7->11 at RVA 0x{ins.address:X} file 0x{patch_foff:X}")
                    break

    print(f"\n{len(patches)} dice patches to apply")
    if patches:
        for (foff, old_b, new_b, addr) in patches:
            data[foff:foff+4] = new_b
        out = SO_PATH.replace('.so', '_patched.so')
        with open(out, 'wb') as f:
            f.write(data)
        print(f"[OK] Written: {out}")
    else:
        print("[!] No patches. Dice likely uses different encoding or is server-side.")
        # Print all calls summary
        print("\nAll Random.Range(int,int) call sites:")
        for (call_rva, w0_val, w1_val, call_foff) in interesting:
            print(f"  0x{call_rva:X}: Range({w0_val}, {w1_val})")

if __name__ == '__main__':
    main()
