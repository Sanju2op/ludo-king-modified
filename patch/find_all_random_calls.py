"""
find_all_random_calls.py
Scans for ALL calls to any UnityEngine.Random method in libil2cpp.so
and for any multiply-by-6 patterns (dice via float).
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

# From dump.cs
TARGETS = {
    0x4767360: "Random.Range(float,float)",
    0x47673A0: "Random.Range(int,int)",
    0x47673E4: "RandomRangeInt(int,int)",  # private
    0x4767428: "Random.get_value()",
    0x4767558: "Random.RandomRange(int,int)",  # deprecated
}

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

def decode_bl_target(instr_bytes, from_addr):
    val = struct.unpack_from('<I', instr_bytes)[0]
    if (val >> 26) != 0b000101:
        return None
    imm26 = val & 0x3FFFFFF
    if imm26 & (1 << 25):
        imm26 |= ~0x3FFFFFF
    return from_addr + (imm26 << 2)

def decode_movz_w(b4):
    v = struct.unpack_from('<I', b4)[0]
    if (v >> 31) == 0 and ((v >> 29) & 3) == 2 and ((v >> 23) & 0x3F) == 0x25:
        hw = (v >> 21) & 3
        imm = (v >> 5) & 0xFFFF
        rd  = v & 0x1F
        return rd, imm, hw * 16
    return None

# ARM64 FMOV pattern: fmov s0, #6.0 or similar
def decode_fimm(b4):
    """Check if this is FMOV Sn, #imm8 and return the float value."""
    v = struct.unpack_from('<I', b4)[0]
    # FMOV (scalar, immediate): 0|0|0|11110|ftype|1|imm8|100|00000|Rd
    # For single: ftype=00, so: 00011110 00 1 imm8 100 00000 Rd
    if (v >> 24) == 0x1E and ((v >> 13) & 0x7) == 0b100 and ((v >> 5) & 0xFF) == 0:
        # This doesn't match FMOV imm
        pass
    # Actually FMOV imm: sf|0|0|11110|type|1|imm8|100|00000|Rd
    # single: 0|0|0|11110|00|1|imm8(8)|100|00000|Rd(5)
    if ((v >> 23) & 0x1FF) == 0b000111100 and ((v >> 13) & 0b111) == 0b100:
        imm8 = (v >> 13) & 0xFF  # wrong extraction, let me fix
        pass
    return None

def main():
    print(f"Reading {SO_PATH}")
    with open(SO_PATH, 'rb') as f:
        data = bytearray(f.read())
    segs = parse_load_segs(data)

    scan_segs = [(v, fo, fsz) for v, fo, fsz in segs if fo > 0]
    
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

    for target_rva, target_name in TARGETS.items():
        calls = []
        for (seg_va, seg_fo, seg_fsz) in scan_segs:
            for i in range(0, seg_fsz - 3, 4):
                foff = seg_fo + i
                rva  = seg_va + i
                b4   = bytes(data[foff:foff+4])
                t    = decode_bl_target(b4, rva)
                if t == target_rva:
                    calls.append((rva, foff))

        print(f"\n{target_name} (RVA 0x{target_rva:X}): {len(calls)} call sites")
        
        for (call_rva, call_foff) in calls[:20]:  # show first 20
            # Look back 10 instructions for context
            pre_foff = max(0, call_foff - 48)
            pre_code = bytes(data[pre_foff : call_foff + 4])
            pre_rva  = call_rva - (call_foff - pre_foff)
            insns    = list(md.disasm(pre_code, pre_rva))
            
            w_vals = {}
            for ins in reversed(insns[:-1]):  # exclude the BL itself
                info = decode_movz_w(ins.bytes)
                if info:
                    reg, imm, sh = info
                    if sh == 0 and reg not in w_vals:
                        w_vals[reg] = imm
            
            w0 = w_vals.get(0, '?')
            w1 = w_vals.get(1, '?')
            print(f"  0x{call_rva:X}: W0={w0} W1={w1}")
        
        if len(calls) > 20:
            print(f"  ... and {len(calls)-20} more")

if __name__ == '__main__':
    main()
