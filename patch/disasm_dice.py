"""
disasm_dice.py — Disassembles dice-related functions from libil2cpp.so
to discover the exact ARM64 instruction pattern used for the random dice roll.
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

FUNCS = {
    "OnDiceRoll":            0x20059BC,
    "CompTurn":              0x2001674,
    "OnDiceRollForAuto":     0x200573C,
    "ExcludeCompDiceValues": 0x200CB70,
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

def main():
    print(f"Reading SO ...")
    with open(SO_PATH, 'rb') as f:
        data = f.read()
    segs = parse_load_segs(data)
    
    print("LOAD segments:")
    for v, fo, fsz in segs:
        print(f"  VA=0x{v:X}  FileOffset=0x{fo:X}  Size=0x{fsz:X}")
    print()
    
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True

    for name, rva in FUNCS.items():
        foff = rva2off(segs, rva)
        if foff is None:
            print(f"[!] {name} RVA 0x{rva:X} -> NOT MAPPED")
            continue
        print(f"=== {name} RVA=0x{rva:X} FileOffset=0x{foff:X} ===")
        code = data[foff : foff + 600]
        insns = list(md.disasm(code, rva))
        
        # Print each instruction, highlight any loading of constants 1-12
        for ins in insns[:80]:
            # Check if this instruction loads a small integer (dice-range relevant)
            highlight = ""
            raw = ins.bytes
            if len(raw) == 4:
                val = struct.unpack_from('<I', raw)[0]
                # Check MOVZ 32-bit
                if (val >> 31) == 0 and ((val >> 29) & 3) == 2 and ((val >> 23) & 0x3F) == 0x25:
                    imm = (val >> 5) & 0xFFFF
                    if 1 <= imm <= 15:
                        highlight = f"  <-- MOVZ constant #{imm}"
                # Check MOV immediate alias (ORR with Xzr/Wzr) 
                if (val >> 23) & 0x1FF == 0b001100100 and (val & 0x1F) != 31:
                    pass  # skip for now
            print(f"  0x{ins.address:X}:  {ins.mnemonic:<8} {ins.op_str}{highlight}")
        print()

if __name__ == '__main__':
    main()
