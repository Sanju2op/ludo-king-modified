"""
check_setdicevalue.py
Disassembles SetDiceValue(int num) to see if it crashes on values > 6.
RVA from dump.cs line 15618: public void SetDiceValue(int num)
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

# From dump.cs: SetDiceValue(int num) at line 15618
# Need to find its RVA — search nearby in dump for the exact line
# Line 15674: private void SetDiceValue() { } -- RVA: 0x202C614
# Line 15618: public void SetDiceValue(int num) { } -- RVA slightly before 0x202C614
# Let's look at nearby RVAs from dump context lines 15610-15680:
# Line 15612: public void OnDiceAnimComplete() { } -- RVA: 0x2029B1C  
# Line 15618: public void SetDiceValue(int num) { }
# Line 15668: internal void SixDiceAnim() { } -- RVA: 0x202D1E0

# Let's check the dump.cs around line 15618 for the RVA comment
FUNCS_TO_CHECK = {
    "OnDiceAnimComplete": 0x2029B1C,   # known from dump
    "SixDiceAnim":        0x202D1E0,   # known from dump
    "SetDiceValue_priv":  0x202C614,   # private void SetDiceValue()
}

# The public SetDiceValue(int num) RVA must be between OnDiceAnimComplete and SixDiceAnim
# Let's scan between 0x202A000 and 0x202D200 to find it

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
    with open(SO_PATH, 'rb') as f:
        data = f.read()
    segs = parse_load_segs(data)
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True

    # Check SetDiceValue(int num) - search dump for exact RVA
    # From dump line 15616: "// RVA: 0x202B4BC" -- wait that was GetDiceValue
    # Let me read dump.cs around lines 15615-15625
    print("Searching dump.cs for SetDiceValue(int num) RVA...")
    with open(r"E:\Dev\ludo-king-modified\il2cpp_dump\dump.cs", encoding='utf-8', errors='replace') as f:
        lines = f.readlines()

    # Look at lines 15610-15630
    for i, line in enumerate(lines[15605:15630], start=15606):
        print(f"  {i}: {line.rstrip()}")

    print()

    # Disassemble SetDiceValue(int num) using confirmed RVA from searching
    # Also disassemble private SetDiceValue() to compare
    for name, rva in FUNCS_TO_CHECK.items():
        foff = rva2off(segs, rva)
        if not foff:
            print(f"[!] {name} not mapped")
            continue
        
        code = data[foff : foff + 400]
        insns = list(md.disasm(code, rva))
        print(f"\n=== {name} @ RVA 0x{rva:X} ===")
        
        for ins in insns[:60]:
            # Highlight array bounds checks (CMP, CBZ, CBNZ with small constants)
            highlight = ""
            raw = struct.unpack_from('<I', ins.bytes)[0]
            # Check for CMP with immediate
            if ins.mnemonic == 'cmp':
                highlight = "  *** CMP (bounds check?)"
            # Check for MOVZ with small constant
            if ins.mnemonic == 'movz':
                rd = raw & 0x1F
                imm = (raw >> 5) & 0xFFFF
                if 5 <= imm <= 12:
                    highlight = f"  *** MOVZ #{imm} (dice range?)"
            print(f"  0x{ins.address:X}: {ins.mnemonic:<10} {ins.op_str}{highlight}")

if __name__ == '__main__':
    main()
