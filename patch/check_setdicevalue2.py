"""
check_setdicevalue2.py
Disassembles SetDiceValue(int num) at RVA 0x2029C88 for array-bounds risk.
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

def parse_segs(data):
    e_phoff     = struct.unpack_from('<Q', data, 0x20)[0]
    e_phentsize = struct.unpack_from('<H', data, 0x36)[0]
    e_phnum     = struct.unpack_from('<H', data, 0x38)[0]
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

with open(SO_PATH, 'rb') as f:
    data = f.read()
segs = parse_segs(data)
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True

# SetDiceValue(int num) - RVA confirmed from dump: 0x2029C88
TARGETS = {
    "SetDiceValue(int num)": 0x2029C88,
    "private SetDiceValue()": 0x202C614,
    "SetDiceValueForTeamUpOMP": 0x202C2B0,
}

for name, rva in TARGETS.items():
    foff = rva2off(segs, rva)
    if not foff:
        print(f"[!] {name} not mapped")
        continue
    code = data[foff : foff + 500]
    insns = list(md.disasm(code, rva))
    print(f"\n=== {name} @ RVA 0x{rva:X} ===")
    for ins in insns[:70]:
        raw = struct.unpack_from('<I', ins.bytes)[0]
        note = ""
        if ins.mnemonic == 'cmp':
            note = "  <-- BOUNDS CHECK?"
        # MOVZ with small constant 5-12 (could be dice max index)
        if ins.mnemonic in ('movz', 'mov') and '#' in ins.op_str:
            # try to extract immediate
            try:
                imm_str = ins.op_str.split('#')[1].split(',')[0].strip()
                imm = int(imm_str, 0) if imm_str.startswith('0x') else int(imm_str)
                if 4 <= imm <= 12:
                    note = f"  <-- CONST #{imm} (possible dice max)"
            except:
                pass
        # Array indexing: check for LDRSH, LDR with index register (could be sprite array)
        if ins.mnemonic in ('ldr', 'ldrsw') and '[' in ins.op_str and 'x' in ins.op_str:
            note = "  <-- ARRAY ACCESS"
        print(f"  0x{ins.address:X}: {ins.mnemonic:<10} {ins.op_str}{note}")
