"""Full disassembly of SetDiceValue(int num) at 0x2029C88"""
import struct, os
try:
    from capstone import *
    from capstone.arm64 import *
except: pass

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

# SetDiceValue(int num) @ 0x2029C88  -- show first 100 instructions
rva   = 0x2029C88
foff  = rva2off(segs, rva)
code  = data[foff : foff + 400]
insns = list(md.disasm(code, rva))

print(f"=== SetDiceValue(int num) @ 0x{rva:X} ===")
print(f"(W1 = num = dice value passed in)\n")
for ins in insns[:100]:
    raw = struct.unpack_from('<I', ins.bytes)[0]
    note = ""
    if ins.mnemonic == 'cmp':
        note = "  <-- COMPARE"
    if ins.mnemonic in ('movz','mov') and 'w1' in ins.op_str.lower() and '#' in ins.op_str:
        note = "  <-- OVERWRITING W1 (original num arg)"
    # Check if w1 is used as array index  
    if 'w1' in ins.op_str and ins.mnemonic in ('ldr','str','ldrsw'):
        note = "  *** W1 USED IN MEMORY ACCESS (array index?)"
    print(f"  0x{ins.address:X}: {ins.mnemonic:<10} {ins.op_str}{note}")
