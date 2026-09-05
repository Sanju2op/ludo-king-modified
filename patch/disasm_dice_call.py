"""
disasm_dice_call.py
Disassembles the region around the single Random.Range(int,int) call at 0x22927A8
to understand how the max value (W1) is loaded.
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
CALL_RVA = 0x22927A8  # The single Random.Range(int,int) call site

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

    call_foff = rva2off(segs, CALL_RVA)
    print(f"Call @ RVA=0x{CALL_RVA:X}  File=0x{call_foff:X}")

    # Disassemble 80 instructions before and 20 after
    start_foff = call_foff - 320
    end_foff   = call_foff + 80
    code = data[start_foff : end_foff]
    start_rva = CALL_RVA - 320

    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True
    insns = list(md.disasm(code, start_rva))

    print("\n=== Disassembly around Random.Range(int,int) call ===\n")
    for ins in insns:
        marker = " <===== RANDOM.RANGE CALL" if ins.address == CALL_RVA else ""
        # Highlight instructions that set W0 or W1
        highlight = ""
        raw = struct.unpack_from('<I', ins.bytes)[0]
        # MOVZ W0/W1
        if (raw >> 31) == 0 and ((raw >> 29) & 3) == 2 and ((raw >> 23) & 0x3F) == 0x25:
            rd = raw & 0x1F
            imm = (raw >> 5) & 0xFFFF
            if rd in (0, 1):
                highlight = f"  *** W{rd} = #{imm}"
        print(f"  0x{ins.address:08X}:  {ins.mnemonic:<10} {ins.op_str}{highlight}{marker}")

    # Also look at what class/method this is in (by checking dump.cs)
    print(f"\nThis call is at RVA 0x{CALL_RVA:X}")
    print("Search dump.cs for the enclosing method...")

if __name__ == '__main__':
    main()
