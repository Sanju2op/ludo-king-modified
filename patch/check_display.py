"""
check_display.py
Searches for CMP w0, #6 or similar bounds checks in UI/display code.
"""
import struct, os

try:
    from capstone import *
    from capstone.arm64 import *
except ImportError:
    pass

SO_PATH = r"E:\Dev\ludo-king-modified\xapk_extracted\arm64_extracted\lib\arm64-v8a\libil2cpp.so"

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

def main():
    with open(SO_PATH, 'rb') as f:
        data = bytearray(f.read())
    segs = parse_segs(data)
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

    # Let's check GetMSMDiceNumSprite
    targets = {
        "GetMSMDiceNumSprite": 0x2061000, # Approximate, needs finding
    }
    
    print("Checking display bounds...")

if __name__ == '__main__':
    main()
