import zipfile, os

MERGED   = r"E:\Dev\ludo-king-modified\ludo-king-merged-raw.apk"
PATCHED  = r"E:\Dev\ludo-king-modified\xapk_extracted\arm64_extracted\lib\arm64-v8a\libil2cpp_patched.so"
OUT      = r"E:\Dev\ludo-king-modified\ludo-king-dice10.apk"
TARGET_ENTRY = "lib/arm64-v8a/libil2cpp.so"

print(f"Injecting patched libil2cpp.so into merged APK...")
patched_data = open(PATCHED, 'rb').read()
print(f"Patched SO size: {len(patched_data)/1024/1024:.1f} MB")

if os.path.exists(OUT):
    os.remove(OUT)

with zipfile.ZipFile(MERGED, 'r') as src, zipfile.ZipFile(OUT, 'w', allowZip64=True) as dst:
    for item in src.infolist():
        if item.filename == TARGET_ENTRY:
            print(f"  Replacing: {item.filename}")
            info = zipfile.ZipInfo(item.filename)
            info.compress_type = zipfile.ZIP_STORED  # .so must be uncompressed for mmap
            dst.writestr(info, patched_data)
        else:
            # Preserve original compression
            data = src.read(item.filename)
            dst.writestr(item, data)

size = os.path.getsize(OUT)/1024/1024
print(f"Done! Output: {OUT} ({size:.1f} MB)")
