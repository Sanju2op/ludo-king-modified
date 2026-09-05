"""
build_merged_apk.py
Merges base APK + config ARM64 APK + Unity Data APK + Addressables APK
into a single self-contained APK with patched libil2cpp.so
"""
import zipfile, os, shutil, io

BASE_APK       = r"E:\Dev\ludo-king-modified\xapk_extracted\com.ludo.king.apk"
CONFIG_APK     = r"E:\Dev\ludo-king-modified\xapk_extracted\config.arm64_v8a.apk"
UNITY_DATA_APK = r"E:\Dev\ludo-king-modified\xapk_extracted\UnityDataAssetPack.apk"
ADDR_APK       = r"E:\Dev\ludo-king-modified\xapk_extracted\AddressablesAssetPack.apk"
PATCHED_SO     = r"E:\Dev\ludo-king-modified\xapk_extracted\arm64_extracted\lib\arm64-v8a\libil2cpp_patched.so"
OUT_APK        = r"E:\Dev\ludo-king-modified\ludo-king-dice10.apk"

# Entries to SKIP when merging (these are split-APK control files we don't want)
SKIP_PREFIXES  = {"META-INF/"}           # Will be re-signed anyway

def merge_zip_into(out_zip, src_path, overrides=None, skip_prefixes=None, label=""):
    """Copy all entries from src_path into out_zip (skip META-INF)."""
    if skip_prefixes is None:
        skip_prefixes = set()
    
    added = 0
    skipped_existing = 0
    skipped_prefix = 0
    existing_names = set(out_zip.namelist())
    
    with zipfile.ZipFile(src_path, 'r') as src:
        for entry in src.infolist():
            name = entry.filename
            
            # Skip META-INF (signatures)
            if any(name.startswith(p) for p in skip_prefixes):
                skipped_prefix += 1
                continue
            
            # Check if there's a patched override for this file
            if overrides and name in overrides:
                print(f"  [PATCH] {name}")
                data = open(overrides[name], 'rb').read()
                info = zipfile.ZipInfo(name)
                info.compress_type = zipfile.ZIP_DEFLATED
                out_zip.writestr(info, data)
                added += 1
                continue
            
            # Skip if already exists in output (base APK takes precedence for manifests etc.)
            if name in existing_names:
                skipped_existing += 1
                continue
            
            # Copy entry
            data = src.read(name)
            info = zipfile.ZipInfo(name)
            info.compress_type = entry.compress_type
            out_zip.writestr(info, data)
            existing_names.add(name)
            added += 1
    
    if label:
        print(f"  {label}: +{added} entries ({skipped_existing} skipped as duplicate, {skipped_prefix} META-INF)")
    return added

def main():
    print("=== Merging APKs into single ludo-king-dice10.apk ===\n")
    
    # Patched files to inject (entry name in APK -> local file path)
    overrides = {
        "lib/arm64-v8a/libil2cpp.so": PATCHED_SO,
    }
    
    if os.path.exists(OUT_APK):
        os.remove(OUT_APK)
    
    with zipfile.ZipFile(OUT_APK, 'w', compression=zipfile.ZIP_DEFLATED) as out_zip:
        # 1. Base APK first (has DEX, resources, basic assets)
        print("Adding base APK (DEX + base resources)...")
        merge_zip_into(out_zip, BASE_APK, overrides=None, 
                       skip_prefixes=SKIP_PREFIXES, label="Base APK")
        
        # 2. Config APK (native libraries, with patched libil2cpp.so)
        print("\nAdding config.arm64_v8a.apk (native libs with patched libil2cpp.so)...")
        merge_zip_into(out_zip, CONFIG_APK, overrides=overrides,
                       skip_prefixes=SKIP_PREFIXES, label="Config ARM64 APK")
        
        # 3. Unity Data Asset Pack
        print("\nAdding UnityDataAssetPack.apk (game assets)...")
        merge_zip_into(out_zip, UNITY_DATA_APK, overrides=None,
                       skip_prefixes=SKIP_PREFIXES, label="Unity Data APK")
        
        # 4. Addressables Asset Pack
        if os.path.exists(ADDR_APK):
            print("\nAdding AddressablesAssetPack.apk...")
            merge_zip_into(out_zip, ADDR_APK, overrides=None,
                           skip_prefixes=SKIP_PREFIXES, label="Addressables APK")
    
    size_mb = os.path.getsize(OUT_APK) / 1024 / 1024
    print(f"\n[OK] Merged APK: {OUT_APK}")
    print(f"     Size: {size_mb:.1f} MB")
    print(f"\nNext step: sign with uber-apk-signer")

if __name__ == '__main__':
    main()
