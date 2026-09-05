"""
scan_dice_packs.py
Scans the dicepack* asset bundles to find and list all textures inside.
"""
import os, sys

try:
    import UnityPy
except ImportError:
    os.system("pip install unitypy -q")
    import UnityPy

DICE_DIR = r"E:\Dev\ludo-king-modified\xapk_extracted\unity_data_extracted\assets"
OUT_DIR  = r"E:\Dev\ludo-king-modified\patch\textures\extracted"
os.makedirs(OUT_DIR, exist_ok=True)

def scan_pack(path):
    try:
        env = UnityPy.load(path)
        items = []
        for obj in env.objects:
            t = obj.type.name
            if t in ('Texture2D', 'Sprite', 'SpriteAtlas'):
                data = obj.read()
                name = getattr(data, 'name', '?')
                items.append((t, name, obj))
        return items
    except Exception as e:
        return []

def extract_texture(obj, out_path):
    try:
        data = obj.read()
        if hasattr(data, 'image'):
            img = data.image
            img.save(out_path)
            return True
    except Exception as e:
        print(f"    [!] Extract error: {e}")
    return False

def main():
    # Find all dicepack files
    dice_packs = []
    for root, dirs, files in os.walk(DICE_DIR):
        for f in files:
            if f.startswith('dicepack'):
                dice_packs.append(os.path.join(root, f))
    
    dice_packs.sort()
    print(f"Found {len(dice_packs)} dicepack files\n")
    
    for pack_path in dice_packs:
        pack_name = os.path.basename(pack_path)
        items = scan_pack(pack_path)
        if not items:
            continue
        
        print(f"[{pack_name}] ({len(items)} objects):")
        for (t, name, obj) in items[:10]:
            print(f"  {t}: {name}")
            # Extract textures for dicepack1_* (the classic dice faces)
            if t == 'Texture2D' and 'dicepack1' in pack_name:
                safe_name = name.replace('/', '_').replace('\\', '_')
                out_path = os.path.join(OUT_DIR, f"{pack_name}_{safe_name}.png")
                ok = extract_texture(obj, out_path)
                if ok:
                    print(f"    -> Extracted: {os.path.basename(out_path)}")
        if len(items) > 10:
            print(f"  ... and {len(items)-10} more")
        print()

if __name__ == '__main__':
    main()
