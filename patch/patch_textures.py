"""
patch_textures.py — Adds dice faces 7-10 to the Unity asset bundles
Uses UnityPy to read/write Unity assets.

Strategy:
  1. Find sharedassets files that contain dice textures (Texture2D named Die*)
  2. Duplicate an existing face texture for faces 7-10
  3. Draw numbers 7, 8, 9, 10 on the face images using Pillow
  4. Replace textures in the asset bundle
"""
import os, struct, io, sys

try:
    import UnityPy
except ImportError:
    os.system("pip install unitypy pillow -q")
    import UnityPy

try:
    from PIL import Image, ImageDraw, ImageFont
except ImportError:
    os.system("pip install pillow -q")
    from PIL import Image, ImageDraw, ImageFont

# Paths
UNITY_DATA_DIR = r"E:\Dev\ludo-king-modified\xapk_extracted\unity_data_extracted"
BASE_APK_DATA  = r"E:\Dev\ludo-king-modified\decompiled\assets\bin\Data"
OUT_DIR        = r"E:\Dev\ludo-king-modified\patch\textures"

os.makedirs(OUT_DIR, exist_ok=True)

def find_asset_files():
    """Find all .assets and .assets.split* files with dice textures."""
    candidates = []
    for root, dirs, files in os.walk(UNITY_DATA_DIR):
        for f in files:
            if '.assets' in f and 'split0' in f:  # split0 is the first chunk
                candidates.append(os.path.join(root, f))
    for root, dirs, files in os.walk(BASE_APK_DATA):
        for f in files:
            if f.endswith('.assets') and 'shared' in f:
                candidates.append(os.path.join(root, f))
    return candidates

def scan_asset_for_dice_textures(path):
    """Load an asset file and find Texture2D objects with dice-related names."""
    try:
        env = UnityPy.load(path)
        dice_textures = []
        for obj in env.objects:
            if obj.type.name == 'Texture2D':
                data = obj.read()
                name = getattr(data, 'name', '')
                if any(kw in name.lower() for kw in ['die', 'dice', 'dot', 'face', 'pip', 'd6', 'd_']):
                    dice_textures.append((obj, data, name, path))
                    print(f"  Found texture: {name} ({data.m_Width}x{data.m_Height}) in {os.path.basename(path)}")
        return dice_textures
    except Exception as e:
        return []

def make_dice_face_image(number, size=128, bg_color=(240, 240, 240), fg_color=(30, 30, 30)):
    """Create a PIL image of a dice face with a number."""
    img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    
    # Rounded square background
    margin = int(size * 0.05)
    radius = int(size * 0.15)
    draw.rounded_rectangle([margin, margin, size-margin, size-margin], 
                            radius=radius, fill=bg_color + (255,), outline=(180, 180, 180, 255), width=2)
    
    # Draw number text
    # Use a large bold font - try system fonts
    font = None
    for font_path in [
        "C:/Windows/Fonts/arialbd.ttf",
        "C:/Windows/Fonts/arial.ttf", 
        "C:/Windows/Fonts/calibrib.ttf",
        "C:/Windows/Fonts/verdanab.ttf",
    ]:
        if os.path.exists(font_path):
            try:
                font_size = int(size * 0.55)
                if number == 10:
                    font_size = int(size * 0.42)  # smaller for two-digit
                font = ImageFont.truetype(font_path, font_size)
                break
            except:
                pass
    
    text = str(number)
    if font:
        bbox = draw.textbbox((0, 0), text, font=font)
        tw = bbox[2] - bbox[0]
        th = bbox[3] - bbox[1]
        x = (size - tw) // 2 - bbox[0]
        y = (size - th) // 2 - bbox[1]
        draw.text((x, y), text, font=font, fill=fg_color + (255,))
    else:
        # Fallback: use default font
        draw.text((size//4, size//4), text, fill=fg_color + (255,))
    
    return img

def main():
    print("=== Dice Texture Patcher ===\n")
    
    # First, generate the new face images for 7-10
    print("Generating dice face images for 7-10...")
    face_images = {}
    for n in [7, 8, 9, 10]:
        img = make_dice_face_image(n, size=256)
        out_path = os.path.join(OUT_DIR, f"dice_face_{n}.png")
        img.save(out_path)
        face_images[n] = img
        print(f"  Created: {out_path} ({img.size[0]}x{img.size[1]})")
    
    print("\nScanning Unity asset files for dice textures...")
    
    # Scan base APK assets first (more likely to have dice textures)
    all_candidates = []
    
    # Try sharedassets files from decompiled base APK
    for f in os.listdir(BASE_APK_DATA):
        if f.endswith('.assets'):
            all_candidates.append(os.path.join(BASE_APK_DATA, f))
    
    # Try split asset files from unity data pack
    for root, dirs, files in os.walk(UNITY_DATA_DIR):
        for f in files:
            if '.assets' in f and not any(ext in f for ext in ['.split1', '.split2', '.split3']):
                if '.split0' in f or f.endswith('.assets'):
                    all_candidates.append(os.path.join(root, f))
    
    print(f"Checking {len(all_candidates)} asset files...")
    
    found_dice = []
    for path in all_candidates[:20]:  # Check first 20
        textures = scan_asset_for_dice_textures(path)
        found_dice.extend(textures)
    
    if not found_dice:
        print("\n[!] No dice textures found in common locations.")
        print("    The dice visuals may be:")
        print("    1. In addressable asset packs (bpacksnl* files)")
        print("    2. Loaded from server/CDN at runtime")  
        print("    3. In a different format (Sprite atlas, not individual Texture2D)")
        print("\nScanning addressable asset packs...")
        
        # Try addressable packs
        for root, dirs, files in os.walk(UNITY_DATA_DIR):
            for f in files:
                if f.startswith('bpacksnl'):
                    path = os.path.join(root, f)
                    textures = scan_asset_for_dice_textures(path)
                    if textures:
                        found_dice.extend(textures)
                        print(f"  Found {len(textures)} dice texture(s) in {f}")
    
    if found_dice:
        print(f"\nFound {len(found_dice)} dice texture(s). Patching...")
        # TODO: patch logic would go here
        # For now, report what was found
        for (obj, data, name, path) in found_dice:
            print(f"  - {name} ({data.m_Width}x{data.m_Height}) in {os.path.basename(path)}")
    else:
        print("\n[INFO] Dice textures not found in binary assets.")
        print("The game likely downloads dice skins from the server.")
        print("Generating local texture replacements instead...")
        print(f"New dice face images saved to: {OUT_DIR}")
        print("These can be used if a texture injection method is found.")
    
    print(f"\nGenerated face images:")
    for n, img in face_images.items():
        print(f"  dice_face_{n}.png saved")

if __name__ == '__main__':
    main()
