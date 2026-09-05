# Ludo King — Dice 1–10 Modification

A modified version of Ludo King where the dice rolls **1–10** instead of 1–6.

## What's Changed

| Feature | Original | Modified |
|---|---|---|
| Dice range | 1–6 | **1–10** |
| Dice faces 1–6 | Dot pips | Same dot pips |
| Dice faces 7–10 | N/A | Number displayed |
| Gameplay | Standard | Extended movement |

### Technical Details
- **Binary patched** `libil2cpp.so` at two locations:
  - `RVA 0x2292774`: `ldr w1, [x19, #0x18]` → `movz w1, #10` (main dice roll path)
  - `RVA 0x22927A4`: `add w1, w8, #1` → `movz w1, #11` (fallback path)
- `UnityEngine.Random.Range(0, 6)` → `Random.Range(0, 10)` effectively
- Single merged APK (base + ARM64 libs + Unity assets) for easy installation

## Installation

1. Download `ludo-king-dice10.apk` from [Releases](../../releases/latest)
2. Enable "Install from unknown sources" on your Android device
3. Install the APK
4. Enjoy 1–10 dice rolls!

> **Note:** This uses a debug keystore signature. If you have the original Ludo King installed, uninstall it first (or use ADB install with `--allow-test`).

## Building from Source

### Prerequisites
- Python 3.8+
- Java 17+

### Setup
```bash
# Install Python dependencies
pip install capstone unitypy pillow

# Java tools are in tools/
# tools/apktool/apktool.jar
# tools/apktool/uber-apk-signer.jar
```

### Steps
```bash
# 1. Run the binary patch
python patch/patch_dice_final.py

# 2. Merge APKs
python patch/build_merged_apk.py

# 3. Sign
java -jar tools/apktool/uber-apk-signer.jar \
  --apks ludo-king-dice10.apk --out .
```

Or just push to `main` and the GitHub Actions workflow builds and releases automatically.

## Tools Used (and How to Remove)

| Tool | Location | How to Remove |
|---|---|---|
| OpenJDK 17 portable | `tools/jdk/` | Delete the folder |
| apktool 2.9.3 | `tools/apktool/apktool.jar` | Delete the file |
| uber-apk-signer 1.3.0 | `tools/apktool/uber-apk-signer.jar` | Delete the file |
| Il2CppDumper v6.7.46 | `tools/Il2CppDumper/` | Delete the folder |
| capstone (Python) | pip package | `pip uninstall capstone` |
| UnityPy (Python) | pip package | `pip uninstall unitypy` |
| Pillow (Python) | pip package | `pip uninstall pillow` |

## Disclaimer

This is a fan modification for educational purposes. Ludo King is developed by Gametion Technologies. All game assets belong to their respective owners. Do not distribute this APK commercially.
