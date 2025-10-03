#!/usr/bin/env python3
import os
import shutil
import time


def main():
    print("\n[✓] Exporting Loot...")
    export_dir = f"/tmp/lanimals_loot_{int(time.time())}"
    os.makedirs(export_dir, exist_ok=True)
    files = ["loot.log"]
    for f in files:
        if os.path.exists(f):
            shutil.copy(f, export_dir)
            print(f"  [+] Copied {f} to {export_dir}/")
        else:
            print(f"  [!] Missing file: {f}")
    print(f"\n[✓] Export complete. Loot stored in {export_dir}/")


if __name__ == "__main__":
    main()
