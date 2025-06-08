#!/usr/bin/env python3
import os
def main():
    print("\n[✓] Probing HTTP services...")
    os.system("cat /tmp/target_net | xargs -I {} nmap -p 80,443 {} --open")
if __name__ == "__main__":
    main()
