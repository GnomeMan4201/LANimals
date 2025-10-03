def main():
    import sys

    args = sys.argv[1:]

    if not args:
        print("Usage: lanimals <command>")
        print("Available commands: recon, scan, loot")
        return

    command = args[0]

    if command == "recon":
        print("[*] Running ARP recon...")
        try:
            from modules.arp_recon import run

            run()
        except ImportError:
            print("[!] Module arp_recon not found or missing 'run()' method.")
    elif command == "scan":
        print("[*] Running network scan...")
        try:
            from modules.net_scan import run

            run()
        except ImportError:
            print("[!] Module net_scan not found or missing 'run()' method.")
    elif command == "loot":
        print("[*] Opening loot viewer...")
        try:
            from modules.loot_viewer import run

            run()
        except ImportError:
            print("[!] Module loot_viewer not found or missing 'run()' method.")
    else:
        print(f"[!] Unknown command: {command}")
