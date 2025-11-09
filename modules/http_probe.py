import sys, os
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__) + "/.."))
import sys, os
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__) + "/.."))
#!/usr/bin/env python3
import os
def main():
    print("\n[] Probing HTTP services...")
    os.system("cat /data/data/com.termux/files/usr/tmp/target_net | xargs -I {} nmap -p 80,443 {} --open")
if __name__ == "__main__":
    main()
