import sys, os
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__) + "/.."))
import sys, os
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__) + "/.."))
#!/usr/bin/env python3
import os
def main():
    print("\n[] Running Service Fingerprinting...")
    os.system("nmap -sV -iL /data/data/com.termux/files/usr/tmp/target_net")
if __name__ == "__main__":
    main()
