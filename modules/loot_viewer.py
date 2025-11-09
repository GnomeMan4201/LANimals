import os

print(r'''
               
        
      
     
       
           
         LANimals :: Loot Viewer
''')

loot_dir = "loot"
if not os.path.isdir(loot_dir) or not os.listdir(loot_dir):
    print("[!] Loot folder is empty.")
else:
    for f in os.listdir(loot_dir):
        path = os.path.join(loot_dir, f)
        print(f"\n[+] {f}:\n" + "-"*50)
        with open(path) as file:
            print(file.read())
