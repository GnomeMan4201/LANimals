#!/usr/bin/env zsh

# Full LANimals repo cleanup, refactor, and push workflow.
# Replace <YOUR_GIT_REPO_URL> with your actual Git remote URL before running.

# 1. Unzip the provided archive and enter the extracted folder.
unzip LANimals_MAIN.zip -d LANimals && cd LANimals/LANimals_MAIN

# 2. Remove the virtual environment folder (not needed in repo).
rm -rf venv

# 3. Rename the launcher script to main.py for consistency.
mv lanimals-launcher.py main.py

# 4. Strip emojis from the banner call in main.py.
sed -i 's/banner("LANimals 🧠")/banner("LANimals")/' main.py

# 5. Ensure main.py has the correct shebang and is executable.
sed -i '1s;.*;#!/usr/bin/env python3;' main.py
chmod +x main.py

# 6. Loop through every module in modules/:
#    a) Ensure first line is "#!/usr/bin/env python3"
#    b) Add "if __name__ == '__main__': main()" stub at end if missing
#    c) Make each module executable
for module in modules/*.py; do
  sed -i '1s;.*;#!/usr/bin/env python3;' "$module"
  if ! grep -q "__main__" "$module"; then
    printf "

if __name__ == '__main__':
    main()
" >> "$module"
  fi
  chmod +x "$module"
done

# 7. Ensure main.py can import modules by setting PYTHONPATH at the top.
if ! grep -q "export PYTHONPATH" main.py; then
  sed -i '1i export PYTHONPATH="$(dirname "$0")"' main.py
fi

# 8. Update all bin/* scripts to call main.py instead of lanimals-launcher.py.
for script in bin/*; do
  sed -i 's|lanimals-launcher.py|$(dirname "$0")/../main.py|g' "$script"
  sed -i '1s;.*;#!/usr/bin/env bash;' "$script"
  chmod +x "$script"
done

# 9. Install Python dependencies (only rich is required).
pip3 install --upgrade rich

# 10. Remove stray emojis from README.md.
sed -i 's/🧠//g' README.md

# 11. Correct Quickstart section in README.md to point to "python3 main.py".
sed -i 's|python3 main.py|python3 main.py|g' README.md

# 12. Remove any leftover emoji-based text in lanimals_utils.py.
sed -i 's/🧠//g' lanimals_utils.py

# 13. Remove stray __pycache__ directories within modules/.
find . -type d -name "__pycache__" -exec rm -rf {} +

# 14. Initialize Git (if not already), point to your repo, stage, commit, and push.
git init
git remote add origin <YOUR_GIT_REPO_URL>
git add .
git commit -m "Refactor LANimals repo: remove venv, rename launcher, clean modules, remove emojis, wire everything"
git push -u origin main
EOF
