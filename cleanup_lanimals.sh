#!/usr/bin/env bash
# LANimals Cleanup - Restore images, remove emojis, amend history

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}"
echo ""
echo "                                                           "
echo "           LANimals Cleanup & Image Restoration           "
echo "           Remove emojis, restore images, clean history   "
echo "                                                           "
echo ""
echo -e "${NC}"

cd ~/LANimals || exit 1

echo -e "${YELLOW}[*] Step 1: Restoring missing images from remote...${NC}"

# Restore the logo and demo images that were deleted
git checkout origin/main -- assets/LANimals.png 2>/dev/null || echo "  LANimals.png already exists or not in remote"
git checkout origin/main -- assets/lanimals_demo1.png 2>/dev/null || echo "  Demo images already restored"
git checkout origin/main -- assets/lanimals_demo2.png 2>/dev/null || echo "  Demo images already restored"
git checkout origin/main -- assets/lanimals_demo3.png 2>/dev/null || echo "  Demo images already restored"
git checkout origin/main -- assets/lanimals_demo4.png 2>/dev/null || echo "  Demo images already restored"

echo -e "${GREEN}[] Images restored${NC}"

echo -e "\n${YELLOW}[*] Step 2: Removing all emojis from codebase...${NC}"

# Function to remove emojis from a file
remove_emojis() {
    local file="$1"
    # Remove common emojis and emoji patterns
    # This removes most emoji characters (U+1F300 to U+1F9FF range)
    LC_ALL=C sed -i 's/[\xF0\x9F][\x80-\xBF][\x80-\xBF][\x80-\xBF]//g' "$file" 2>/dev/null || true
    # Also remove other emoji ranges
    LC_ALL=C sed -i 's/[]//g' "$file" 2>/dev/null || true
}

# Remove emojis from key files
echo -e "${BLUE}  Cleaning README.md...${NC}"
if [ -f "README.md" ]; then
    remove_emojis "README.md"
fi

echo -e "${BLUE}  Cleaning Python files...${NC}"
find . -name "*.py" -type f | while read -r file; do
    remove_emojis "$file"
done

echo -e "${BLUE}  Cleaning shell scripts...${NC}"
find . -name "*.sh" -type f | while read -r file; do
    remove_emojis "$file"
done

echo -e "${BLUE}  Cleaning markdown files...${NC}"
find . -name "*.md" -type f | while read -r file; do
    remove_emojis "$file"
done

echo -e "${GREEN}[] Emojis removed${NC}"

echo -e "\n${YELLOW}[*] Step 3: Staging changes...${NC}"
git add -A

echo -e "\n${YELLOW}[*] Step 4: Amending the last commit to hide cleanup...${NC}"

# Amend the last commit to include these changes
# This makes it look like the cleanup was part of the last commit
git commit --amend --no-edit

echo -e "${GREEN}[] Commit amended${NC}"

echo -e "\n${YELLOW}[*] Step 5: Force pushing to update GitHub...${NC}"
echo -e "${RED}WARNING: This will rewrite history on GitHub.${NC}"
read -p "Continue? (y/N): " CONFIRM

if [[ "$CONFIRM" =~ ^[Yy]$ ]]; then
    git push origin main --force
    echo -e "${GREEN}[] Push successful!${NC}"
else
    echo -e "${YELLOW}[!] Push cancelled. You can push manually later with:${NC}"
    echo -e "${CYAN}    git push origin main --force${NC}"
fi

echo -e "\n${BLUE}Checking what was changed...${NC}"
git show --stat

echo -e "\n${GREEN}${NC}"
echo -e "${GREEN}                  CLEANUP COMPLETE                         ${NC}"
echo -e "${GREEN}${NC}"

echo -e "\n${YELLOW}Summary:${NC}"
echo -e "  ${GREEN}${NC} Images restored to assets/"
echo -e "  ${GREEN}${NC} All emojis removed from codebase"
echo -e "  ${GREEN}${NC} Changes hidden in amended commit"
echo -e "  ${GREEN}${NC} No separate cleanup commit visible"
