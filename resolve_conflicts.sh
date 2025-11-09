#!/usr/bin/env bash
# LANimals Merge Conflict Resolution
# Resolves conflicts by keeping your working production code

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
echo "           LANimals Conflict Resolution                   "
echo "           Keep your working production code              "
echo "                                                           "
echo ""
echo -e "${NC}"

cd ~/LANimals || exit 1

# Get list of conflicted files
CONFLICTS=$(git diff --name-only --diff-filter=U)

echo -e "${YELLOW}[*] Conflicted files:${NC}"
echo "$CONFLICTS"
echo

echo -e "${BLUE}Resolution Strategy:${NC}"
echo -e "${CYAN}1. Keep YOUR version (your working production code)${NC}"
echo -e "${CYAN}2. Keep REMOTE version (the GitHub polished code)${NC}"
echo -e "${CYAN}3. Manually resolve each file${NC}"
echo -e "${CYAN}4. Abort merge${NC}"
read -p "Choice (1-4): " CHOICE

case $CHOICE in
    1)
        echo -e "\n${YELLOW}[*] Keeping YOUR working version for all conflicts...${NC}"
        
        # For each conflicted file, keep "ours" (your version)
        for file in $CONFLICTS; do
            echo -e "${BLUE}  Keeping YOUR version: $file${NC}"
            git checkout --ours "$file"
            git add "$file"
        done
        
        # Special handling for lanimals_nexus.py (deleted in remote but you have it)
        if [ -f "lanimals_nexus.py" ]; then
            echo -e "${BLUE}  Keeping lanimals_nexus.py (your production nexus)${NC}"
            git add lanimals_nexus.py
        fi
        
        echo -e "${GREEN}[] All conflicts resolved with YOUR version${NC}"
        
        # Show status
        echo -e "\n${YELLOW}[*] Current status:${NC}"
        git status --short
        
        # Commit the merge
        echo -e "\n${YELLOW}[*] Committing merge...${NC}"
        git commit -m "Merge remote changes - keeping production LANimals functionality"
        echo -e "${GREEN}[] Merge committed${NC}"
        
        # Push
        echo -e "\n${YELLOW}[*] Pushing to GitHub...${NC}"
        git push origin main
        echo -e "${GREEN}[] Push successful!${NC}"
        ;;
        
    2)
        echo -e "\n${YELLOW}[*] Keeping REMOTE version for all conflicts...${NC}"
        
        for file in $CONFLICTS; do
            echo -e "${BLUE}  Keeping REMOTE version: $file${NC}"
            git checkout --theirs "$file"
            git add "$file"
        done
        
        # For lanimals_nexus.py, accept deletion
        if git status | grep -q "lanimals_nexus.py"; then
            echo -e "${BLUE}  Removing lanimals_nexus.py (deleted in remote)${NC}"
            git rm lanimals_nexus.py
        fi
        
        echo -e "${GREEN}[] All conflicts resolved with REMOTE version${NC}"
        
        echo -e "\n${YELLOW}[*] Committing merge...${NC}"
        git commit -m "Merge: accept remote changes with professional polish"
        echo -e "${GREEN}[] Merge committed${NC}"
        
        echo -e "\n${YELLOW}[*] Pushing to GitHub...${NC}"
        git push origin main
        echo -e "${GREEN}[] Push successful!${NC}"
        ;;
        
    3)
        echo -e "\n${YELLOW}[*] Manual resolution required${NC}"
        echo -e "${BLUE}Conflicted files to resolve:${NC}"
        echo "$CONFLICTS"
        echo
        echo -e "${CYAN}For each file, edit and resolve conflicts marked with:${NC}"
        echo -e "  ${YELLOW}<<<<<<< HEAD${NC} (your version)"
        echo -e "  ${YELLOW}=======${NC} (separator)"
        echo -e "  ${YELLOW}>>>>>>> remote${NC} (their version)"
        echo
        echo -e "${CYAN}After resolving each file:${NC}"
        echo -e "  ${BLUE}git add <file>${NC}"
        echo
        echo -e "${CYAN}When all resolved:${NC}"
        echo -e "  ${BLUE}git commit -m 'Resolve merge conflicts'${NC}"
        echo -e "  ${BLUE}git push origin main${NC}"
        ;;
        
    4)
        echo -e "\n${YELLOW}[*] Aborting merge...${NC}"
        git merge --abort
        echo -e "${GREEN}[] Merge aborted. Back to pre-merge state.${NC}"
        ;;
        
    *)
        echo -e "${RED}[] Invalid choice${NC}"
        exit 1
        ;;
esac

echo -e "\n${GREEN}${NC}"
echo -e "${GREEN}                  RESOLUTION COMPLETE                      ${NC}"
echo -e "${GREEN}${NC}"
