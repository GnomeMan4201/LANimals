#!/usr/bin/env bash
# Fix rejected push - merge remote changes

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
echo "           LANimals Push Fix                              "
echo "           Resolving remote conflicts                     "
echo "                                                           "
echo ""
echo -e "${NC}"

cd ~/LANimals || exit 1

echo -e "${YELLOW}[*] Fetching remote changes...${NC}"
git fetch origin

echo -e "\n${YELLOW}[*] Checking what's different...${NC}"
git log HEAD..origin/main --oneline

echo -e "\n${BLUE}Choose merge strategy:${NC}"
echo -e "${CYAN}1. Merge remote changes (keeps both)${NC}"
echo -e "${CYAN}2. Rebase (cleaner history)${NC}"
echo -e "${CYAN}3. Force push (DANGER: overwrites remote)${NC}"
echo -e "${CYAN}4. Cancel${NC}"
read -p "Choice (1-4): " CHOICE

case $CHOICE in
    1)
        echo -e "\n${YELLOW}[*] Merging remote changes...${NC}"
        git pull origin main --no-rebase
        echo -e "${GREEN}[] Merged${NC}"
        echo -e "\n${YELLOW}[*] Pushing...${NC}"
        git push origin main
        echo -e "${GREEN}[] Push successful!${NC}"
        ;;
    2)
        echo -e "\n${YELLOW}[*] Rebasing on remote...${NC}"
        git pull origin main --rebase
        echo -e "${GREEN}[] Rebased${NC}"
        echo -e "\n${YELLOW}[*] Pushing...${NC}"
        git push origin main
        echo -e "${GREEN}[] Push successful!${NC}"
        ;;
    3)
        echo -e "\n${RED}[!] WARNING: This will overwrite remote changes!${NC}"
        read -p "Are you SURE? (type 'yes' to confirm): " CONFIRM
        if [ "$CONFIRM" == "yes" ]; then
            echo -e "\n${YELLOW}[*] Force pushing...${NC}"
            git push origin main --force
            echo -e "${GREEN}[] Force push complete${NC}"
        else
            echo -e "${YELLOW}[!] Cancelled${NC}"
        fi
        ;;
    4)
        echo -e "${YELLOW}[!] Cancelled${NC}"
        exit 0
        ;;
    *)
        echo -e "${RED}[] Invalid choice${NC}"
        exit 1
        ;;
esac

echo -e "\n${GREEN}${NC}"
echo -e "${GREEN}                  PUSH COMPLETE                            ${NC}"
echo -e "${GREEN}${NC}"
