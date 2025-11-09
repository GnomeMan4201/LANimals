#!/usr/bin/env bash
# LANimals GitHub Push Script
# Pushes your working version to GitHub

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

LANIMALS_DIR="$HOME/LANimals"

echo -e "${CYAN}"
echo ""
echo "                                                           "
echo "           LANimals GitHub Push Script                    "
echo "           Version: Production-Ready Network Arsenal      "
echo "                                                           "
echo ""
echo -e "${NC}"

cd "$LANIMALS_DIR" || {
    echo -e "${RED}[] LANimals directory not found at $LANIMALS_DIR${NC}"
    exit 1
}

echo -e "${YELLOW}[*] Current directory: $(pwd)${NC}"
echo

# Check if git is initialized
if [ ! -d ".git" ]; then
    echo -e "${YELLOW}[*] Git not initialized. Initializing...${NC}"
    git init
    echo -e "${GREEN}[] Git initialized${NC}"
else
    echo -e "${GREEN}[] Git already initialized${NC}"
fi

# Check for remote
REMOTE_URL=$(git remote get-url origin 2>/dev/null || echo "")

if [ -z "$REMOTE_URL" ]; then
    echo -e "${YELLOW}[!] No remote configured${NC}"
    echo -e "${BLUE}Enter your GitHub repository URL:${NC}"
    echo -e "${CYAN}Example: https://github.com/GnomeMan4201/LANimals.git${NC}"
    read -p "URL: " REPO_URL
    
    if [ -n "$REPO_URL" ]; then
        git remote add origin "$REPO_URL"
        echo -e "${GREEN}[] Remote added: $REPO_URL${NC}"
    else
        echo -e "${RED}[] No URL provided${NC}"
        exit 1
    fi
else
    echo -e "${GREEN}[] Remote configured: $REMOTE_URL${NC}"
fi

# Check current branch
CURRENT_BRANCH=$(git branch --show-current 2>/dev/null || echo "")

if [ -z "$CURRENT_BRANCH" ]; then
    echo -e "${YELLOW}[*] Creating main branch...${NC}"
    git checkout -b main
    CURRENT_BRANCH="main"
fi

echo -e "${GREEN}[] Current branch: $CURRENT_BRANCH${NC}"

# Create/update .gitignore
echo -e "\n${YELLOW}[*] Updating .gitignore...${NC}"
cat > .gitignore << 'GITIGNORE'
# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg

# Virtual environments
venv/
ENV/
env/

# LANimals specific
loot/
reports/*.json
*.log
osv_cache.json
autopilot_state.json
.lanimals/

# Sensitive data
*.pcap
*.cap

# IDE
.vscode/
.idea/
*.swp
*.swo
*~

# OS
.DS_Store
Thumbs.db

# Backup files
*.bak
*.bak2
*_backup/
LANimals_github_backup/
GITIGNORE

echo -e "${GREEN}[] .gitignore updated${NC}"

# Show what will be committed
echo -e "\n${YELLOW}[*] Files to be committed:${NC}"
git status --short

echo -e "\n${BLUE}Files that will be staged:${NC}"
echo -e "${CYAN}  - Core modules (modules/)${NC}"
echo -e "${CYAN}  - Binary wrappers (bin/)${NC}"
echo -e "${CYAN}  - Core functionality (core/)${NC}"
echo -e "${CYAN}  - Documentation (docs/)${NC}"
echo -e "${CYAN}  - Entry points (lanimals_nexus.py, lanimals-ui.py, etc.)${NC}"
echo -e "${CYAN}  - Configuration files${NC}"

echo -e "\n${YELLOW}Files that will be ignored:${NC}"
echo -e "${CYAN}  - Virtual environments${NC}"
echo -e "${CYAN}  - Python cache${NC}"
echo -e "${CYAN}  - Operational data (loot/, reports/)${NC}"
echo -e "${CYAN}  - Log files${NC}"

# Prompt for commit message
echo -e "\n${BLUE}Enter commit message (or press Enter for default):${NC}"
read -p "Message: " COMMIT_MSG

if [ -z "$COMMIT_MSG" ]; then
    COMMIT_MSG="Update LANimals - Production-ready network arsenal

- Autonomous reconnaissance with device fingerprinting
- Network visualization and mapping
- Security fortress toolkit
- Real-time traffic monitoring
- Threat hunting capabilities
- System analysis tools
- Lightweight and operational"
fi

# Stage all changes
echo -e "\n${YELLOW}[*] Staging changes...${NC}"
git add .
echo -e "${GREEN}[] Changes staged${NC}"

# Commit
echo -e "\n${YELLOW}[*] Creating commit...${NC}"
git commit -m "$COMMIT_MSG"
echo -e "${GREEN}[] Commit created${NC}"

# Show commit info
echo -e "\n${BLUE}Last commit:${NC}"
git log -1 --oneline

# Push confirmation
echo -e "\n${YELLOW}Ready to push to GitHub?${NC}"
echo -e "${CYAN}This will push to: $(git remote get-url origin)${NC}"
echo -e "${CYAN}Branch: $CURRENT_BRANCH${NC}"
read -p "Push now? (y/N): " CONFIRM

if [[ "$CONFIRM" =~ ^[Yy]$ ]]; then
    echo -e "\n${YELLOW}[*] Pushing to GitHub...${NC}"
    
    # Set upstream if needed
    git push -u origin "$CURRENT_BRANCH"
    
    if [ $? -eq 0 ]; then
        echo -e "\n${GREEN}${NC}"
        echo -e "${GREEN}                  PUSH SUCCESSFUL!                         ${NC}"
        echo -e "${GREEN}${NC}"
        echo
        echo -e "${GREEN}[] LANimals pushed to GitHub${NC}"
        echo -e "${CYAN}Repository: $(git remote get-url origin)${NC}"
        echo -e "${CYAN}Branch: $CURRENT_BRANCH${NC}"
        echo
        echo -e "${BLUE}Next steps:${NC}"
        echo -e "  1. Visit your GitHub repo to verify"
        echo -e "  2. Update README.md if needed"
        echo -e "  3. Add screenshots from docs/screenshots/"
        echo -e "  4. Tag release: git tag -a v1.0.0 -m 'Release v1.0.0' && git push origin v1.0.0"
    else
        echo -e "\n${RED}[] Push failed!${NC}"
        echo -e "${YELLOW}Common issues:${NC}"
        echo -e "  - Check GitHub credentials"
        echo -e "  - Verify repository permissions"
        echo -e "  - Pull remote changes first: git pull origin $CURRENT_BRANCH"
        exit 1
    fi
else
    echo -e "\n${YELLOW}[!] Push cancelled${NC}"
    echo -e "${BLUE}Your changes are committed locally.${NC}"
    echo -e "${BLUE}Push later with: git push origin $CURRENT_BRANCH${NC}"
fi
