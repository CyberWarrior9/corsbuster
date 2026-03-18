#!/bin/bash
# CORSbuster - One-line installer
# Usage: curl -sSL https://raw.githubusercontent.com/CyberWarrior9/corsbuster/main/install.sh | bash
# Or: ./install.sh

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${RED}"
echo "   _____ ___  ____  ____  _               _            "
echo "  / ____/ _ \|  _ \/ ___|| |__  _   _ ___| |_ ___ _ __ "
echo " | |  | | | | |_) \___ \| '_ \| | | / __| __/ _ \ '__|"
echo " | |__| |_| |  _ < ___) | |_) | |_| \__ \ ||  __/ |   "
echo "  \____\___/|_| \_\____/|_.__/ \__,_|___/\__\___|_|   "
echo -e "${NC}"
echo -e "${CYAN}CORS Misconfiguration Scanner with Exploitability Verification${NC}"
echo ""

# ── Check Python ──────────────────────────────────────────────────────
echo -e "${YELLOW}[*] Checking Python...${NC}"
if command -v python3 &>/dev/null; then
    PY_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
    PY_MAJOR=$(echo "$PY_VERSION" | cut -d. -f1)
    PY_MINOR=$(echo "$PY_VERSION" | cut -d. -f2)
    echo -e "  ${GREEN}[+] Python $PY_VERSION found${NC}"

    if [ "$PY_MAJOR" -lt 3 ] || ([ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 8 ]); then
        echo -e "  ${RED}[!] Python 3.8+ required. Found $PY_VERSION${NC}"
        exit 1
    fi
else
    echo -e "  ${RED}[!] Python3 not found. Install Python 3.8+ first.${NC}"
    exit 1
fi

# ── Check pip ─────────────────────────────────────────────────────────
echo -e "${YELLOW}[*] Checking pip...${NC}"
if command -v pip3 &>/dev/null; then
    echo -e "  ${GREEN}[+] pip3 found${NC}"
    PIP="pip3"
elif command -v pip &>/dev/null; then
    echo -e "  ${GREEN}[+] pip found${NC}"
    PIP="pip"
else
    echo -e "  ${RED}[!] pip not found. Installing...${NC}"
    python3 -m ensurepip --upgrade 2>/dev/null || {
        echo -e "  ${RED}[!] Cannot install pip. Install manually: sudo apt install python3-pip${NC}"
        exit 1
    }
    PIP="pip3"
fi

# ── Check existing dependencies ───────────────────────────────────────
echo -e "${YELLOW}[*] Checking dependencies...${NC}"
DEPS=("aiohttp" "rich" "tldextract")
MISSING=()

for dep in "${DEPS[@]}"; do
    if python3 -c "import $dep" 2>/dev/null; then
        VERSION=$(python3 -c "import $dep; print(getattr($dep, '__version__', 'installed'))" 2>/dev/null)
        echo -e "  ${GREEN}[+] $dep ($VERSION) — already installed${NC}"
    else
        echo -e "  ${YELLOW}[-] $dep — not installed${NC}"
        MISSING+=("$dep")
    fi
done

# ── Install CORSbuster ───────────────────────────────────────────────
INSTALL_DIR="$HOME/.local/share/corsbuster"

# Check if already installed
if command -v corsbuster &>/dev/null; then
    CURRENT_VERSION=$(corsbuster --version 2>&1 | grep -oP '[\d.]+' || echo "unknown")
    echo -e "${YELLOW}[*] CORSbuster $CURRENT_VERSION already installed. Updating...${NC}"
fi

# Clone or update
if [ -d "$INSTALL_DIR" ]; then
    echo -e "${YELLOW}[*] Updating existing installation...${NC}"
    cd "$INSTALL_DIR"
    git pull --quiet 2>/dev/null || true
else
    echo -e "${YELLOW}[*] Cloning CORSbuster...${NC}"
    git clone --quiet https://github.com/CyberWarrior9/corsbuster.git "$INSTALL_DIR" 2>/dev/null || {
        # If git clone fails (no internet or repo not yet public), check if we're running locally
        if [ -f "setup.py" ] && [ -d "corsbuster" ]; then
            INSTALL_DIR="$(pwd)"
            echo -e "  ${CYAN}[*] Installing from local directory${NC}"
        else
            echo -e "  ${RED}[!] Failed to clone repository${NC}"
            exit 1
        fi
    }
fi

cd "$INSTALL_DIR"

# Install with pip
echo -e "${YELLOW}[*] Installing CORSbuster...${NC}"
if [ ${#MISSING[@]} -gt 0 ]; then
    echo -e "  ${CYAN}[*] Installing missing dependencies: ${MISSING[*]}${NC}"
fi

# Try normal install first, fall back to --break-system-packages for Kali/Debian
$PIP install -e "$INSTALL_DIR" --quiet 2>/dev/null || \
$PIP install -e "$INSTALL_DIR" --quiet --break-system-packages 2>/dev/null || {
    echo -e "  ${YELLOW}[*] Trying with --user flag...${NC}"
    $PIP install -e "$INSTALL_DIR" --user --quiet 2>/dev/null || {
        echo -e "  ${RED}[!] Installation failed. Try manually: cd $INSTALL_DIR && pip install -e .${NC}"
        exit 1
    }
}

# ── Verify installation ──────────────────────────────────────────────
echo ""
if command -v corsbuster &>/dev/null; then
    echo -e "${GREEN}[+] CORSbuster installed successfully!${NC}"
    corsbuster --version
else
    # Check if it's in ~/.local/bin
    if [ -f "$HOME/.local/bin/corsbuster" ]; then
        echo -e "${GREEN}[+] CORSbuster installed to ~/.local/bin/corsbuster${NC}"
        echo -e "${YELLOW}    Add to PATH: export PATH=\"\$HOME/.local/bin:\$PATH\"${NC}"
    else
        echo -e "${GREEN}[+] Installation complete. Run with: python3 -m corsbuster${NC}"
    fi
fi

echo ""
echo -e "${CYAN}Quick start:${NC}"
echo -e "  corsbuster -u https://target.com/api/endpoint"
echo -e "  corsbuster -u https://target.com -H 'Cookie: session=abc' --poc"
echo -e "  corsbuster -l urls.txt -o report.json --html-report report.html"
echo ""
echo -e "${RED}Only scan targets you have permission to test.${NC}"
