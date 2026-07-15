#!/usr/bin/env bash

# Exit immediately if a command exits with a non-zero status
set -e

# --- Color Palette ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# --- Beautiful Banner ---
clear
echo -e "${CYAN}"
echo "========================================================="
echo "   _    _                    _____                       "
echo "  | |  | |                  / ____|                      "
echo "  | |__| | ___  __  __ __ _| |     ___  _ __ ___         "
echo "  |  __  |/ _ \\ \ \/ // _\` | |    / _ \\| '__/ _ \\        "
echo "  | |  | |  __/  >  <| (_| | |___| (_) | | |  __/        "
echo "  |_|  |_|\\___| /_/\\_\\\\__,_|\\_____\\___/|_|  \\___|        "
echo "                                                         "
echo "        THE ULTRA-SIMPLE LINUX SETUP & RUNNER            "
echo "========================================================="
echo -e "${NC}"

# --- Helper Functions ---
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# --- Step 1: Detect Linux OS & Package Manager ---
log_info "Step 1: Detecting system environment..."
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$NAME
    log_success "Detected Operating System: $OS"
else
    OS="Unknown Linux"
    log_warn "Could not determine Linux distribution. Assuming Debian/Ubuntu-like."
fi

# Check for apt-get (Debian/Ubuntu/Kali)
if ! command -v apt-get &> /dev/null; then
    log_warn "This script is optimized for Debian, Ubuntu, or Kali Linux."
    log_warn "If you are on another system (e.g. Fedora, Arch), please install dependencies manually."
fi

# --- Step 2: Install Base Packages ---
log_info "Step 2: Installing required system tools (Python 3, Node.js, npm, pip)..."
log_info "We might need admin permission (sudo) to install system software."

install_packages() {
    sudo apt-get update -y
    sudo apt-get install -y python3 python3-pip python3-venv nodejs npm curl git
}

if command -v apt-get &> /dev/null; then
    if ! command -v python3 &> /dev/null || ! command -v node &> /dev/null || ! command -v npm &> /dev/null || ! command -v pip3 &> /dev/null; then
        log_info "Installing missing system dependencies. Enter your password if prompted:"
        install_packages
    else
        log_success "All base packages (Python 3, Node.js, npm, pip) are already installed!"
    fi
else
    # Non-apt system check
    command -v python3 &> /dev/null || { log_error "python3 is not installed. Please install it first."; exit 1; }
    command -v node &> /dev/null || { log_error "Node.js is not installed. Please install it first."; exit 1; }
    command -v npm &> /dev/null || { log_error "npm is not installed. Please install it first."; exit 1; }
fi

# --- Step 3: Create & Configure Python Virtual Environment ---
log_info "Step 3: Creating Python Virtual Environment (venv) to keep libraries clean..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
    log_success "Created virtual environment 'venv'!"
else
    log_success "Virtual environment 'venv' already exists."
fi

# Activate venv
log_info "Activating virtual environment..."
source venv/bin/activate

# Upgrade pip inside venv
log_info "Upgrading pip..."
pip install --upgrade pip

# --- Step 4: Install Python Dependencies ---
log_info "Step 4: Installing Python backend libraries from requirements.txt..."
if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt
    log_success "Backend libraries successfully installed!"
else
    log_error "requirements.txt not found! Make sure you are in the project root directory."
    exit 1;
fi

# --- Step 5: Install Node.js Frontend Dependencies ---
log_info "Step 5: Installing Frontend libraries in console/ directory..."
if [ -d "console" ]; then
    cd console
    npm install
    cd ..
    log_success "Frontend libraries successfully installed!"
else
    log_error "'console' directory not found!"
    exit 1;
fi

# --- Step 6: Ingest Skills Database ---
log_info "Step 6: Ingesting skills and building validation report..."
if [ -f "skills/skillsvc/ingest.py" ]; then
    python skills/skillsvc/ingest.py --heart Heart
    log_success "Skills successfully ingested!"
else
    log_warn "Could not find skills ingestion script (skills/skillsvc/ingest.py). Skipping step."
fi

# --- Step 7: Launch Configuration ---
echo -e "\n${CYAN}=========================================================${NC}"
echo -e "              SETUP COMPLETE & READY TO RUN!             "
echo -e "${CYAN}=========================================================${NC}\n"

echo -e "Would you like to start the application right now?"
read -p "Start servers? (y/n): " launch_choice

if [[ "$launch_choice" =~ ^[Yy]$ ]]; then
    # Kill any old servers if they are somehow running on these ports
    log_info "Cleaning up old server instances on ports 8000 and 5173..."
    fuser -k 8000/tcp &> /dev/null || true
    fuser -k 5173/tcp &> /dev/null || true

    log_info "Starting Backend API server in the background..."
    nohup python serve.py > backend.log 2>&1 &
    BACKEND_PID=$!
    
    log_info "Starting Frontend Console server in the background..."
    cd console
    nohup npm run dev -- --host 0.0.0.0 > ../frontend.log 2>&1 &
    FRONTEND_PID=$!
    cd ..

    # Save PIDs to a file for easy shutdown later
    echo "$BACKEND_PID" > .backend.pid
    echo "$FRONTEND_PID" > .frontend.pid

    log_info "Waiting for servers to initialize..."
    sleep 4

    # Print server URLs
    echo -e "\n${GREEN}🚀 Application is running successfully! 🚀${NC}\n"
    echo -e "👉 ${BLUE}Frontend Console (Dashboard):${NC}  http://localhost:5173/"
    echo -e "👉 ${BLUE}Backend API Server (Docs):${NC}   http://localhost:8000/docs"
    echo -e "👉 ${BLUE}Backend Root URL:${NC}            http://localhost:8000/\n"
    
    echo -e "${YELLOW}How to manage the servers:${NC}"
    echo -e "• Stop servers:      Run ${CYAN}./stop_linux.sh${NC} (or kill processes manually)"
    echo -e "• View backend logs:  Run ${CYAN}tail -f backend.log${NC}"
    echo -e "• View frontend logs: Run ${CYAN}tail -f frontend.log${NC}"
    echo -e "• Run tests:          Run ${CYAN}python -m pytest${NC}"
    echo ""
else
    log_info "Setup complete. To start the servers manually next time, run:"
    echo -e "  Activate Environment:  ${CYAN}source venv/bin/activate${NC}"
    echo -e "  Start Backend API:     ${CYAN}python serve.py --reload${NC}"
    echo -e "  Start Frontend:        ${CYAN}cd console && npm run dev${NC}"
    echo ""
fi
