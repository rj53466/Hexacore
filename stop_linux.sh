#!/usr/bin/env bash

# --- Color Palette ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}=========================================================${NC}"
echo -e "               STOPPING HEXACORE SERVERS                 "
echo -e "${CYAN}=========================================================${NC}\n"

# Stop backend
if [ -f .backend.pid ]; then
    BACKEND_PID=$(cat .backend.pid)
    if kill -0 $BACKEND_PID 2>/dev/null; then
        echo -e "${YELLOW}[Stopping]${NC} Terminating Backend API server (PID: $BACKEND_PID)..."
        kill $BACKEND_PID
        echo -e "${GREEN}[Stopped]${NC} Backend API server stopped."
    else
        echo -e "${YELLOW}[Info]${NC} Backend process $BACKEND_PID is not running."
    fi
    rm .backend.pid
else
    # Fallback to fuser/pkill if PID file is not present
    echo -e "${YELLOW}[Info]${NC} No backend PID file found. Checking port 8000..."
    fuser -k 8000/tcp &> /dev/null || true
fi

# Stop frontend
if [ -f .frontend.pid ]; then
    FRONTEND_PID=$(cat .frontend.pid)
    if kill -0 $FRONTEND_PID 2>/dev/null; then
        echo -e "${YELLOW}[Stopping]${NC} Terminating Frontend Console server (PID: $FRONTEND_PID)..."
        kill $FRONTEND_PID
        echo -e "${GREEN}[Stopped]${NC} Frontend Console server stopped."
    else
        echo -e "${YELLOW}[Info]${NC} Frontend process $FRONTEND_PID is not running."
    fi
    rm .frontend.pid
else
    # Fallback to fuser/pkill if PID file is not present
    echo -e "${YELLOW}[Info]${NC} No frontend PID file found. Checking port 5173..."
    fuser -k 5173/tcp &> /dev/null || true
fi

# Extra cleanup just in case
echo -e "${GREEN}[Done]${NC} HexaCore services stopped successfully!\n"
