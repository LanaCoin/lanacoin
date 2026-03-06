#!/bin/bash
# =============================================================================
# Lanacoin Qt & Daemon Build Script for Linux (Ubuntu/Debian)
# =============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NPROC=$(nproc 2>/dev/null || echo 2)

echo "============================================"
echo " Lanacoin Linux Build"
echo "============================================"

# --- Install Dependencies ---
echo "[1/4] Installing dependencies..."
sudo apt-get update -qq
sudo apt-get install -y --no-install-recommends \
    build-essential \
    qt5-qmake qtbase5-dev qttools5-dev-tools \
    libboost-system-dev libboost-filesystem-dev libboost-program-options-dev \
    libboost-thread-dev libboost-chrono-dev libboost-timer-dev \
    libdb++-dev libssl-dev libminiupnpc-dev \
    libqrencode-dev

# --- Build LevelDB ---
echo "[2/4] Building LevelDB..."
cd "$SCRIPT_DIR/src/leveldb"
make clean 2>/dev/null || true
make -j"$NPROC" libleveldb.a libmemenv.a

# --- Build lanacoind (daemon) ---
echo "[3/4] Building lanacoind..."
cd "$SCRIPT_DIR/src"
mkdir -p obj
make -f makefile.unix -j"$NPROC"
strip lanacoind
echo "  -> lanacoind built: $SCRIPT_DIR/src/lanacoind"

# --- Build lanacoin-qt (GUI wallet) ---
echo "[4/4] Building lanacoin-qt..."
cd "$SCRIPT_DIR"
# Clean previous Qt build artifacts
rm -f Makefile lanacoin-qt
rm -rf build/*.o build/moc_* build/ui_* build/qrc_*

qmake "USE_UPNP=1" "USE_DBUS=0" "RELEASE=1" lanacoin-qt.pro
make -j"$NPROC"
strip lanacoin-qt
echo "  -> lanacoin-qt built: $SCRIPT_DIR/lanacoin-qt"

echo ""
echo "============================================"
echo " Build Complete!"
echo "============================================"
echo " Daemon:  $SCRIPT_DIR/src/lanacoind"
echo " Qt GUI:  $SCRIPT_DIR/lanacoin-qt"
echo "============================================"
