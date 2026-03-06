#!/bin/bash
# =============================================================================
# Lanacoin Build Script for macOS
# Run this directly on a macOS machine with Xcode and MacPorts/Homebrew
# =============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NPROC=$(sysctl -n hw.ncpu 2>/dev/null || echo 2)

echo "============================================"
echo " Lanacoin macOS Build"
echo "============================================"

# --- Detect package manager ---
if command -v brew &>/dev/null; then
    PKG_MANAGER="homebrew"
    echo "Using Homebrew package manager"
elif command -v port &>/dev/null; then
    PKG_MANAGER="macports"
    echo "Using MacPorts package manager"
else
    echo "ERROR: Neither Homebrew nor MacPorts found."
    echo "Install Homebrew: https://brew.sh"
    echo "  or MacPorts: https://www.macports.org"
    exit 1
fi

# --- Install Dependencies ---
echo "[1/4] Installing dependencies..."
if [ "$PKG_MANAGER" = "homebrew" ]; then
    brew install boost openssl berkeley-db@4 miniupnpc qrencode qt@5

    # Set up paths for Homebrew
    export BOOST_INCLUDE_PATH="$(brew --prefix boost)/include"
    export BOOST_LIB_PATH="$(brew --prefix boost)/lib"
    export BDB_INCLUDE_PATH="$(brew --prefix berkeley-db@4)/include"
    export BDB_LIB_PATH="$(brew --prefix berkeley-db@4)/lib"
    export OPENSSL_INCLUDE_PATH="$(brew --prefix openssl)/include"
    export OPENSSL_LIB_PATH="$(brew --prefix openssl)/lib"
    export MINIUPNPC_INCLUDE_PATH="$(brew --prefix miniupnpc)/include"
    export MINIUPNPC_LIB_PATH="$(brew --prefix miniupnpc)/lib"
    export PATH="$(brew --prefix qt@5)/bin:$PATH"
else
    sudo port install boost openssl db48 miniupnpc libqrencode qt5
fi

# --- Build LevelDB ---
echo "[2/4] Building LevelDB..."
cd "$SCRIPT_DIR/src/leveldb"
make clean 2>/dev/null || true
make -j"$NPROC" libleveldb.a libmemenv.a

# --- Build lanacoind (daemon) ---
echo "[3/4] Building lanacoind..."
cd "$SCRIPT_DIR/src"
mkdir -p obj

if [ "$PKG_MANAGER" = "homebrew" ]; then
    make -f makefile.osx -j"$NPROC" \
        BOOST_INCLUDE_PATH="$BOOST_INCLUDE_PATH" \
        BOOST_LIB_PATH="$BOOST_LIB_PATH" \
        BDB_INCLUDE_PATH="$BDB_INCLUDE_PATH" \
        BDB_LIB_PATH="$BDB_LIB_PATH" \
        OPENSSL_INCLUDE_PATH="$OPENSSL_INCLUDE_PATH" \
        OPENSSL_LIB_PATH="$OPENSSL_LIB_PATH"
else
    make -f makefile.osx -j"$NPROC"
fi

strip lanacoind
echo "  -> lanacoind built: $SCRIPT_DIR/src/lanacoind"

# --- Build lanacoin-qt (GUI wallet) ---
echo "[4/4] Building lanacoin-qt..."
cd "$SCRIPT_DIR"
rm -f Makefile lanacoin-qt Lanacoin-Qt.app
rm -rf build/*.o build/moc_* build/ui_* build/qrc_*

if [ "$PKG_MANAGER" = "homebrew" ]; then
    qmake "USE_UPNP=1" "RELEASE=1" \
        "BOOST_INCLUDE_PATH=$BOOST_INCLUDE_PATH" \
        "BOOST_LIB_PATH=$BOOST_LIB_PATH" \
        "BDB_INCLUDE_PATH=$BDB_INCLUDE_PATH" \
        "BDB_LIB_PATH=$BDB_LIB_PATH" \
        "OPENSSL_INCLUDE_PATH=$OPENSSL_INCLUDE_PATH" \
        "OPENSSL_LIB_PATH=$OPENSSL_LIB_PATH" \
        "MINIUPNPC_INCLUDE_PATH=$MINIUPNPC_INCLUDE_PATH" \
        "MINIUPNPC_LIB_PATH=$MINIUPNPC_LIB_PATH" \
        lanacoin-qt.pro
else
    qmake "USE_UPNP=1" "RELEASE=1" lanacoin-qt.pro
fi

make -j"$NPROC"
echo "  -> Lanacoin-Qt.app built: $SCRIPT_DIR/Lanacoin-Qt.app"

# --- Create DMG (optional) ---
echo ""
echo "To create a distributable DMG:"
echo "  macdeployqt Lanacoin-Qt.app -dmg"
echo ""

echo "============================================"
echo " macOS Build Complete!"
echo "============================================"
echo " Daemon:  $SCRIPT_DIR/src/lanacoind"
echo " Qt GUI:  $SCRIPT_DIR/Lanacoin-Qt.app"
echo "============================================"
