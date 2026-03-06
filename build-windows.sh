#!/bin/bash
# =============================================================================
# Lanacoin Cross-Compilation Build Script for Windows (from Linux host)
# Uses MinGW-w64 to cross-compile for Windows x86_64
# =============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NPROC=$(nproc 2>/dev/null || echo 2)

TARGET_PLATFORM="${TARGET_PLATFORM:-x86_64}"
DEPSDIR="${DEPSDIR:-/usr/${TARGET_PLATFORM}-w64-mingw32}"

CC="${TARGET_PLATFORM}-w64-mingw32-gcc"
CXX="${TARGET_PLATFORM}-w64-mingw32-g++"
RANLIB="${TARGET_PLATFORM}-w64-mingw32-ranlib"
STRIP="${TARGET_PLATFORM}-w64-mingw32-strip"

echo "============================================"
echo " Lanacoin Windows Cross-Compilation Build"
echo " Target: ${TARGET_PLATFORM}-w64-mingw32"
echo "============================================"

# --- Check for cross-compiler ---
if ! command -v "$CXX" &>/dev/null; then
    echo "ERROR: Cross-compiler $CXX not found."
    echo "Install with: sudo apt-get install g++-mingw-w64-${TARGET_PLATFORM}-posix"
    exit 1
fi

# --- Step 1: Install cross-compiler and tools ---
echo "[1/5] Checking build tools..."
sudo apt-get install -y --no-install-recommends \
    g++-mingw-w64-${TARGET_PLATFORM}-posix \
    mingw-w64-${TARGET_PLATFORM}-dev

# --- Step 2: Build cross-compiled dependencies ---
echo "[2/5] Building cross-compiled dependencies..."
echo "  Dependencies need to be built/placed at: $DEPSDIR"
echo ""

DEPS_BUILD_DIR="$SCRIPT_DIR/depends/win64"
mkdir -p "$DEPS_BUILD_DIR"

# -- OpenSSL --
OPENSSL_VERSION="1.1.1w"
OPENSSL_DIR="$DEPSDIR/openssl-${OPENSSL_VERSION}"
if [ ! -f "$OPENSSL_DIR/libssl.a" ]; then
    echo "  Building OpenSSL ${OPENSSL_VERSION} for Windows..."
    cd "$DEPS_BUILD_DIR"
    if [ ! -d "openssl-${OPENSSL_VERSION}" ]; then
        curl -sLO "https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz"
        tar xzf "openssl-${OPENSSL_VERSION}.tar.gz"
    fi
    cd "openssl-${OPENSSL_VERSION}"
    ./Configure mingw64 no-shared no-dso --cross-compile-prefix="${TARGET_PLATFORM}-w64-mingw32-" --prefix="$OPENSSL_DIR"
    make -j"$NPROC"
    sudo make install_sw
    echo "  -> OpenSSL built at $OPENSSL_DIR"
else
    echo "  -> OpenSSL already built at $OPENSSL_DIR"
fi

# -- Berkeley DB --
BDB_VERSION="6.0.20"
BDB_DIR="$DEPSDIR/db-${BDB_VERSION}"
if [ ! -f "$BDB_DIR/build_unix/libdb_cxx.a" ]; then
    echo "  Building Berkeley DB ${BDB_VERSION} for Windows..."
    cd "$DEPS_BUILD_DIR"
    if [ ! -d "db-${BDB_VERSION}" ]; then
        curl -sLO "https://download.oracle.com/berkeley-db/db-${BDB_VERSION}.tar.gz"
        tar xzf "db-${BDB_VERSION}.tar.gz"
    fi
    cd "db-${BDB_VERSION}/build_unix"
    ../dist/configure \
        --host="${TARGET_PLATFORM}-w64-mingw32" \
        --enable-cxx --enable-mingw --disable-shared --disable-replication \
        CC="$CC" CXX="$CXX"
    make -j"$NPROC"
    sudo mkdir -p "$BDB_DIR/build_unix"
    sudo cp -a .libs/libdb*.a "$BDB_DIR/build_unix/"
    sudo cp -a ../build_unix/*.h "$BDB_DIR/build_unix/" 2>/dev/null || true
    echo "  -> Berkeley DB built at $BDB_DIR"
else
    echo "  -> Berkeley DB already built at $BDB_DIR"
fi

# -- Boost --
BOOST_VERSION="1_68_0"
BOOST_DIR="$DEPSDIR/boost_${BOOST_VERSION}"
if [ ! -f "$BOOST_DIR/stage/lib/libboost_system-mt.a" ]; then
    echo "  Building Boost ${BOOST_VERSION} for Windows..."
    cd "$DEPS_BUILD_DIR"
    if [ ! -d "boost_${BOOST_VERSION}" ]; then
        curl -sLO "https://archives.boost.io/release/1.68.0/source/boost_${BOOST_VERSION}.tar.gz"
        tar xzf "boost_${BOOST_VERSION}.tar.gz"
    fi
    cd "boost_${BOOST_VERSION}"
    echo "using gcc : mingw64 : ${TARGET_PLATFORM}-w64-mingw32-g++ ;" > user-config.jam
    ./bootstrap.sh --without-icu
    ./b2 -j"$NPROC" \
        --user-config=user-config.jam \
        toolset=gcc-mingw64 target-os=windows \
        threading=multi link=static runtime-link=static \
        --with-chrono --with-filesystem --with-program_options \
        --with-system --with-thread --with-timer \
        stage
    sudo mkdir -p "$BOOST_DIR/stage/lib"
    sudo cp -a stage/lib/* "$BOOST_DIR/stage/lib/"
    sudo cp -a boost "$BOOST_DIR/"
    echo "  -> Boost built at $BOOST_DIR"
else
    echo "  -> Boost already built at $BOOST_DIR"
fi

# --- Step 3: Build LevelDB for Windows ---
echo "[3/5] Building LevelDB for Windows..."
cd "$SCRIPT_DIR/src/leveldb"
make clean 2>/dev/null || true
CC="$CC" CXX="$CXX" TARGET_OS=OS_WINDOWS_CROSSCOMPILE make -j"$NPROC" libleveldb.a libmemenv.a
"$RANLIB" libleveldb.a
"$RANLIB" libmemenv.a

# --- Step 4: Build lanacoind.exe ---
echo "[4/5] Building lanacoind.exe..."
cd "$SCRIPT_DIR/src"
mkdir -p obj
make -f makefile.linux-mingw TARGET_PLATFORM="$TARGET_PLATFORM" clean 2>/dev/null || true
make -f makefile.linux-mingw TARGET_PLATFORM="$TARGET_PLATFORM" -j"$NPROC"
echo "  -> lanacoind.exe built: $SCRIPT_DIR/src/lanacoind.exe"

# --- Step 5: Build lanacoin-qt.exe (requires MXE or pre-built Qt5 for MinGW) ---
echo "[5/5] Qt GUI cross-compilation..."
echo ""
echo "  NOTE: Cross-compiling the Qt GUI (lanacoin-qt.exe) requires Qt5"
echo "  libraries built for MinGW. The recommended approach is to use MXE"
echo "  (M cross environment): https://mxe.cc/"
echo ""
echo "  To set up MXE and build the Qt wallet:"
echo "    git clone https://github.com/mxe/mxe.git"
echo "    cd mxe && make qt5"
echo "    export PATH=\$(pwd)/usr/bin:\$PATH"
echo "    cd $SCRIPT_DIR"
echo "    ${TARGET_PLATFORM}-w64-mingw32.static-qmake-qt5 \\"
echo "      \"USE_UPNP=1\" \"RELEASE=1\" lanacoin-qt.pro"
echo "    make -j$NPROC"
echo ""

echo "============================================"
echo " Windows Build Complete!"
echo "============================================"
echo " Daemon:  $SCRIPT_DIR/src/lanacoind.exe"
echo "============================================"
