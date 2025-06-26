#!/bin/bash -eu

# Update package list and install basic dependencies
apt-get update
apt-get install -y build-essential cmake pkg-config git libjson-c-dev

# Set up dependencies directory
DEPS_DIR="$PWD/deps"
mkdir -p "$DEPS_DIR"
cd "$DEPS_DIR"

# Download and build libubox (required dependency)
if [ ! -d "libubox" ]; then
    echo "Downloading libubox..."
    git clone https://github.com/openwrt/libubox.git
    cd libubox
    # Remove unnecessary components to avoid CMake errors
    rm -rf tests examples lua
    # Also patch CMakeLists.txt to remove references to examples and lua
    sed -i '/ADD_SUBDIRECTORY(examples)/d' CMakeLists.txt
    sed -i '/ADD_SUBDIRECTORY(lua)/d' CMakeLists.txt
    cd ..
fi

cd libubox
mkdir -p build
cd build
cmake .. -DCMAKE_INSTALL_PREFIX="$DEPS_DIR/install" \
         -DCMAKE_C_FLAGS="$CFLAGS" \
         -DBUILD_LUA=OFF \
         -DBUILD_EXAMPLES=OFF \
         -DBUILD_TESTS=OFF \
         -DBUILD_STATIC=ON \
         -DBUILD_SHARED_LIBS=OFF
make -j$(nproc)
make install
cd "$DEPS_DIR"

# Go back to source directory
cd ..

# Set up compiler flags and paths
: "${CFLAGS:=-O2 -fPIC}"
: "${LDFLAGS:=}"
: "${PKG_CONFIG_PATH:=}"
: "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"  # Default to libFuzzer if not provided

# Add required flags for the build
export CFLAGS="$CFLAGS -D_GNU_SOURCE -std=gnu99"
export CFLAGS="$CFLAGS -I$DEPS_DIR/install/include"
export LDFLAGS="$LDFLAGS -L$DEPS_DIR/install/lib"
export PKG_CONFIG_PATH="$DEPS_DIR/install/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"

echo "Compiling relayd source files..."

# Compile the individual source files
$CC $CFLAGS -c dhcp.c -o dhcp.o
$CC $CFLAGS -c route.c -o route.o

# For main.c, we need to exclude the main() function and global variable definitions when building for fuzzing
# Create a temporary file without the main function and conflicting globals
echo "Creating main source without main() function and global definitions..."
cat > main_for_fuzz.c << 'EOF'
// Include everything from main.c except the main() function and global variables
// Global variables will be defined in the fuzzer instead
#define MAIN_C_NO_MAIN
EOF

# Extract everything from main.c except the main function and global variable definitions
sed -e '/^int main(/,/^}[[:space:]]*$/d' \
    -e '/^static LIST_HEAD(pending_routes);/d' \
    -e '/^LIST_HEAD(interfaces);/d' \
    -e '/^int debug;/d' \
    -e '/^static int host_timeout;/d' \
    -e '/^static int host_ping_tries;/d' \
    -e '/^static int inet_sock;/d' \
    -e '/^static int forward_bcast;/d' \
    -e '/^static int forward_dhcp;/d' \
    -e '/^static int parse_dhcp;/d' \
    -e '/^uint8_t local_addr\[4\];/d' \
    -e '/^int local_route_table;/d' \
    main.c >> main_for_fuzz.c

$CC $CFLAGS -c main_for_fuzz.c -o main_for_fuzz.o

echo "Compiling fuzzer..."
$CC $CFLAGS -c relayd-fuzz.c -o relayd-fuzz.o

echo "Linking fuzzer..."
# Link all object files together
$CC $CFLAGS $LIB_FUZZING_ENGINE relayd-fuzz.o \
    main_for_fuzz.o dhcp.o route.o \
    $LDFLAGS -static -lubox \
    -o $OUT/relayd_fuzzer

# Clean up temporary files
rm -f *.o main_for_fuzz.c

echo "Build completed successfully!"
echo "Fuzzer binary: $OUT/relayd_fuzzer"

# Verify the binary was created
if [ -f "$OUT/relayd_fuzzer" ]; then
    echo "Fuzzer binary size: $(stat -c%s "$OUT/relayd_fuzzer") bytes"
    echo "Fuzzer binary permissions: $(stat -c%A "$OUT/relayd_fuzzer")"
else
    echo "ERROR: Failed to create fuzzer binary!"
    exit 1
fi
