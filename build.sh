#!/bin/bash -eu

# Update package list and install basic dependencies
apt-get update
apt-get install -y build-essential cmake pkg-config git

# Set up dependencies directory
DEPS_DIR="$PWD/deps"
mkdir -p "$DEPS_DIR"
cd "$DEPS_DIR"

# Download and build libubox (required dependency)
if [ ! -d "libubox" ]; then
    echo "Downloading libubox..."
    git clone https://github.com/openwrt/libubox.git
    cd libubox
    # Remove unnecessary components
    rm -rf tests examples
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

# For main.c, we need to exclude the main() function when building for fuzzing
# Create a temporary file without the main function
echo "Creating main source without main() function..."
cat > main_for_fuzz.c << 'EOF'
// Include everything from main.c except the main() function
#define MAIN_C_NO_MAIN
EOF

# Extract everything from main.c except the main function
sed '/^int main(/,/^}[[:space:]]*$/d' main.c >> main_for_fuzz.c

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
