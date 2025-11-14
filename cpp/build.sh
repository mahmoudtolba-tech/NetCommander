#!/bin/bash
# Build script for fast_ping C++ module

echo "Building fast_ping C++ module..."

# Check if Python development headers are available
if ! python3 -c "import sys; import sysconfig" 2>/dev/null; then
    echo "Warning: Python development headers not found"
    echo "The C++ module will not be built, but the application will work with fallback ping"
    exit 0
fi

# Build the module
python3 setup.py build_ext --inplace

if [ $? -eq 0 ]; then
    # Move the built module to bin directory
    find . -name "fast_ping*.so" -exec mv {} ../bin/ \;
    echo "Successfully built fast_ping module"
    echo "Module location: ../bin/"
else
    echo "Warning: Failed to build C++ module"
    echo "The application will work with fallback ping implementation"
fi

# Clean up build artifacts
rm -rf build *.o

exit 0
