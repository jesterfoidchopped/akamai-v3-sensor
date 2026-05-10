# HTTPCloak Bindings Makefile
# Build shared libraries and prepare binding packages

.PHONY: all build clean python nodejs install-python install-nodejs test help

# Default target
all: build copy

# Build the shared library for current platform
build:
	@echo "Building shared library..."
	@cd clib && bash build.sh native

# Build for all platforms (requires cross-compilers)
build-all:
	@echo "Building for all platforms..."
	@cd clib && bash build.sh all

# Copy libraries to binding directories
copy:
	@echo "Copying libraries to bindings..."
	@cd clib && bash build.sh copy

# Clean all build artifacts
clean:
	@echo "Cleaning..."
	@cd clib && bash build.sh clean
	@rm -rf python/dist python/build python/*.egg-info
	@rm -rf nodejs/node_modules

# Python targets
python: build
	@echo "Preparing Python package..."
	@cp clib/dist/libsensor-* python/sensor/lib/ 2>/dev/null || mkdir -p python/sensor/lib && cp clib/dist/libsensor-* python/sensor/lib/

python-build: python
	@echo "Building Python wheel..."
	@cd python && python -m build

install-python: python
	@echo "Installing Python package in development mode..."
	@cd python && pip install -e .

test-python: python
	@echo "Testing Python bindings..."
	@cd python && python -c "from sensor import Session, version; print('Version:', version()); s = Session(); r = s.get('https://www.cloudflare.com/cdn-cgi/trace'); print('Status:', r.status_code, 'Protocol:', r.protocol)"

# Node.js targets
nodejs: build
	@echo "Preparing Node.js package..."
	@cp clib/dist/libsensor-* nodejs/lib/ 2>/dev/null || mkdir -p nodejs/lib && cp clib/dist/libsensor-* nodejs/lib/

nodejs-install: nodejs
	@echo "Installing Node.js dependencies..."
	@cd nodejs && npm install

test-nodejs: nodejs nodejs-install
	@echo "Testing Node.js bindings..."
	@cd nodejs && node test.js

# Test all bindings
test: test-python test-nodejs
	@echo "All tests passed!"

# Platform-specific builds
linux:
	@cd clib && bash build.sh linux

darwin:
	@cd clib && bash build.sh darwin

windows:
	@cd clib && bash build.sh windows

# Help
help:
	@echo "HTTPCloak Bindings Build System"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Build targets:"
	@echo "  all           Build native library and copy to bindings (default)"
	@echo "  build         Build shared library for current platform"
	@echo "  build-all     Build for all platforms (needs cross-compilers)"
	@echo "  copy          Copy libraries to binding directories"
	@echo "  clean         Remove all build artifacts"
	@echo ""
	@echo "Python targets:"
	@echo "  python        Prepare Python package with native library"
	@echo "  python-build  Build Python wheel"
	@echo "  install-python Install Python package in dev mode"
	@echo "  test-python   Test Python bindings"
	@echo ""
	@echo "Node.js targets:"
	@echo "  nodejs        Prepare Node.js package with native library"
	@echo "  nodejs-install Install Node.js dependencies"
	@echo "  test-nodejs   Test Node.js bindings"
	@echo ""
	@echo "Platform-specific:"
	@echo "  linux         Build for Linux (amd64 + arm64)"
	@echo "  darwin        Build for macOS (amd64 + arm64)"
	@echo "  windows       Build for Windows (amd64 + arm64)"
	@echo ""
	@echo "Other:"
	@echo "  test          Run all binding tests"
	@echo "  help          Show this help"
