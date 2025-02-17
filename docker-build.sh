#!/bin/bash

# Exit on error
set -e

# List of supported platforms
VALID_PLATFORMS=(
    "linux/amd64"
    "linux/arm64"
    "linux/arm64/v8"
    "linux/arm/v7"
    "linux/arm/v6"
    "windows/amd64"
)

# Function to check if the given platform is valid
is_valid_platform() {
    for platform in "${VALID_PLATFORMS[@]}"; do
        if [[ "$1" == "$platform" ]]; then
            return 0  # Valid platform
        fi
    done
    return 1  # Invalid platform
}

# Function to auto-detect system platform
detect_platform() {
    ARCH=$(uname -m)
    OS=$(uname | tr '[:upper:]' '[:lower:]')

    # Force OS to linux if not linux or windows since only these are supported
    if [[ "$OS" != "linux" && "$OS" != "windows" ]]; then
        OS="linux"
    fi

    case "$ARCH" in
        x86_64)
            echo "$OS/amd64"
            ;;
        aarch64|arm64)
            echo "$OS/arm64"
            ;;
        armv7l)
            echo "$OS/arm/v7"
            ;;
        armv6l)
            echo "$OS/arm/v6"
            ;;
        *)
            echo "Unsupported architecture: $ARCH"
            exit 1
            ;;
    esac
}

# Determine platform: use provided argument or detect automatically
if [ -z "$1" ]; then
    PLATFORM=$(detect_platform)
    echo "No platform specified. Using detected platform: $PLATFORM"
else
    PLATFORM=$1

    # Validate the input platform
    if ! is_valid_platform "$PLATFORM"; then
        echo "Error: Invalid platform '$PLATFORM'."
        echo "Available platforms:"
        for p in "${VALID_PLATFORMS[@]}"; do
            echo "  - $p"
        done
        exit 1
    fi
fi

IMAGE_NAME="mailio/mailio-server"

# Enable BuildKit (ensures multi-platform support)
export DOCKER_BUILDKIT=1

# Create a buildx instance if necessary
if ! docker buildx inspect mybuilder &>/dev/null; then
    echo "Creating a new buildx instance: mybuilder"
    docker buildx create --name mybuilder --use
fi

echo "Building Docker image for platform: $PLATFORM..."

docker buildx build \
    --platform "$PLATFORM" \
    -t "$IMAGE_NAME" --debug \
    --load .  # Use --push instead if you want to push to a registry

echo "Docker image built successfully for $PLATFORM"