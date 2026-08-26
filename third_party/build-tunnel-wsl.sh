#!/bin/bash
# Builds the pinned AmneziaWG :tunnel Android library (native .so + AAR) inside WSL2 Ubuntu.
# Run from Windows: wsl -d Ubuntu -- bash /mnt/c/.../third_party/build-tunnel-wsl.sh
#
# Why WSL: the upstream native build (Makefile-driven wireguard-go/amneziawg-go cross-compile,
# elf-cleaner) requires a POSIX host toolchain (cc, flock) not present on plain Windows.
#
# Pinned revision: v3.0.1 (f82900455f1aceaa85658686dc2c5e32c2c42a73) - do not float to master.
set -euo pipefail

WORK=~/build/amneziawg-android
ANDROID_HOME=~/android-sdk
PIN_TAG="v3.0.1"
PIN_SHA="f82900455f1aceaa85658686dc2c5e32c2c42a73"

if [ ! -d "$WORK" ]; then
    mkdir -p ~/build
    git clone --recurse-submodules https://github.com/amnezia-vpn/amneziawg-android.git "$WORK"
fi

cd "$WORK"
git fetch --tags -q
git checkout -q "$PIN_TAG"
git submodule update --init --recursive -q

actual_sha=$(git rev-parse HEAD)
if [ "$actual_sha" != "$PIN_SHA" ]; then
    echo "ERROR: pinned tag $PIN_TAG resolved to $actual_sha, expected $PIN_SHA" >&2
    exit 1
fi

cat > local.properties <<EOF
sdk.dir=$ANDROID_HOME
ndk.dir=$ANDROID_HOME/ndk/26.1.10909125
cmake.dir=$ANDROID_HOME/cmake/3.22.1
EOF

export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
./gradlew :tunnel:assembleDebug --console=plain

OUT="$WORK/tunnel/build/outputs/aar/tunnel-debug.aar"
echo "Built: $OUT"
echo "Copy this file into android/app/libs/amneziawg-tunnel-v3.0.1-debug.aar for the app module to consume it."
