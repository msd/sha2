#!/bin/bash

BASE_DIR="$(realpath $(dirname $0))" #< directory of the script
SRC_DIR="$BASE_DIR"
BUILD_DIR="$BASE_DIR/../build"
CONAN_PROFILE="default"

if [[ -d "$BUILD_DIR" ]]; then
    echo "ERROR: build directory already exists"
    exit 1
fi

mkdir "$BUILD_DIR"
cd "$BUILD_DIR"

conan install -pr "$CONAN_PROFILE" "$SRC_DIR" --build=missing
if [[ $? -ne 0 ]]; then
    echo "ERROR: conan failed to install dependencies"
    exit 1
fi

cmake ../src -"DCMAKE_MODULE_PATH=$(realpath .)" -D"CMAKE_PREFIX_PATH=$(realpath .)"
if [[ $? -ne 0 ]]; then
    echo "ERROR: cmake configuration failed"
    exit 1
fi

cmake --build .
if [[ $? -ne 0 ]]; then
    echo "ERROR: cmake building failed"
    exit 1
fi
