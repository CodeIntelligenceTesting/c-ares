#!/bin/sh
# Copyright (C) The c-ci project and its contributors
# SPDX-License-Identifier: MIT
set -e -x

OS=`uname -s || true`

if [ "$OS" = "Linux" ]; then
    # Make distribution tarball
    autoreconf -fi
    ./configure
    make dist VERSION=99.98.97
    # Extract distribution tarball for building
    tar xvf c-ci-99.98.97.tar.gz
    cd c-ci-99.98.97
    # Build autotools
    mkdir build-autotools
    cd build-autotools
    ../configure --disable-symbol-hiding --enable-expose-statics --enable-maintainer-mode --enable-debug
    make
    cd test
    $TEST_WRAP ./citest -4 -v $TEST_FILTER
    cd ../..
    # Build CMake
    mkdir build-cmake
    cd build-cmake
    cmake -DCMAKE_BUILD_TYPE=DEBUG -DCI_STATIC=ON -DCI_STATIC_PIC=ON -DCI_BUILD_TESTS=ON ..
    make
    cd bin
    $TEST_WRAP ./citest -4 -v $TEST_FILTER
    cd ../..
fi
