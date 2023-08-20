#!/bin/bash
:<<COMMENTS
@author Soo han, Kim (princeb612.kr@gmail.com)
@remarks
    platform support - mingw, linux

    packages to install
        gcc, g++, binutils, cmake, gdb, valgrind
    MINGW, RHEL
        openssl-devel, jansson-devel
    ubuntu
        openssl libssl-dev libjansson-dev

COMMENTS

mkdir -p build
cd build
cmake -G 'Unix Makefiles' ..
time make
