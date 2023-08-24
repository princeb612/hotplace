#!/bin/bash
:<<COMMENTS
@author Soo han, Kim (princeb612.kr@gmail.com)
@remarks
    platform support - mingw, linux

    packages to install
        gcc, g++, binutils, cmake, gdb, valgrind
    MINGW, RHEL
        openssl-devel, jansson-devel zlib-devel
    ubuntu
        openssl libssl-dev libjansson-dev zlib1g-dev

    make sure root directory hotplace (not hotplace-master and so on ...)
    $ hotplace ./make.sh

COMMENTS

mkdir -p build
cd build
cmake -G 'Unix Makefiles' ..
time make
