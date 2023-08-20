#!/bin/bash
:<<COMMENTS
@author Soo han, Kim (princeb612.kr@gmail.com)
@remarks
    platform support - mingw, linux

    1 tool chain
    sudo yum install package # RHEL family
    sudo apt install package # ubundu family
    pacman -S        package # mingw

    2 packages to install
    gcc, g++, binutils, cmake, gdb, valgrind
    openssl-devel, jansson-devel

COMMENTS

mkdir -p build
cd build
cmake -G 'Unix Makefiles' ..
time make
