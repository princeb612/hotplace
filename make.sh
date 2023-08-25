#!/bin/bash
:<<COMMENTS
@author Soo han, Kim (princeb612.kr@gmail.com)
@remarks

    * platform support - mingw, linux
    * packages to install
      gcc, g++, binutils, cmake, gdb
      openssl-devel, jansson-devel zlib-devel (MINGW, RHEL)
      openssl libssl-dev libjansson-dev zlib1g-dev (ubuntu)
      valgrind (linux)
    * make sure root directory hotplace (not hotplace-master and so on ...)
      $ hotplace ./make.sh

COMMENTS

mkdir -p build
cd build
cmake -G 'Unix Makefiles' ..
time make
