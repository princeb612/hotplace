#!/bin/bash
:<<COMMENTS
@author Soo han, Kim (princeb612.kr@gmail.com)
@remarks

    * platform support - mingw, linux
    * packages to install
      gcc, g++, binutils, cmake, gdb
      openssl-devel jansson-devel zlib-devel (MINGW)
      openssl-devel jansson zlib-devel (RHEL)
      openssl libssl-dev libjansson-dev zlib1g-dev (ubuntu)
      valgrind (linux)
    * make sure root directory hotplace (not hotplace-master and so on ...)
      $ hotplace ./make.sh

COMMENTS

mkdir -p build
cd build
if [ $OSTYPE = "msys" ]; then
    set SUPPORT_SHARED=1
    #set SUPPORT_ODBC=1
else
    #set SUPPORT_SHARED=1
    true
fi
export CXXFLAGS='-DDEBUG'
cmake -G 'Unix Makefiles' ..
time make
