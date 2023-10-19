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

:<< SWITCHES
    SUPPORT_SHARED  - recompile openssl, jansson with -fPIC
    SUPPORT_ODBC    - unixODBC
    SUPPORT_PCH     - precompiled header
    SET_STDCPP      - c++11 (gcc 4.7~), c++14 (gcc 5.1~), linux option
SWITCHES

if [ $OSTYPE = "msys" ]; then
    export SUPPORT_SHARED=0
    export SUPPORT_ODBC=0
    export SUPPORT_PCH=1
    true
else
    export SUPPORT_SHARED=0
    export SUPPORT_ODBC=0
    export SUPPORT_PCH=0
    export SET_STDCPP=c++11
    # -Wl,--copy-dt-needed-entries # DSO missing from command line
    export CMAKE_CXX_FLAGS='-Wl,--copy-dt-needed-entries'
    true
fi
export CXXFLAGS='-DDEBUG'

project_dir=$(pwd)

mkdir -p build
cd build
cmake -G 'Unix Makefiles' ..
time make

# redist binaries to run wo mingw environment
:<< REDIST
cd $project_dir
source redist.msys
redist
REDIST
