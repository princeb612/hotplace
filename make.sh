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

:<< HELP
    ctest - build and run ctest
    debug - debug build
    format - clang-format
    pch - precompiled header
    redist - redistribute MSYS2(MINGW) binaries
    test - run examples
    ex) ./make.sh format debug pch
HELP

:<< SWITCHES
    SUPPORT_SHARED  - recompile openssl, jansson with -fPIC
    SUPPORT_ODBC    - unixODBC
    SUPPORT_PCH     - precompiled header
    SET_STDCPP      - c++11 (gcc 4.7~), c++14 (gcc 5.1~), linux option
SWITCHES

if [ $OSTYPE = "msys" ]; then
    export SUPPORT_SHARED=0
    export SUPPORT_ODBC=0
    true
else
    export SUPPORT_SHARED=0
    export SUPPORT_ODBC=0
    export SET_STDCPP=c++11
    # -Wl,--copy-dt-needed-entries # DSO missing from command line
    CXXFLAGS='-Wl,--copy-dt-needed-entries '${CXXFLAGS}
    true
fi

do_clangformat=0
do_ctest=0
do_redist=0
do_test=0

CXXFLAGS=''
SUPPORT_PCH=0
args=("$@")
if [ ${#args[@]} -ne 0 ]; then
    for arg in ${args[@]}; do
        if [ $arg = 'format' ]; then
            do_clangformat=1
        elif [ $arg = 'ctest' ]; then
            do_ctest=1
        elif [ $arg = 'redist' ]; then
            do_redist=1
        elif [ $arg = 'pch' ]; then
            SUPPORT_PCH=1
        elif [ $arg = 'test' ]; then
            do_test=1
        elif [ $arg = 'debug' ]; then
            CXXFLAGS='-DDEBUG -g'
        fi
    done
fi

export HOTPLACE_HOME=$(pwd)
export CXXFLAGS
export SUPPORT_PCH

# clang-format
if [ $do_clangformat = 1 ]; then
    clang-format -i `find sdk -name \*.\?pp`
    clang-format -i `find test -name \*.\?pp`
fi

# build
mkdir -p build
cd build
cmake -G 'Unix Makefiles' ..
time make

# ctest
if [ $do_ctest = 1 ]; then
    cd ${HOTPLACE_HOME}/build/test/
    ctest
fi
# redist mingw binaries
if [ $do_redist = 1 ]; then
    # redist binaries to run wo mingw environment
    cd ${HOTPLACE_HOME}
    source redist.msys
    redist
fi
# run build/test/test.sh
if [ $do_test = 1 ]; then
    cd ${HOTPLACE_HOME}/build/test/
    ./test.sh
fi
