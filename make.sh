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
    redist - redistribute MSYS2(MINGW) binaries
    test - run examples
HELP

args=("$@")
if [ ${#args[@]} -ne 0 ]; then
    do_clangformat=0
    do_ctest=0
    do_redist=0
    do_test=0
    for arg in ${args[@]}; do
        if [ $arg = 'format' ]; then
            do_clangformat=1
        elif [ $arg = 'ctest' ]; then
            do_ctest=1
        elif [ $arg = 'redist' ]; then
            do_redist=1
        elif [ $arg = 'test' ]; then
            do_test=1
        fi
    done
fi

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

if [ $do_clangformat = 1 ]; then
    clang-format -i `find sdk -name \*.\?pp`
    clang-format -i `find test -name \*.\?pp`
fi

mkdir -p build
cd build
cmake -G 'Unix Makefiles' ..
time make

if [ $do_ctest = 1 ]; then
    cd $project_dir
    cd build/test/
    ctest
fi
if [ $do_redist = 1 ]; then
    # redist binaries to run wo mingw environment
    cd $project_dir
    source redist.msys
    redist
fi
if [ $do_test = 1 ]; then
    cd $project_dir
    cd build/test/
    ./test.sh
fi
