#!/bin/bash
:<<COMMENTS
@author Soo Han, Kim (princeb612.kr@gmail.com)
@remarks

    * platform support - mingw, linux
    * packages to install
      gcc, g++, binutils, cmake, gdb
      openssl-devel jansson-devel zlib-devel (MINGW)
      openssl-devel jansson zlib-devel (RHEL)
      openssl libssl-dev libjansson-dev zlib1g-dev (ubuntu)
      valgrind (linux)
    * make
      $ ./make.sh

COMMENTS

:<< HELP
    cf       - clang-format
    cmake    - makefile only (only clang-format possible)
    ctest    - build and run ctest
    debug    - debug build
    format   - clang-format (syn. cf)
    opt      - optimize
    pch      - precompiled header
    prof     - gprof
    odbc     - ODBC feature
    redist   - redistribute MSYS2(MINGW) binaries
    shared   -
    test     - run examples
    ex) ./make.sh format debug pch
HELP

:<< SWITCHES
    SUPPORT_SHARED  - recompile openssl, jansson with -fPIC
    SUPPORT_ODBC    - unixODBC
    SUPPORT_PCH     - precompiled header
    SET_STDCPP      - c++11 (gcc 4.7~), c++14 (gcc 5.1~), linux option
SWITCHES

if [ $OSTYPE = "msys" ]; then
    true
else
    export SET_STDCPP=c++11
    # -Wl,--copy-dt-needed-entries # DSO missing from command line
    CXXFLAGS='-Wl,--copy-dt-needed-entries '${CXXFLAGS}
fi

do_clangformat=0
do_ctest=0
do_makefile=0
do_redist=0
do_test=0

CXXFLAGS=''
SUPPORT_PCH=0
args=("$@")

export HOTPLACE_HOME=$(pwd)

if [ ${#args[@]} -ne 0 ]; then
    for arg in ${args[@]}; do
        if [ $arg = 'cf' ]; then
            do_clangformat=1
        elif [ $arg = 'cmake' ]; then
            do_makefile=1
        elif [ $arg = 'ctest' ]; then
            do_ctest=1
        elif [ $arg = 'debug' ]; then
            CXXFLAGS="${CXXFLAGS} -DDEBUG -g"
        elif [ $arg = 'format' ]; then
            do_clangformat=1
        elif [ $arg = 'odbc' ]; then
            export SUPPORT_ODBC=1
        elif [ $arg = 'opt' ]; then
            CXXFLAGS="${CXXFLAGS}  -O2"
        elif [ $arg = 'pch' ]; then
            SUPPORT_PCH=1
        elif [ $arg = 'prof' ]; then
            CXXFLAGS="${CXXFLAGS}  -pg"
        elif [ $arg = 'redist' ]; then
            do_redist=1
        elif [ $arg = 'shared' ]; then
            export SUPPORT_SHARED=1
        elif [ $arg = 'test' ]; then
            do_test=1
        elif [ $arg = 'toolchain' ]; then
            # custom toolchain
            toolchain_dir=${HOTPLACE_HOME}/thirdparty/toolchain
            thirdparty_dir=${HOTPLACE_HOME}/thirdparty/toolchain
            export LD_LIBRARY_PATH=${toolchain_dir}/lib:${LD_LIBRARY_PATH}
            export PATH=${thirdparty_dir}/bin:${toolchain_dir}/bin:$PATH
            export CMAKE_CXX_COMPILER=${toolchain_dir}/bin/c++
        fi
    done
fi

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
if [ $do_makefile = 1 ]; then
    exit
fi
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
