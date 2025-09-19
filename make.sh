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
    cf             - clang-format
    cmake          - makefile only
    ctest          - build and run ctest
    debug          - debug build
    format         - clang-format (syn. cf)
    leaks          - gdb 
    opt            - optimize
    pch            - precompiled header
    prof           - gprof
    odbc           - ODBC feature
    redist         - redistribute MSYS2(MINGW) binaries
    shared         - shared build
    disable_static - disable static build
    verbose        - CMAKE_VERBOSE_MAKEFILE ON
    test           - run examples

    static build example
      mingw64
        source env.ubuntu && install_packages
        ./make.sh debug pch
      ubuntu
        source env.mingw64 && install_packages
        ./make.sh debug pch
    shared build examples
      mingw64
        source env.ubuntu && install_packages && export_path
        ./make.sh debug pch disable_static shared
      ubuntu
        source env.mingw64 && install_packages && export_path
        ./make.sh debug pch disable_static shared
HELP

:<< SWITCHES
    SUPPORT_SHARED  - recompile openssl, jansson with -fPIC
    SUPPORT_ODBC    - unixODBC
    SUPPORT_PCH     - precompiled header
    SET_STDCPP      - c++11 (gcc 4.7~), c++14 (gcc 5.1~), linux option
SWITCHES

if [[ $OSTYPE = "cygwin" || $OSTYPE = "msys" ]]; then
    true
else
    export SET_STDCPP=c++11
    # DSO missing
    # -Wl,--copy-dt-needed-entries
    CXXFLAGS='-Wl,--copy-dt-needed-entries '${CXXFLAGS}
fi

do_clangformat=0
do_ctest=0
do_makefile=0
do_redist=0
do_test=0

CXXFLAGS=''
SUPPORT_PCH=0
builddir=build
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
        elif [ $arg = 'leaks' ]; then
            CXXFLAGS="${CXXFLAGS} -fsanitize=leak"
        elif [ $arg = 'odbc' ]; then
            export SUPPORT_ODBC=1
        elif [ $arg = 'opt' ]; then
            CXXFLAGS="${CXXFLAGS}  -O2"
        elif [ $arg = 'pch' ]; then
            SUPPORT_PCH=1
        elif [ $arg = 'prof' ]; then
            CXXFLAGS="${CXXFLAGS} -pg"
        elif [ $arg = 'redist' ]; then
            do_redist=1
        elif [ $arg = 'disable_static' ]; then
            export SUPPORT_STATIC=0
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
        elif [ $arg = 'verbose' ]; then
            export CMAKE_VERBOSE_MAKEFILE=ON
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

# redist mingw binaries
if [ $do_redist = 1 ]; then
    # redist binaries to run wo mingw environment
    cd ${HOTPLACE_HOME}
    source redist.msys
    redist
    # and now
    #   cp xxx.exe ${HOTPLACE_HOME}/redist
    #   cd ${HOTPLACE_HOME}
    #   xxx.exe
fi

# build
mkdir -p ${builddir}
cd ${builddir}
export MAKEFLAGS='-j 4'
cmake -G 'Unix Makefiles' -DCMAKE_POLICY_VERSION_MINIMUM=3.5 ..
if [ $do_makefile = 1 ]; then
    exit
fi
time make

# ctest
if [ $do_ctest = 1 ]; then
    cd ${HOTPLACE_HOME}/${builddir}/test/
    ctest
fi
# run build/test/test.sh
if [ $do_test = 1 ]; then
    cd ${HOTPLACE_HOME}/${builddir}/test/
    ./test.sh
fi
