#!/bin/bash -x
:<<COMMENTS
@author Soo Han, Kim (princeb612.kr@gmail.com)
@remarks

    * platform support - mingw, linux
    * packages to install
      gcc, g++, binutils, cmake, gdb
      valgrind (linux)
    * make
      $ ./make.sh

COMMENTS

set -e

source function
source dependency

if [ -z ${HOTPLACE_HOME} ]; then
    HOTPLACE_HOME=`cd ..; pwd`
    export HOTPLACE_HOME
fi

for item in ${dependency[@]}; do
    member=item[name]
    member_name=${!member}[name]
    member_url=${!member}[url]
    member_dir=${!member}[dir]
    member_build="${!member}[build]"
    member_buildscript="${!member}[buildscript]"

    cd ${HOTPLACE_HOME}/thirdparty/

    # wget tarball
    download ${!member_url}
    # directory
    if [ -z ${!member_dir} ]; then
        member_filename=$(basename ${!member_url})
        member_basedir=`echo $(filename $member_filename)`
    else
        member_basedir=`echo ${!member_dir}`
    fi
    # tar xvfz tarball
    if [ ! -d $member_basedir ]; then
        inflate `basename ${!member_url}`
    fi
    # build
    if [ ! -f $member_basedir/.complete ]; then
        cd ${HOTPLACE_HOME}/thirdparty/$member_basedir
        if [ ! -z ${!member_buildscript} ]; then
            $(${!member_buildscript})
        else
            ${!member_build}
        fi
    fi
done
