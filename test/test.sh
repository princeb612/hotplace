#!/bin/bash -x
:<<COMMENTS
@author Soo han, Kim (princeb612.kr@gmail.com)
@remarks
    ./test.sh       # test all
    ./test.sh base  # test single
COMMENTS

cwd=$(pwd)
valgrind --help > /dev/null 2>&1 || test_valgrind=$?

if [ $# -eq 0 ]; then
    array=(base bufferio cmdline datetime encode thread) # base
    array+=(mlfq cbor stream string unittest) # io
    array+=(crypto kdf hash ecdsa jose cose authenticode) # crypto
    array+=(ipaddr) # net
    if [ $OSTYPE = "msys" ]; then
        array+=(windows)
    else
        array+=(linux)
    fi
    # following test files are user interaction required
    # tcpserver1 tcpserver2 tlsserver httpserver
else
    if [ -d $1 ]; then
        array=($1)
    fi
fi

tool=(memcheck helgrind drd)
#tool+=(cachegrind)
for item in ${array[@]}; do
    cd $cwd/$item
    binary=./test-$item
    $binary
    if [ -z $test_valgrind ]; then
        for tool in ${tool[@]}; do
            option=
            if [ $tool = 'memcheck' ]; then
                option='--leak-check=full --track-origins=yes'
            fi
            valgrind -v --tool=$tool $option --log-file=report-$tool $binary
            cat report-$tool
        done
    fi
done

#echo --------------------------------------------------------------------------------
# grep fail `find . -name report`
