#!/bin/bash
:<<COMMENTS
@author Soo han, Kim (princeb612.kr@gmail.com)
@remarks
    ./test.sh       # test all
    ./test.sh base  # test single
COMMENTS

cwd=$(pwd)
valgrind --help > /dev/null 2>&1 || test_valgrind=$?

if [ $# -eq 0 ]; then
    array=(base string bufferio stream datetime thread crypto jose)
else
    if [ -d $1 ]; then
        array=($1)
    fi
fi

tool=(memcheck helgrind drd)
for item in ${array[@]}; do
    cd $cwd/$item
    binary=./test-$item
    $binary
    if [ -z $test_valgrind ]; then
        for tool in ${tool[@]}; do
            valgrind --tool=$tool --log-file=report-$tool $binary
            cat report-$tool
        done
    fi
done
