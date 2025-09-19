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
    array=(base bufferio cmdline datetime encode ieee754 graph nostd pattern thread unittest) # base
    array+=(cbor mlfq payload stream string asn1 parser) # io
    array+=(authenticode crypto cose hash jose kdf key random sign) # crypto
    array+=(ipaddr httptest quic tls13) # net
    if [[ $OSTYPE = "cygwin" || $OSTYPE = "msys" ]]; then
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

# valgrind -v --tool=memcheck --leak-check=full --show-leak-kinds=all --track-origins=yes --log-file=report-memcheck ...
# valgrind -v --tool=helgrind --log-file=report-helgrind ...
# valgrind -v --tool=drd --read-var-info=yes --log-file=report-drd ...
tool=(memcheck helgrind drd)
#tool+=(cachegrind)
for item in ${array[@]}; do
    cd $cwd/$item
    binary=./test-$item
    time $binary
    if [ -z $test_valgrind ]; then
        for tool in ${tool[@]}; do
            option=
            if [ $tool = 'memcheck' ]; then
                option='--leak-check=full --show-leak-kinds=all --track-origins=yes'
            elif [ $tool = 'drd' ]; then
                option='--read-var-info=yes'
            fi
            valgrind -v --tool=$tool $option --log-file=report-$tool $binary
            cat report-$tool
        done
    fi
done

#echo --------------------------------------------------------------------------------
#cd $cwd
#grep fail `find . -name report`
for item in ${array[@]}; do
    grep fail `find $cwd/$item -name report`
done
