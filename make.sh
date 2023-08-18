#!/bin/bash
:<<COMMENTS
@author Soo han, Kim (princeb612.kr@gmail.com)
@remarks
    platform support - mingw, linux
COMMENTS

mkdir -p build include lib
cd build
cmake -G 'Unix Makefiles' ..
time make
