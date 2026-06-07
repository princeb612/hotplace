#!/bin/bash

file=$1

if [[ ! -z ${file} ]]; then
    # basename="${file##*/}"
    filename="${file%.*}"
    fileext="${file##*.}"

    if [[ $fileext = 'crt' ]]; then
        openssl x509 -outform der -in $1 -out ${filename}.der
        openssl x509 -inform DER -in ${filename}.der -text -noout
    fi
fi
