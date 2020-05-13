#!/bin/bash

printf "[x] Assembling...\n"
nasm -f elf32 $1.nasm -o $1.o

printf "[x] Linking...\n"
ld $1.o -o $1-exec

printf "[x] Done !\n\n"

printf "Shellcode : \n"
objdump -d ./$1-exec|grep '[0-9a-f]:'|grep -v 'file'|grep -v 'format'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
