; Author :      Demey Alexandre (PA-14186)
; Date :        06-05-2020
; 
; Description : SLAE assignment #4 - Reverse bits encoder
;               This is the decoded stub for the reverse bits encoder
;
; Decoder stub length : 30 bytes


global _start
section .text

_start:
    jmp    decoder      ; jmp call 'pop' technique to get the memory address after the call
                        ; this will be the address of the encoded shellcode

decode:
    mov    ebx,[esp]    ; ebx will point the encoded shellcode
    xor    ecx,ecx      ; ecx set to 0
    mov    cl,0x21      ; The encoded shellcode length used for the loop counter
                        ; (will be calculated and inserted in function of the chosen shellcode to execute)

next_byte:
    push   ecx          ; Save the main loop counter on the stack
    mov    cl,0x08      ; Set the ecx to 8, the bit counter

next_bit:
    shr byte [ebx],1    ; Shift the bits of the byte pointed by ebx to the right 
			; and copy the lower bit in the Carry Flag (CF)
    adc    al,al        ; add al with al and the CF, in other words shift all bits to the left (al * 2)
			; and insert the last bit pointed by ebx to the right			
			; So in the end, all the bit of the byte pointed by ebx will be pushed to the right 
			; and inserted in al from the right and moved to the left, in the reverse order

    loop   next_bit     ; Process next bit of current byte 

    mov byte [ebx], al  ; copy the decoded byte at the memory address pointed by ebx
    inc    ebx          ; point ebx to the next encoded shellcode byte

    pop    ecx          ; Pop the main loop counter in ecx
    loop   next_byte    ; Process next byte

    ret                 ; Return to the start of the decoded shellcode

decoder:    
    call   decode       ; Push the memory address of the next instruction to the stack
                        ; And jump to the decoder

; The encoded shellcode will be added here in the python script