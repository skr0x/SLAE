#!/usr/bin/python3
from ctypes import CDLL, CFUNCTYPE, c_char_p, cast
from sys import argv

libc = CDLL("libc.so.6")

egg = "\\x90\\x50\\x90\\x50"

egghunter = \
"\\x31\\xdb\\xfc\\x66\\x81\\xc9\\xff\\x0f\\x41\\x74\\xf8\\x6a\\x43\\x58\\xcd\\x80\\x3c\\xf2\\x74\\xef\\xb8\\x90\\x50\\x90\\x50\\x89\\xcf\\xaf\\x75\\xea\\xaf\\x75\\xe7\\xff\\xe7"

payload = egg * 2 + \
"\\x31\\xdb\\xf7\\xe3\\xb0\\x04\\xb3\\x01\\x68\\x72\\x6c\\x64\\x0a\\x68\\x6f\\x20\\x57\\x6f\\x68\\x48\\x65\\x6c\\x6c\\x89\\xe1\\xb2\\x0c\\xcd\\x80\\xb0\\x01\\xcd\\x80"

# Write Hello World shellcode :
#    xor ebx, ebx
#    mul ebx
#    mov al, 0x4
#    mov bl, 0x1
#
#    push 0x0a646c72
#    push 0X6f57206f
#    push 0x6c6c6548
#    mov ecx, esp
#    mov dl, 0xc
#    int 0x80
#
#    mov al, 0x1
#    int 0x80

egghunter = bytes.fromhex(egghunter.replace('\\x', ''))
payload = bytes.fromhex(payload.replace('\\x', ''))


print("Egg hunter length : {}".format(len(egghunter)))
print("Payload length : {}".format(len(payload) - 8))

c_shell_p = c_char_p(payload)
c_egg_p = c_char_p(egghunter)

launch = cast(c_egg_p, CFUNCTYPE(c_char_p))

launch()
