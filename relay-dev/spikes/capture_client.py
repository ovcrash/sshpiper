#!/usr/bin/env python3
"""Spike helper: record what an SSH client sends before key exchange.

Usage: capture_client.py PORT OUTFILE

Accepts one connection, sends a server version line, reads the client's
version line and first binary packet (KEXINIT) and writes all bytes received
so far to OUTFILE. It also prints the client HASSH computed independently of
the Go code (reference for the sshkex tests):
hassh = md5(kex ";" enc_c2s ";" mac_c2s ";" comp_c2s).
"""
import hashlib
import socket
import struct
import sys


def main():
    port, out = int(sys.argv[1]), sys.argv[2]
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(1)
    conn, _ = srv.accept()
    conn.settimeout(10)
    conn.sendall(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.20\r\n")

    data = b""
    while True:
        chunk = conn.recv(65536)
        if not chunk:
            break
        data += chunk
        if b"\n" not in data:
            continue
        rest = data.split(b"\n", 1)[1]
        if len(rest) >= 4 and len(rest) >= 4 + struct.unpack(">I", rest[:4])[0]:
            break
    conn.close()
    open(out, "wb").write(data)

    line, rest = data.split(b"\n", 1)
    packet_len, pad_len = struct.unpack(">IB", rest[:5])
    payload = rest[5 : 4 + packet_len - pad_len]
    off, lists = 17, []
    for _ in range(10):
        (n,) = struct.unpack(">I", payload[off : off + 4])
        lists.append(payload[off + 4 : off + 4 + n].decode())
        off += 4 + n
    algos = ";".join([lists[0], lists[2], lists[4], lists[6]])
    print("version:", line.rstrip(b"\r").decode())
    print("hasshAlgorithms:", algos)
    print("hassh:", hashlib.md5(algos.encode()).hexdigest())


if __name__ == "__main__":
    main()
