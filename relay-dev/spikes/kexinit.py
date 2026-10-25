#!/usr/bin/env python3
"""Spike helper: print the version line and the KEXINIT lists of an SSH server.

Usage: kexinit.py HOST [PORT]

Sends a client version line, reads the server version line and its first
binary packet (KEXINIT, sent unencrypted), then prints the ten name-lists in
order and hasshServer = md5(kex;enc_s2c;mac_s2c;comp_s2c).
"""
import hashlib
import socket
import struct
import sys

NAMES = [
    "kex_algorithms",
    "server_host_key_algorithms",
    "encryption_algorithms_client_to_server",
    "encryption_algorithms_server_to_client",
    "mac_algorithms_client_to_server",
    "mac_algorithms_server_to_client",
    "compression_algorithms_client_to_server",
    "compression_algorithms_server_to_client",
    "languages_client_to_server",
    "languages_server_to_client",
]


def recv_exact(sock, n, buf):
    while len(buf) < n:
        chunk = sock.recv(4096)
        if not chunk:
            raise EOFError("connection closed")
        buf += chunk
    return buf


def main():
    host = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 22
    sock = socket.create_connection((host, port), timeout=10)
    sock.sendall(b"SSH-2.0-probe\r\n")

    buf = b""
    while b"\n" not in buf:
        buf = recv_exact(sock, len(buf) + 1, buf)
    line, buf = buf.split(b"\n", 1)
    print("version:", line.rstrip(b"\r").decode())

    buf = recv_exact(sock, 5, buf)
    packet_len, pad_len = struct.unpack(">IB", buf[:5])
    buf = recv_exact(sock, 4 + packet_len, buf)
    payload = buf[5 : 4 + packet_len - pad_len]
    sock.close()

    if payload[0] != 20:
        sys.exit("first packet is not KEXINIT: %d" % payload[0])
    off = 17  # msg type + 16-byte cookie
    lists = {}
    for name in NAMES:
        (n,) = struct.unpack(">I", payload[off : off + 4])
        lists[name] = payload[off + 4 : off + 4 + n].decode()
        off += 4 + n
    for name in NAMES:
        print("%s: %s" % (name, lists[name]))

    hassh_algos = ";".join(
        [
            lists["kex_algorithms"],
            lists["encryption_algorithms_server_to_client"],
            lists["mac_algorithms_server_to_client"],
            lists["compression_algorithms_server_to_client"],
        ]
    )
    print("hasshServerAlgorithms:", hassh_algos)
    print("hasshServer:", hashlib.md5(hassh_algos.encode()).hexdigest())


if __name__ == "__main__":
    main()
