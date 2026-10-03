#!/usr/bin/env python3
"""Fuzz bifrost.sock. Daemon must survive and stay coherent."""
import json
import random
import socket
import sys

SOCK = "/run/heimdall/bifrost.sock"
DEV_TCP = ("127.0.0.1", 47651)


def connect(dev=False):
    if dev:
        return socket.create_connection(DEV_TCP, timeout=5)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect(SOCK)
    return sock


def send_line(sock, line):
    try:
        sock.sendall(line + b"\n")
        sock.settimeout(2)
        try:
            return sock.recv(65536)
        except socket.timeout:
            return b""
    except Exception as exc:
        return f"err:{exc}".encode()


def rand_bytes(size):
    return bytes(random.randint(0, 255) for _ in range(size))


def main():
    dev = "--dev" in sys.argv
    random.seed(0xC0FFEE)
    cases = [b'{"op":"ping"}'] * 10
    cases += [b'{"op":123}', b'{"op":["ping"]}', b'{"op":null}', b'{}']
    cases += [b'{"op":"verdict"}', b'{"op":"mode_set"}']
    cases += [b'{"op":"verdict","cmd":"' + b'A' * 100000 + b'"}']
    cases += [rand_bytes(random.randint(1, 200)) for _ in range(1000)]
    cases += [
        b'{"op":"verdict","cmd":"\\u0000"}',
        b'{"op":"mode_set","mode":"__admin__"}',
        b'{"op":"lab_enable","token":"x"}',
        b'{"op":' + b'[' * 500 + b']' * 500 + b'}',
    ]
    sent = recognized = unrecognized = 0
    for case in cases * 10:
        try:
            sock = connect(dev=dev)
        except Exception as exc:
            print(f"[fuzz] cannot connect: {exc}")
            return 2
        try:
            response = send_line(sock, case)
            sent += 1
            if response and any(token in response for token in (b'error', b'pong', b'verdict', b'ok')):
                recognized += 1
            else:
                unrecognized += 1
        finally:
            try:
                sock.close()
            except Exception:
                pass
    try:
        sock = connect(dev=dev)
        ping = send_line(sock, b'{"op":"ping"}')
        sock.close()
        alive = b'pong' in ping
    except Exception:
        alive = False
    print(f"[fuzz] sent={sent} recognized={recognized} unrecognized={unrecognized} alive={alive}")
    return 0 if alive else 1


if __name__ == "__main__":
    sys.exit(main())
