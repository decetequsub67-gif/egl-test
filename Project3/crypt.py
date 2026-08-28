import struct, sys

path = "main.exe"

data = bytearray(open(path, "rb").read())

e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
if data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
    print("Not a PE file!"); sys.exit(1)

num_sections = struct.unpack_from("<H", data, e_lfanew + 6)[0]
opt_off = e_lfanew + 24
opt_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]
magic = struct.unpack_from("<H", data, opt_off)[0]
sec_off = opt_off + opt_size

secs = []
for i in range(num_sections):
    off = sec_off + i * 40
    name = bytes(data[off:off + 8]).rstrip(b"\0")
    vsize, vaddr, rsize, raddr = struct.unpack_from("<IIII", data, off + 8)
    secs.append((vaddr, vsize, raddr, rsize, name))

def rva2off(rva):
    for vaddr, vsize, raddr, rsize, nm in secs:
        if vaddr <= rva < vaddr + max(vsize, rsize):
            return raddr + (rva - vaddr)
    return None

def encrypt(name, fn):
    for vaddr, vsize, raddr, rsize, nm in secs:
        if nm == name:
            for j in range(rsize):
                data[raddr + j] ^= fn(j)
            print(f"Encrypted {nm.decode()}: file 0x{raddr:X}..0x{raddr + rsize:X} ({rsize} bytes)")
            return True
    return False

# --- Слой 1: .idata, ключ выводится из заголовка PE (зеркало stage1 в main.cpp) ---
k1 = (e_lfanew ^ num_sections) & 0xFF
if not encrypt(b".idata", lambda j: (k1 ^ (j & 0x0F)) & 0xFF):
    print(".idata not found!"); sys.exit(1)

# --- Слой 2: .crt, ключ зашит в зашифрованной stage2 (зеркало obf_stage2) ---
if not encrypt(b".crt", lambda j: (0x5F ^ (j & 0x0F)) & 0xFF):
    print(".crt not found!"); sys.exit(1)

# --- Wipe debug directory (POGO-запись палит имена секций) ---
dd_off = opt_off + (112 if magic == 0x20B else 96) + 6 * 8
dbg_rva, dbg_sz = struct.unpack_from("<II", data, dd_off)
if dbg_rva and dbg_sz:
    d = rva2off(dbg_rva)
    if d is not None:
        k = 0
        while k + 28 <= dbg_sz:
            szdata, addr_raw = struct.unpack_from("<II", data, d + k + 16)
            if szdata and addr_raw:
                p = rva2off(addr_raw)
                if p is not None:
                    for j in range(p, p + szdata):
                        data[j] = 0
            k += 28
        for j in range(d, d + dbg_sz):
            data[j] = 0
    struct.pack_into("<II", data, dd_off, 0, 0)
    print("Debug directory wiped")

open(path, "wb").write(data)
