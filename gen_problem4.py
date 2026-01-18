# 第一次scanf (main函数开头)
# 用于凯撒解密演示1，内容不重要
payload = b'hello\n'

# 第二次scanf
# 用于凯撒解密演示2，内容不重要
payload += b'world\n'

# 第三次scanf(进入func)
# 这是关键：输入-1(即unsigned int的0xffffffff)
# 程序会进行大量的循环计算，最终验证通过
payload += b'-1\n'

with open("ans4.txt", "wb") as f:
    f.write(payload)
    print("Payload generated for Problem 4.")