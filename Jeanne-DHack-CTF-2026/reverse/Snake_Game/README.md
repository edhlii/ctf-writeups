**Yêu cầu**

![alt text](image.png)  

Ta xem code `snake.py` này có gì:  

```python
import sys
import base64

def check_flag(code):
    # SSSssuper SSssecure!!!
    return base64.b64encode(''.join(chr((ord(c) + 2) ^ 0x23) for c in code)[::-1].swapcase().encode()).decode() == "dhpEd2YWFGJxRGRuYlIaYlpyaWJaclNOYlUKcxFlYlZETkFTVmIAUUBXZg=="

print(r"""

                                    __
                      ---_ ...... _/_ -
                     /  .      ./ .'*\ \
                     : '         /__-'   \.
                    /                      ) 
                  _/                  >   .' 
                /   .   .       _.-" /  .' 
                \           __/"     /.'/| 
                  \ '--  .-" /     //' |\| 
                   \|  \ | /     //_ _ |/| 
                    `.  \:     //|_ _ _|\|
                    | \/.    //  | _ _ |/| ASH
                     \_ | \/ /    \ _ _ \\\
                         \__/      \ _ _ \|\
         ------------------------------------------------
    
    ___________________________________     _______________________________
    7     77     77  _  77  7  77     7     7     77  _  77        77     7
    |  ___!|  _  ||  _  ||   __!|  ___!     |   __!|  _  ||  _  _  ||  ___!
    !__   7|  7  ||  7  ||     ||  __|_     |  !  7|  7  ||  7  7  ||  __|_
    7     ||  |  ||  |  ||  7  ||     7     |     ||  |  ||  |  |  ||     7
    !_____!!__!__!!__!__!!__!__!!_____!     !_____!!__!__!!__!__!__!!_____!

""")
print("Welcome to Snake Game! Enter the SSSSSsssecret code to get your flag Ssss.")

flag = input(">>> ")
if check_flag(flag):
    print("Ssss Congratulations! You found the Sssecret flag! You can validate with: ")
    print("JDHACK{" + flag + "}")
else:
    print("\nGame Over! Try again.")
    print(r"""
                          _  /)
                         mo / )
                         |/)\)
                          /\_
                          \__|=
                         (    )
                         __)(__
                   _____/      \\_____
                  |  _     ___   _   ||
                  | | \     |   | \  ||
                  | |  |    |   |  | ||
                  | |_/     |   |_/  ||
                  | | \     |   |    ||
                  | |  \    |   |    ||
                  | |   \. _|_. | .  ||
                  |                  ||
                  |       You        ||
                  |  Eaten by Snake  ||
          *       | *   **    * **   |**      **
           \))ejm97/.,(//,,..,,\||(,,.,\\,.((//
    """)
    sys.exit(1) 
```

Khá đơn giản, mục tiêu của tôi là đảo ngược hàm `check_flag()`.  

```py
def check_flag(code):
    # SSSssuper SSssecure!!!
    return base64.b64encode(''.join(chr((ord(c) + 2) ^ 0x23) for c in code)[::-1].swapcase().encode()).decode() == "dhpEd2YWFGJxRGRuYlIaYlpyaWJaclNOYlUKcxFlYlZETkFTVmIAUUBXZg=="
```  

Ta sẽ phân tích cách hàm `check_flag()` mã hoá chuỗi `code`:  
- Với mỗi ký tự `c` trong `code`
  - Lấy giá trị ASCII của `c` qua hàm `ord(c)`.
  - Cộng thêm 2 đơn vị vào giá trị ASCII.
  - XOR với `0x23`, thập phân là số 35.
  - Chuyển ngược kết quả về char qua hàm `chr()`
- Sau khi tính toán xong, chuỗi bị đảo ngược: `[::--1]`
- Sau đó chuỗi bị `swapcase()` và `encode()` về byte.
- Cuối cùng mã hoá chuỗi này theo `base64`.  

Từ đây ta dễ dàng đảo ngược logic hàm mã hoá để lấy được flag. Tôi có một script để tự động hoá việc này:

```py
import base64

encoded_str = "dhpEd2YWFGJxRGRuYlIaYlpyaWJaclNOYlUKcxFlYlZETkFTVmIAUUBXZg=="

step1 = base64.b64decode(encoded_str).decode("latin-1")

# Bước 2: Đảo ngược swapcase()
# swapcase() là hàm đối xứng, gọi lại nó lần nữa sẽ đưa chữ hoa/thường về vị trí cũ
step2 = step1.swapcase()

# Bước 3: Đảo ngược chuỗi [::-1]
step3 = step2[::-1]

# Bước 4: Đảo ngược phép toán (ord(c) + 2) ^ 0x23
# Logic: Nếu y = (x + 2) ^ 0x23
# Thì: x = (y ^ 0x23) - 2
original_code = ""
for c in step3:
    # Thực hiện XOR với 0x23 trước, sau đó mới trừ 2
    char_code = (ord(c) ^ 0x23) - 2
    original_code += chr(char_code)

print("--- Kết quả giải mã ---")
print(f"Flag: {original_code}")
print("-----------------------")
```  

Flag: `JDHACK{cRaP!_SN@KES_d0n'T_KNoW_hoW_7O_keEp_53crE7s}
`

